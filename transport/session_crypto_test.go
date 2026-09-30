package transport

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSessionKeyReusePreservesWireAndProfileIsolation(t *testing.T) {
	s, err := NewSession(testParams, true)
	if err != nil {
		t.Fatal(err)
	}
	secret := "abcdefghijklmnopqrstuvwxyz123456"
	receiverRaw := &fakeTransport{}
	receiver, err := NewEncryptedTransport(receiverRaw, secret, "profile/1", false)
	if err != nil {
		t.Fatal(err)
	}
	var received [][]byte
	receiver.Receive(func(p []byte) { received = append(received, p) })
	for i := 0; i < 3; i++ {
		raw := &fakeTransport{}
		sender, err := s.wrapEncrypted(raw, secret, "profile/1")
		if err != nil {
			t.Fatal(err)
		}
		if err = sender.Send([]byte(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
		receiverRaw.cb(raw.firstSent())
	}
	if len(s.encryptionCache) != 1 || len(received) != 3 {
		t.Fatal("keys not reused or wire changed")
	}
	raw := &fakeTransport{}
	wrong, err := s.wrapEncrypted(raw, secret, "profile/2")
	if err != nil {
		t.Fatal(err)
	}
	wrong.Send([]byte("other-profile"))
	receiverRaw.cb(raw.firstSent())
	if len(received) != 3 {
		t.Fatal("cross-profile decryption succeeded")
	}
	if !bytes.Equal(received[2], []byte("2")) {
		t.Fatal("wire content changed")
	}
	if len(s.encryptionCache) != 2 {
		t.Fatal("contexts not separated")
	}
}

func TestBatchByteBudgetBeforeAllocationAndStopReleases(t *testing.T) {
	b := newBatchedTransportWithBudget(&fakeTransport{}, 65536)
	b.running.Store(true) // No drain loop, deterministic bounded queue.
	packet := make([]byte, 32768)
	if b.Send(packet) != nil || b.Send(packet) != nil {
		t.Fatal("budget rejected valid packets")
	}
	if b.Send([]byte{1}) == nil {
		t.Fatal("byte cap not enforced")
	}
	if b.queueBytes.Load() != 65536 {
		t.Fatal("invalid budget accounting")
	}
	b.Stop()
	if b.queueBytes.Load() != 0 || len(b.queue) != 0 {
		t.Fatal("retained stopped queue")
	}
}
func TestSessionBatchBudgetLifecycle(t *testing.T) {
	s, _ := NewSession(testParams, true)
	if err := s.SetBatchByteLimit(256 << 10); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTransport("a", &fakeTransport{}, "abcdefghijklmnopqrstuvwxyz123456", "ctx", 1); err != nil {
		t.Fatal(err)
	}
	if s.links["a"].batched.queueByteLimit != 256<<10 {
		t.Fatal("budget not propagated")
	}
	if s.SetBatchByteLimit(64<<10) == nil {
		t.Fatal("late budget mutation allowed")
	}
}

func BenchmarkThreeLaneKeySetup(b *testing.B) {
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprintf("session_cache_%t", cached), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s, _ := NewSession(testParams, true)
				for j := 0; j < 3; j++ {
					var err error
					if cached {
						_, err = s.wrapEncrypted(&fakeTransport{}, "abcdefghijklmnopqrstuvwxyz123456", "benchmark")
					} else {
						_, err = NewEncryptedTransport(&fakeTransport{}, "abcdefghijklmnopqrstuvwxyz123456", "benchmark", true)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
