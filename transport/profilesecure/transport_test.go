package profilesecure

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"universal-bypass-tool/transport"
)

type memoryTransport struct {
	mu        sync.Mutex
	peer      *memoryTransport
	callback  func([]byte)
	connected bool
	latency   time.Duration
}

func (m *memoryTransport) Start() error      { m.mu.Lock(); m.connected = true; m.mu.Unlock(); return nil }
func (m *memoryTransport) Stop() error       { m.mu.Lock(); m.connected = false; m.mu.Unlock(); return nil }
func (m *memoryTransport) IsConnected() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.connected }
func (m *memoryTransport) Receive(callback func([]byte)) {
	m.mu.Lock()
	m.callback = callback
	m.mu.Unlock()
}
func (m *memoryTransport) Stats() transport.TransportStats {
	return transport.TransportStats{Connected: m.IsConnected()}
}
func (m *memoryTransport) Send(data []byte) error {
	m.peer.mu.Lock()
	callback := m.peer.callback
	ready := m.peer.connected
	m.peer.mu.Unlock()
	if callback != nil && ready {
		copy := bytes.Clone(data)
		if m.latency > 0 {
			time.AfterFunc(m.latency, func() { callback(copy) })
		} else {
			callback(copy)
		}
	}
	return nil
}

func TestAuthenticatedPackets(t *testing.T) {
	aRaw, bRaw := &memoryTransport{}, &memoryTransport{}
	aRaw.peer, bRaw.peer = bRaw, aRaw
	a, err := New(aRaw, "7", "a-long-random-token-with-at-least-32-chars", "cupsonline", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(bRaw, "7", "a-long-random-token-with-at-least-32-chars", "cupsonline", true)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	b.Receive(func(pkt []byte) { received <- bytes.Clone(pkt) })
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	defer b.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for !(a.IsConnected() && b.IsConnected()) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !a.IsConnected() || !b.IsConnected() {
		t.Fatal("peers did not authenticate")
	}
	packet := []byte{0x45, 0, 0, 4}
	if err := a.Send(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, packet) {
			t.Fatalf("got %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("packet not delivered")
	}
}

func TestWrongTokenRejected(t *testing.T) {
	aRaw, bRaw := &memoryTransport{}, &memoryTransport{}
	aRaw.peer, bRaw.peer = bRaw, aRaw
	a, _ := New(aRaw, "7", "a-long-random-token-with-at-least-32-chars", "mailru", false)
	b, _ := New(bRaw, "7", "different-random-token-with-at-least-32-chars", "mailru", true)
	_ = a.Start()
	_ = b.Start()
	defer a.Stop()
	defer b.Stop()
	time.Sleep(2200 * time.Millisecond)
	if a.IsConnected() || b.IsConnected() {
		t.Fatal("mismatched profile key authenticated")
	}
}
