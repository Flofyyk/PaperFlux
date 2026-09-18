package yandex

import (
	"bytes"
	"testing"
)

func pair(t *testing.T) (*secureChannel, *secureChannel) {
	t.Helper()
	a, e := newSecureChannel("42", "0123456789abcdef0123456789abcdef", "doc", false)
	if e != nil {
		t.Fatal(e)
	}
	b, e := newSecureChannel("42", "0123456789abcdef0123456789abcdef", "doc", true)
	if e != nil {
		t.Fatal(e)
	}
	handshake(t, a, b)
	return a, b
}
func handshake(t *testing.T, a, b *secureChannel) {
	t.Helper()
	ackB, e := b.receiveHandshake(a.hello())
	if e != nil {
		t.Fatal(e)
	}
	ackA, e := a.receiveHandshake(b.hello())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.receiveHandshake(ackB); e != nil {
		t.Fatal(e)
	}
	if _, e = b.receiveHandshake(ackA); e != nil {
		t.Fatal(e)
	}
}
func TestSecureRoundTripTamperReplay(t *testing.T) {
	a, b := pair(t)
	frame, e := a.seal([]byte("private traffic"))
	if e != nil {
		t.Fatal(e)
	}
	tamper := append([]byte(nil), frame...)
	tamper[len(tamper)-1] ^= 1
	if _, e = b.open(tamper); e == nil {
		t.Fatal("tamper accepted")
	}
	plain, e := b.open(frame)
	if e != nil || !bytes.Equal(plain, []byte("private traffic")) {
		t.Fatal(e)
	}
	if _, e = b.open(frame); e == nil {
		t.Fatal("replay accepted")
	}
	if _, e = a.open(frame); e == nil {
		t.Fatal("reflection accepted")
	}
	reverse, _ := b.seal([]byte("reply"))
	if _, e = a.open(reverse); e != nil {
		t.Fatal(e)
	}
}
func TestSecureWrongCredentialsAndRestart(t *testing.T) {
	a, b := pair(t)
	old, _ := a.seal([]byte("old"))
	bad, _ := newSecureChannel("42", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "doc", true)
	if _, e := bad.receiveHandshake(a.hello()); e == nil {
		t.Fatal("wrong token accepted")
	}
	fresh, _ := newSecureChannel("42", "0123456789abcdef0123456789abcdef", "doc", true)
	handshake(t, a, fresh)
	if _, e := fresh.open(old); e == nil {
		t.Fatal("pre-restart packet accepted")
	}
	if _, e := a.receiveHandshake(b.hello()); e == nil {
		t.Fatal("retired epoch accepted")
	}
}

func TestSecureRotateEpochReestablishesAfterDocumentReplacement(t *testing.T) {
	a, b := pair(t)
	old, err := a.seal([]byte("before rotation"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.rotateEpoch(); err != nil {
		t.Fatal(err)
	}
	if err := b.rotateEpoch(); err != nil {
		t.Fatal(err)
	}
	if a.ready() || b.ready() {
		t.Fatal("rotated channels remained ready")
	}
	handshake(t, a, b)
	if _, err := b.open(old); err == nil {
		t.Fatal("frame from retired document epoch accepted")
	}
	frame, err := a.seal([]byte("after rotation"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := b.open(frame); err != nil || !bytes.Equal(plain, []byte("after rotation")) {
		t.Fatalf("rotated channel unusable: %q %v", plain, err)
	}
}
func TestSecureRequiresHandshake(t *testing.T) {
	a, _ := newSecureChannel("42", "0123456789abcdef0123456789abcdef", "doc", false)
	if _, e := a.seal([]byte("data")); e == nil {
		t.Fatal("sent before handshake")
	}
	if _, e := a.open(batchMagic); e == nil {
		t.Fatal("plaintext accepted")
	}
}

func TestSecureAcceptsAckWithoutPriorPeerHello(t *testing.T) {
	client, err := newSecureChannel("42", "0123456789abcdef0123456789abcdef", "doc", false)
	if err != nil {
		t.Fatal(err)
	}
	exit, err := newSecureChannel("42", "0123456789abcdef0123456789abcdef", "doc", true)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := client.receiveHandshake(exit.hello())
	if err != nil || ack == nil {
		t.Fatalf("client should accept the first hello: ack=%v err=%v", ack != nil, err)
	}
	if _, err = exit.receiveHandshake(ack); err != nil {
		t.Fatalf("exit should accept an authenticated ACK without a prior peer hello: %v", err)
	}
	// The client still completes its side with its own HELLO, as it does after
	// leaving the editor's waitAuth state.
	clientAck, err := exit.receiveHandshake(client.hello())
	if err != nil || clientAck == nil {
		t.Fatalf("exit should acknowledge the client's hello: ack=%v err=%v", clientAck != nil, err)
	}
	if _, err = client.receiveHandshake(clientAck); err != nil {
		t.Fatalf("client should accept the completing ACK: %v", err)
	}
	if !client.ready() || !exit.ready() {
		t.Fatal("channels did not become ready")
	}
	frame, err := exit.seal([]byte("probe"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := client.open(frame); err != nil || !bytes.Equal(plain, []byte("probe")) {
		t.Fatalf("ack-only handshake did not establish usable keys: %q %v", plain, err)
	}
}

func TestSecureOutOfOrderAndContextIsolation(t *testing.T) {
	a, b := pair(t)
	frames := make([][]byte, 70)
	for i := range frames {
		frames[i], _ = a.seal([]byte{byte(i)})
	}
	if _, err := b.open(frames[2]); err != nil {
		t.Fatal(err)
	}
	if _, err := b.open(frames[1]); err != nil {
		t.Fatal("valid reordering", err)
	}
	if _, err := b.open(frames[69]); err != nil {
		t.Fatal(err)
	}
	if _, err := b.open(frames[0]); err == nil {
		t.Fatal("outside replay window accepted")
	}
	for _, context := range []struct{ id, doc string }{{"43", "doc"}, {"42", "another-doc"}} {
		wrong, _ := newSecureChannel(context.id, "0123456789abcdef0123456789abcdef", context.doc, true)
		if _, err := wrong.receiveHandshake(a.hello()); err == nil {
			t.Fatal("cross-profile/document accepted")
		}
	}
	for n := 0; n < len(frames[0]); n++ {
		if _, err := b.open(frames[0][:n]); err == nil {
			t.Fatal("truncated frame accepted")
		}
	}
}

func TestSecureLowOrderKeyFailsClosed(t *testing.T) {
	a, b := pair(t)
	hello := a.hello()
	for i := 6; i < 38; i++ {
		hello[i] = 0
	}
	hello[6] = 1
	copy(hello[secureHeader:], a.mac(hello[:secureHeader]))
	for i := 0; i < 2; i++ {
		if _, err := b.receiveHandshake(hello); err == nil {
			t.Fatal("low-order key accepted")
		}
	}
	if b.ready() {
		t.Fatal("channel remained confirmed after invalid key")
	}
}
