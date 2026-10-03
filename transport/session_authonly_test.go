package transport

import (
	"net"
	"testing"
	"time"
	"universal-bypass-tool/transport/control"
)

func TestControlOnlyNeverBecomesVPNPath(t *testing.T) {
	a, b, _, _ := sessionPair(t)
	a.SetControlOnly("primary")
	b.SetControlOnly("primary")
	messages := make(chan struct{}, 1)
	b.SetControlHandler(func(control.Subtype, []byte) { messages <- struct{}{} })
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	if a.HasDataPath() || b.HasDataPath() {
		t.Fatal("control-only connection became data path")
	}
	if a.Send(testIPv4(64, 6)) == nil {
		t.Fatal("IP packet allowed over auth channel")
	}
	if err := a.SendControl(control.SubtypeAuthRequired, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-messages:
	case <-time.After(time.Second):
		t.Fatal("control did not arrive")
	}
}
func TestDirectAdmission(t *testing.T) {
	for _, same := range []bool{true, false} {
		a, b := net.Pipe()
		key := "test-profile-secret-12345"
		other := key
		if !same {
			other += "wrong"
		}
		done := make(chan error, 1)
		go func() { defer a.Close(); done <- directAdmission(a, key, true) }()
		err := directAdmission(b, other, false)
		b.Close()
		serverErr := <-done
		if same && (err != nil || serverErr != nil) {
			t.Fatalf("valid proof rejected: %v/%v", err, serverErr)
		}
		if !same && (err == nil || serverErr == nil) {
			t.Fatal("wrong key accepted")
		}
	}
}

func TestDocumentMustHaveItsOwnPeerProof(t *testing.T) {
	a, _, _, _ := sessionPair(t)
	a.mu.Lock()
	a.ready = true
	a.peerConfirmed = true // this test isolates per-document proof after handshake
	lane := a.links["primary"]
	lane.started = true
	a.mu.Unlock()
	if a.HasDataPath() {
		t.Fatal("editor-only connection counted as a verified data path")
	}
	a.mu.Lock()
	lane.lastHeard = time.Now()
	a.mu.Unlock()
	if !a.HasDataPath() {
		t.Fatal("fresh document peer proof ignored")
	}
	a.mu.Lock()
	lane.lastHeard = time.Now().Add(-2 * a.linkTimeout)
	a.mu.Unlock()
	if a.HasDataPath() {
		t.Fatal("expired document proof counted as live")
	}
}
