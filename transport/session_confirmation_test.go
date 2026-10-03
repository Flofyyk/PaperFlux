package transport

import (
	"errors"
	"testing"

	"universal-bypass-tool/transport/control"
)

func TestSessionWaitsForExitConfirmation(t *testing.T) {
	client, exit, cw, _ := linkedSessions(t, "direct")
	startPair(t, client, exit)
	blackhole(cw["direct"])
	client.mu.Lock()
	client.resetLocked()
	local := client.local
	client.mu.Unlock()
	var candidate [32]byte
	candidate[0] = 42
	offer := &control.Envelope{
		Kind: control.KindHello, Role: control.RoleExit, Local: candidate, Peer: local,
		Hello: &control.HelloTail{Capabilities: control.Capabilities(testParams.Capabilities), MaxPacketSize: uint16(testParams.MaxPacketSize)},
	}
	client.receiveHello(client.links["direct"], offer)
	assertPending := func() {
		t.Helper()
		if client.IsConnected() || client.HasDataPath() || client.ActiveTransport() != "" {
			t.Fatal("challenge echo exposed an unconfirmed session")
		}
		if _, ready := client.PeerParameters(); ready {
			t.Fatal("unconfirmed peer parameters exposed")
		}
		if err := client.Send(testIPv4(40, 6)); !errors.Is(err, ErrNegotiationPending) {
			t.Fatalf("Send = %v, want negotiation pending", err)
		}
		client.mu.Lock()
		hello := client.buildHello()
		client.mu.Unlock()
		if hello.Hello.Ready != 0 {
			t.Fatal("pending client stopped requesting final confirmation")
		}
	}
	assertPending()
	// Duplicate challenge must not unblock data or stop hello retries.
	client.receiveHello(client.links["direct"], offer)
	assertPending()
	offer.Hello.Ready = 1
	client.receiveHello(client.links["direct"], offer)
	if !client.IsConnected() || !client.HasDataPath() {
		t.Fatal("exit confirmation did not establish the session")
	}
	// An old Ready=0 challenge from the accepted peer cannot downgrade it.
	offer.Hello.Ready = 0
	client.receiveHello(client.links["direct"], offer)
	if !client.IsConnected() {
		t.Fatal("duplicate challenge downgraded confirmed peer")
	}
}
