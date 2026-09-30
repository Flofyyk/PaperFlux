package transport

import (
	"sync/atomic"
	"testing"
)

func TestSessionDataEpochTracksAuthenticatedReplacement(t *testing.T) {
	client, exit, cw, _ := linkedSessions(t, "direct")
	var received atomic.Uint64
	exit.ReceiveSessionPackets(func(epoch uint64, _ []byte) { received.Store(epoch) })
	startPair(t, client, exit)
	first := exit.DataEpoch()
	if first == 0 {
		t.Fatal("ready session has no epoch")
	}
	eventually(t, "initial epoch packet", func() bool { _ = client.Send(testIPv4(40, 6)); return received.Load() == first })
	// Repeated discovery/keepalives do not destroy established flows.
	for i := 0; i < 3; i++ {
		_ = client.helloVia("direct")
	}
	if exit.DataEpoch() != first {
		t.Fatal("ordinary hello changed the epoch")
	}
	_ = client.Stop()
	restarted := restartOn(t, false, cw["direct"])
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "authenticated new epoch", func() bool { _ = restarted.Send(testIPv4(40, 6)); return received.Load() > first })
	if err := exit.SendSessionPacket(first, testIPv4(40, 6)); err == nil {
		t.Fatal("obsolete stack could send into new session")
	}
	if err := exit.SendSessionPacket(exit.DataEpoch(), testIPv4(40, 6)); err != nil {
		t.Fatal(err)
	}
}
