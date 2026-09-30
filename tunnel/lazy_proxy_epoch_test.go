package tunnel

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestLazyAuthenticatedEpochReleasesOldStackAndDropsLatePackets(t *testing.T) {
	_, wire := newTransportPair()
	p := NewLazyProxy(wire, [4]byte{10, 10, 10, 2})
	defer p.Close()
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 20)
	copy(packet[12:16], []byte{10, 10, 10, 2})
	wait := func(creates uint64) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for p.Snapshot().StackCreates < creates {
			if time.Now().After(deadline) {
				t.Fatal("stack not created")
			}
			time.Sleep(time.Millisecond)
		}
	}
	p.enqueueSession(1, packet)
	wait(1)
	p.stackMu.Lock()
	old := p.stack
	left, right := net.Pipe()
	if !old.trackConnection(left) {
		t.Fatal("connection not tracked")
	}
	p.stackMu.Unlock()
	defer right.Close()
	// A document reconnect using the same authenticated epoch retains TCP.
	p.enqueueSession(1, packet)
	time.Sleep(10 * time.Millisecond)
	if p.Snapshot().SessionResets != 0 {
		t.Fatal("same session was reset")
	}
	p.enqueueSession(2, packet)
	wait(2)
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := right.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("old socket retained: %v", err)
	}
	p.enqueueSession(1, packet)
	if st := p.Snapshot(); st.SessionResets != 1 || st.StaleDrops != 1 || st.StackCreates != 2 {
		t.Fatalf("%+v", st)
	}
	stale := &lazyStackTransport{LazyProxy: p, epoch: 1}
	if err := stale.Send(packet); err == nil {
		t.Fatal("old stack response admitted")
	}
}

func TestHealthChecksStopWithTunnel(t *testing.T) {
	_, wire := newTransportPair()
	stack := NewTCPTunnel(wire, false)
	done := make(chan struct{})
	go func() { stack.RunHealthChecks(); close(done) }()
	stack.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed stack kept probing")
	}
}
