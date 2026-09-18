package transport

import (
	"bytes"
	"testing"
)

func TestBondReordersWithinFlow(t *testing.T) {
	bond := &BondTransport{BaseTransport: *NewBaseTransport(DefaultConfig()), streams: make(map[bondStreamKey]*bondReorder)}
	var got [][]byte
	bond.Receive(func(packet []byte) { got = append(got, append([]byte(nil), packet...)) })
	bond.handleReceive(bondFrame(7, 11, 2, []byte("second")))
	bond.handleReceive(bondFrame(7, 11, 1, []byte("first")))
	if len(got) != 2 || !bytes.Equal(got[0], []byte("first")) || !bytes.Equal(got[1], []byte("second")) {
		t.Fatalf("order: %#v", got)
	}
}

func TestBondFlowsDoNotBlockEachOther(t *testing.T) {
	bond := &BondTransport{BaseTransport: *NewBaseTransport(DefaultConfig()), streams: make(map[bondStreamKey]*bondReorder)}
	var got [][]byte
	bond.Receive(func(packet []byte) { got = append(got, append([]byte(nil), packet...)) })
	bond.handleReceive(bondFrame(7, 11, 2, []byte("blocked")))
	bond.handleReceive(bondFrame(7, 22, 1, []byte("other")))
	if len(got) != 1 || !bytes.Equal(got[0], []byte("other")) {
		t.Fatalf("cross-flow block: %#v", got)
	}
}
