package transport

import "testing"

func TestFlowKeyIsDirectionIndependent(t *testing.T) {
	forward := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 10, 10, 2, 1, 1, 1, 1, 0x30, 0x39, 0x01, 0xbb}
	reverse := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 10, 10, 10, 2, 0x01, 0xbb, 0x30, 0x39}
	if flowKey(forward) != flowKey(reverse) {
		t.Fatal("reply selected a different lane")
	}
}

func TestPickLaneBalancesEqualLanes(t *testing.T) {
	a, b := &memoryTransport{}, &memoryTransport{}
	m := NewMultiTransport([]Transport{a, b}, DefaultConfig())
	first, second := m.pickLane(), m.pickLane()
	if first == second {
		t.Fatalf("equal lanes should round-robin, got %d then %d", first, second)
	}
}
