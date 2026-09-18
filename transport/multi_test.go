package transport

import (
	"testing"
	"time"
)

type healthMemoryTransport struct {
	memoryTransport
	health LaneHealth
}

func (m *healthMemoryTransport) LaneHealth() LaneHealth { return m.health }

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

func TestPickLanePrefersHealthyDocumentForNewFlow(t *testing.T) {
	slow := &healthMemoryTransport{health: LaneHealth{Connected: true, QueueLoad: 0.10, RTT: 900 * time.Millisecond}}
	fast := &healthMemoryTransport{health: LaneHealth{Connected: true, QueueLoad: 0.01, RTT: 120 * time.Millisecond}}
	m := NewMultiTransport([]Transport{slow, fast}, DefaultConfig())
	if got := m.pickLane(); got != 1 {
		t.Fatalf("pickLane() = %d, want healthier lane 1", got)
	}
}

func TestPickLanePrefersQueueHeadroomOverHistoricalRTT(t *testing.T) {
	backedUp := &healthMemoryTransport{health: LaneHealth{Connected: true, QueueLoad: 0.80, RTT: 80 * time.Millisecond}}
	available := &healthMemoryTransport{health: LaneHealth{Connected: true, QueueLoad: 0.01, RTT: 350 * time.Millisecond}}
	m := NewMultiTransport([]Transport{backedUp, available}, DefaultConfig())
	if got := m.pickLane(); got != 1 {
		t.Fatalf("pickLane() = %d, want lane with queue headroom 1", got)
	}
}
