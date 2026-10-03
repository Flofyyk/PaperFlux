package tunnel

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestProxyLimitsBothDirections(t *testing.T) {
	t.Setenv("PAPERFLUX_MAX_MBIT", "8")
	_, wire := newTransportPair()
	exit := NewTCPTunnelWithClientIPMode(wire, true, [4]byte{10, 10, 10, 2}, ExitModeProxy)
	defer exit.Close()
	if exit.downloadLimiter == nil || exit.proxyUploadLimiter == nil {
		t.Fatal("both directions must be limited")
	}
	if exit.downloadLimiter == exit.proxyUploadLimiter {
		t.Fatal("directions must have independent budgets")
	}
	if exit.downloadLimiter.Limit() != 1_000_000 || exit.proxyUploadLimiter.Limit() != 1_000_000 {
		t.Fatal("invalid 8 Mbit/s budget")
	}
}

func TestProxyTCPAckDoesNotWaitBehindBulkRateLimit(t *testing.T) {
	t.Setenv("PAPERFLUX_MAX_MBIT", "0.25")
	_, wire := newTransportPair()
	exit := NewTCPTunnelWithClientIPMode(wire, true, [4]byte{10, 10, 10, 2}, ExitModeProxy)
	defer exit.Close()
	// Model data writers having already reserved the next burst's bandwidth.
	now := time.Now()
	exit.downloadLimiter.ReserveN(now, exit.downloadLimiter.Burst())
	reservation := exit.downloadLimiter.ReserveN(now, exit.downloadLimiter.Burst())
	defer reservation.Cancel()
	ack := make([]byte, 40)
	ack[0], ack[9], ack[32], ack[33] = 0x45, 6, 0x50, 0x10
	binary.BigEndian.PutUint16(ack[2:4], 40)
	done := make(chan struct{})
	go func() { exit.tunnelEP.onOutgoingPacket(ack); close(done) }()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("pure TCP ACK was rate-limited behind queued bulk data")
	}
}

func TestPacedPacketBudgetCannotBypassBulkOrFragments(t *testing.T) {
	for _, tc := range []struct {
		name     string
		size     int
		flags    byte
		fragment uint16
		offset   byte
		zero     bool
	}{
		{"ack", 40, 0x10, 0, 0x50, true},
		{"syn", 40, 0x02, 0, 0x50, true},
		{"fin", 40, 0x11, 0, 0x50, true},
		{"reset", 40, 0x04, 0, 0x50, true},
		{"data", 41, 0x10, 0, 0x50, false},
		{"more fragments", 40, 0x10, 0x2000, 0x50, false},
		{"later fragment", 40, 0x10, 1, 0x50, false},
		{"bad tcp header", 40, 0x10, 0, 0x10, false},
		{"no flags", 40, 0, 0, 0x50, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, tc.size)
			p[0], p[9], p[32], p[33] = 0x45, 6, tc.offset, tc.flags
			binary.BigEndian.PutUint16(p[2:4], uint16(tc.size))
			binary.BigEndian.PutUint16(p[6:8], tc.fragment)
			want := len(p)
			if tc.zero {
				want = 0
			}
			if got := pacedPacketBytes(p); got != want {
				t.Fatalf("got %d want %d", got, want)
			}
		})
	}
}
