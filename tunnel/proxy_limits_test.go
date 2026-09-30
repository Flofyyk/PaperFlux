package tunnel

import "testing"

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
