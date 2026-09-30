package tunnel

import (
	"testing"
	"time"
)

func TestExitLimiterSettingsAndBurst(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "NaN", "+Inf", "invalid"} {
		t.Setenv("PAPERFLUX_MAX_MBIT", value)
		if newExitLimiter() != nil {
			t.Fatalf("invalid/unlimited %q created limiter", value)
		}
	}
	t.Setenv("PAPERFLUX_MAX_MBIT", "8")
	a, b := newExitLimiter(), newExitLimiter()
	if a == nil || a == b || float64(a.Limit()) != 1_000_000 {
		t.Fatal("limit is not per-profile or uses wrong units")
	}
	now := time.Now()
	first := a.ReserveN(now, 128*1024)
	if !first.OK() || first.DelayFrom(now) != 0 {
		t.Fatal("bounded initial burst unavailable")
	}
	next := a.ReserveN(now, 1000)
	if !next.OK() || next.DelayFrom(now) <= 0 {
		t.Fatal("bulk traffic not throttled")
	}
	if b.ReserveN(now, 1000).DelayFrom(now) != 0 {
		t.Fatal("one user exhausted another user's bucket")
	}
}
