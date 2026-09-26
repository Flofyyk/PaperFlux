package tunnel

import (
	"testing"
	"time"
)

func TestHealthProbeRetriesWithinStartupBudget(t *testing.T) {
	if delay := healthProbeDelay(false); delay > 3*time.Second {
		t.Fatalf("failed probe retry too late: %v", delay)
	}
	if delay := healthProbeDelay(true); delay < 30*time.Second {
		t.Fatalf("healthy probe too frequent: %v", delay)
	}
}

func TestHealthProbeImmediatelyDueAfterCarrierRecovery(t *testing.T) {
	s := healthSchedule{}
	now := time.Now()
	if !s.due(now, true) {
		t.Fatal("startup probe delayed")
	}
	s.completed(now, true)
	if s.due(now.Add(time.Second), true) {
		t.Fatal("idle probe too frequent")
	}
	if s.due(now.Add(2*time.Second), false) {
		t.Fatal("probe sent without data carrier")
	}
	if !s.due(now.Add(3*time.Second), true) {
		t.Fatal("recovery waited for idle interval")
	}
	s.completed(now.Add(3*time.Second), false)
	if s.due(now.Add(4*time.Second), true) {
		t.Fatal("failed probe busy loop")
	}
	if !s.due(now.Add(6*time.Second), true) {
		t.Fatal("failed probe retry delayed")
	}
}
