package transport

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandshakeBudgetPausesForVerificationAndStopInterrupts(t *testing.T) {
	s, _ := NewSession(testParams, false)
	var paused atomic.Bool
	paused.Store(true)
	s.SetHandshakePause(paused.Load)
	done := make(chan error, 1)
	go func() { done <- s.waitReady(40 * time.Millisecond) }()
	select {
	case e := <-done:
		t.Fatalf("verification consumed budget: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	paused.Store(false)
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("missing timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout did not resume")
	}
	paused.Store(true)
	go func() { done <- s.waitReady(time.Second) }()
	_ = s.Stop()
	select {
	case e := <-done:
		if e == nil || errors.Is(e, ErrNegotiationPending) {
			t.Fatal("stop not observed")
		}
	case <-time.After(time.Second):
		t.Fatal("stop blocked")
	}
}
