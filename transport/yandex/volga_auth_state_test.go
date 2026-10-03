package yandex

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVolgaAuthSingleFlightAndStaleRejection(t *testing.T) {
	a := newVolgaAuthState(context.Background(), &volgaAuth{Token: "old"})
	defer a.stop()
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	a.authorize = func(context.Context) (*volgaAuth, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return &volgaAuth{Token: "fresh"}, nil
	}
	stale := a.snapshot()
	a.reject(stale)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fresh, err := a.refresh(context.Background(), stale)
			if err != nil || fresh.auth.Token != "fresh" || fresh.generation != 2 {
				t.Errorf("bad shared refresh: %v", err)
			}
		}()
	}
	<-started
	close(release)
	wg.Wait()
	if calls.Load() != 1 || a.expired.Load() {
		t.Fatal("refresh duplicated or remained expired")
	}
	select {
	case <-stale.changed:
	default:
		t.Fatal("live WS was not notified")
	}
	a.reject(stale)
	if a.expired.Load() {
		t.Fatal("late old-generation 401 poisoned fresh authorization")
	}
	if _, err := a.refresh(context.Background(), stale); err != nil || calls.Load() != 1 {
		t.Fatal("stale WS failure caused another login")
	}
}

func TestVolgaAuthFailedAttemptIsSharedAndRetryable(t *testing.T) {
	a := newVolgaAuthState(context.Background(), &volgaAuth{Token: "working"})
	defer a.stop()
	var calls atomic.Int32
	a.authorize = func(context.Context) (*volgaAuth, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("private URL and token must not escape")
		}
		return &volgaAuth{Token: "recovered"}, nil
	}
	stale := a.snapshot()
	for i := 0; i < 16; i++ {
		if _, err := a.refresh(context.Background(), stale); !errors.Is(err, errVolgaAuthRefresh) {
			t.Fatal("failure was not shared/sanitized")
		}
	}
	if calls.Load() != 1 || a.Load().Token != "working" {
		t.Fatal("failure discarded auth or retried per worker")
	}
	select {
	case <-stale.changed:
		t.Fatal("failed auth closed working-generation socket")
	default:
	}
	if _, err := a.refresh(context.Background(), a.snapshot()); !errors.Is(err, errVolgaAuthRefresh) {
		t.Fatal("failure cooldown not enforced")
	}
	a.mu.Lock()
	a.retryAfter = time.Time{} // no real one-second sleep in the test
	a.mu.Unlock()
	fresh, err := a.refresh(context.Background(), a.snapshot())
	if err != nil || fresh.auth.Token != "recovered" || calls.Load() != 2 {
		t.Fatal("failed refresh became permanent")
	}
}

func TestVolgaAuthCancellationAndStop(t *testing.T) {
	a := newVolgaAuthState(context.Background(), &volgaAuth{Token: "working"})
	started := make(chan struct{})
	a.authorize = func(ctx context.Context) (*volgaAuth, error) {
		close(started)
		<-ctx.Done()
		return &volgaAuth{Token: "late"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.refresh(ctx, a.snapshot()); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation hung")
	}
	stopped := make(chan struct{})
	go func() { a.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stop hung during shared refresh")
	}
	if a.Load().Token != "working" {
		t.Fatal("canceled refresh published late credentials")
	}
	a.stop()
}

func TestVolgaAuthSnapshotOwnsCookieAndClientFields(t *testing.T) {
	original := &volgaAuth{Token: "initial", Cookies: []*http.Cookie{{Name: "session", Value: "initial"}}, Session: &http.Client{Timeout: time.Second}}
	a := newVolgaAuthState(context.Background(), original)
	defer a.stop()
	original.Token, original.Cookies[0].Value, original.Session.Timeout = "changed", "changed", 2*time.Second
	if got := a.Load(); got.Token != "initial" || got.Cookies[0].Value != "initial" || got.Session.Timeout != time.Second {
		t.Fatal("authorization snapshot aliases mutable fields")
	}
}

func TestVolgaRelay401RefreshesAndReplaysOnce(t *testing.T) {
	r := newRelayClient(&volgaAuth{Token: "old", UserID: 1}, DefaultVolgaConfig(), &VolgaStats{})
	defer r.Stop()
	w := newWSListener(r.auth.Load(), r.config, r.stats, r, nil)
	defer w.Stop()
	var authCalls, sends atomic.Int32
	w.authorizeFn = func(context.Context) (*volgaAuth, error) {
		authCalls.Add(1)
		return &volgaAuth{Token: "fresh", UserID: 2}, nil
	}
	r.httpClient.Transport = authRoundTripper(func(req *http.Request) (*http.Response, error) {
		call := sends.Add(1)
		status := 204
		if call == 1 {
			status = 401
		}
		if call == 2 && req.Header.Get("Authorization") != "Bearer fresh" {
			t.Error("retry used old credentials")
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if err := r.sendBatch([][]byte{[]byte("packet")}); err != nil {
		t.Fatal(err)
	}
	if authCalls.Load() != 1 || sends.Load() != 2 || r.stats.PacketsSent.Load() != 1 || r.auth.expired.Load() {
		t.Fatal("bad retry or delivery accounting")
	}
}

func TestVolgaRelayDoesNotRefreshOrImmediatelyReplayAmbiguousError(t *testing.T) {
	r := newRelayClient(&volgaAuth{Token: "old"}, DefaultVolgaConfig(), &VolgaStats{})
	defer r.Stop()
	var sends, authCalls atomic.Int32
	r.auth.authorize = func(context.Context) (*volgaAuth, error) { authCalls.Add(1); return &volgaAuth{Token: "fresh"}, nil }
	r.httpClient.Transport = authRoundTripper(func(*http.Request) (*http.Response, error) { sends.Add(1); return nil, errors.New("response lost") })
	if r.sendBatch([][]byte{[]byte("packet")}) == nil || sends.Load() != 1 || authCalls.Load() != 0 || r.stats.PacketsSent.Load() != 0 {
		t.Fatal("ambiguous network failure replayed as an auth rejection")
	}
}
