package yandex

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVolgaRefreshPublishesSharedCookiesAndPreservesOnFailure(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://volga.yandex.ru/")
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "fresh"}})
	r := newRelayClient(&volgaAuth{Token: "old", Session: &http.Client{}}, DefaultVolgaConfig(), &VolgaStats{})
	defer r.Stop()
	w := newWSListener(r.auth.Load(), r.config, r.stats, r, nil)
	defer w.Stop()
	fresh := &volgaAuth{Token: "fresh", RequestPath: "path", Session: &http.Client{Jar: jar}}
	w.authorizeFn = func(context.Context) (*volgaAuth, error) { return fresh, nil }
	if err := w.refreshAuth(); err != nil {
		t.Fatal(err)
	}
	if r.auth.Load().Token != fresh.Token {
		t.Fatal("relay kept stale auth")
	}
	r.httpClient.Transport = authRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer fresh" || !strings.Contains(req.Header.Get("Cookie"), "session=fresh") {
			t.Error("fresh auth/cookies missing")
		}
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if err := r.sendBatch([][]byte{{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	w.authorizeFn = func(context.Context) (*volgaAuth, error) { return nil, errors.New("offline") }
	if w.refreshAuth() == nil || r.auth.Load().Token != fresh.Token {
		t.Fatal("failed refresh discarded last auth")
	}
	w.authorizeFn = func(context.Context) (*volgaAuth, error) { w.Stop(); return &volgaAuth{Token: "late"}, nil }
	if w.refreshAuth() == nil || r.auth.Load().Token != fresh.Token {
		t.Fatal("stopped refresh published auth")
	}
}

func TestVolgaRetryKeepsAcceptedBatch(t *testing.T) {
	cfg := DefaultVolgaConfig()
	cfg.WorkerCount = 1
	cfg.BatchSize = 1
	r := newRelayClient(&volgaAuth{Session: &http.Client{}}, cfg, &VolgaStats{})
	defer r.Stop()
	var calls atomic.Int32
	r.httpClient.Transport = authRoundTripper(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("temporary network failure")
		}
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	r.Start()
	if err := r.Send([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for r.stats.PacketsSent.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.stats.PacketsSent.Load() != 1 || r.stats.QueueDrops.Load() != 0 || r.stats.RetryQueued.Load() == 0 {
		t.Fatal("accepted batch lost on HTTP error")
	}
	r.Stop()
	if r.stats.QueuedPackets.Load() != 0 || r.stats.QueuedBytes.Load() != 0 {
		t.Fatal("budget leaked")
	}
}

func TestVolgaFullQueueCancellation(t *testing.T) {
	cfg := DefaultVolgaConfig()
	cfg.QueueSize = 1
	r := newRelayClient(&volgaAuth{Session: &http.Client{}}, cfg, &VolgaStats{})
	if err := r.Send([]byte("first")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Send([]byte("second")) }()
	time.Sleep(10 * time.Millisecond)
	r.Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stopped queue accepted packet")
		}
	case <-time.After(time.Second):
		t.Fatal("stopped queue stuck")
	}
	if r.stats.QueuedPackets.Load() != 0 || r.stats.QueuedBytes.Load() != 0 {
		t.Fatal("stop left queued data")
	}
}

func TestVolgaStallAndReconnectDelay(t *testing.T) {
	var idle stalledTraffic
	for i := 0; i < 20; i++ {
		if idle.Observe(0, 0) {
			t.Fatal("idle caused reconnect")
		}
	}
	if idle.Observe(1, 0) {
		t.Fatal("early stall")
	}
	for i := 0; i < 10; i++ {
		if idle.Observe(0, 0) {
			t.Fatal("early stall")
		}
	}
	if !idle.Observe(0, 0) || idle.Observe(0, 0) {
		t.Fatal("single request stall detection wrong")
	}
	if idle.Observe(1, 1) {
		t.Fatal("reply did not reset detector")
	}
	cfg := DefaultVolgaConfig()
	if nextReconnectDelay(cfg.ReconnectMaxDelay, 2*cfg.WSReadTimeout, cfg) != cfg.ReconnectMinDelay {
		t.Fatal("healthy session did not reset backoff")
	}
	if !isVolgaKeepalive([]byte{0}) || isVolgaKeepalive([]byte{0, 1}) {
		t.Fatal("keepalive detection wrong")
	}
}
