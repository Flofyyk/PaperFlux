package yandex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestVolgaAuthRefreshRotatesLiveWSWithoutSecondLogin(t *testing.T) {
	opened := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		opened <- req.URL.Query().Get("session")
		_, _, _ = conn.ReadMessage() // no traffic: only generation rotation can close it
	}))
	defer srv.Close()
	cfg := DefaultVolgaConfig()
	cfg.ReconnectMinDelay = 10 * time.Millisecond
	cfg.WSReadTimeout = time.Minute
	r := newRelayClient(&volgaAuth{Token: "old", SessionID: "old-session"}, cfg, &VolgaStats{})
	defer r.Stop()
	w := newWSListener(r.auth.Load(), cfg, r.stats, r, nil)
	defer w.Stop()
	var calls atomic.Int32
	w.authorizeFn = func(context.Context) (*volgaAuth, error) {
		calls.Add(1)
		return &volgaAuth{Token: "fresh", SessionID: "fresh-session"}, nil
	}
	w.dialFn = func(ctx context.Context, raw string, headers http.Header) (*websocket.Conn, error) {
		upstream, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/?"+upstream.RawQuery, headers)
		return conn, err
	}
	w.Start()
	waitSession := func(want string) {
		t.Helper()
		select {
		case got := <-opened:
			if got != want {
				t.Fatalf("WS session = %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("WS did not open %s", want)
		}
	}
	waitSession("old-session")
	stale := r.auth.snapshot()
	r.SetFrontier("old-op")
	if _, err := r.auth.refresh(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	waitSession("fresh-session")
	if calls.Load() != 1 {
		t.Fatal("WS repeated HTTP's shared refresh")
	}
	r.setFrontierForGeneration("late-old-op", stale.generation)
	if len(r.getFrontier()) != 0 {
		t.Fatal("old WS frame overwrote the new frontier")
	}
	r.setFrontierForGeneration("fresh-op", r.auth.snapshot().generation)
	if got := r.getFrontier(); len(got) != 1 || got[0] != "fresh-op" {
		t.Fatal("fresh WS frontier ignored")
	}
}
