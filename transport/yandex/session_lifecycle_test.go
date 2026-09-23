package yandex

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestBootstrapCacheRotatesEditorIdentity(t *testing.T) {
	transport := &YandexDocsTransport{}
	transport.cacheDocInfo(YandexDocsInfo{
		UserID:  "old",
		OpenCmd: map[string]interface{}{"userid": "old", "id": "document"},
	})
	first, ok := transport.cachedDocInfo("next")
	if !ok || first.UserID != "next" || first.OpenCmd["userid"] != "next" {
		t.Fatalf("cached editor identity not refreshed: %#v, %v", first, ok)
	}
	first.OpenCmd["id"] = "changed"
	second, ok := transport.cachedDocInfo("third")
	if !ok || second.OpenCmd["id"] != "document" || second.OpenCmd["userid"] != "third" {
		t.Fatalf("cached bootstrap was mutated: %#v, %v", second, ok)
	}
	transport.bootstrapAt = time.Now().Add(-bootstrapCacheAge)
	if _, ok := transport.cachedDocInfo("expired"); ok {
		t.Fatal("expired bootstrap reused")
	}
	transport.invalidateDocInfo()
	if _, ok := transport.cachedDocInfo("invalidated"); ok {
		t.Fatal("invalidated bootstrap reused")
	}
}

func TestSessionStallReason(t *testing.T) {
	now := time.Now()
	session := &DocSession{createdAt: now.Add(-editorAuthTimeout - time.Second)}
	if got := sessionStallReason(session, now, true); got != "editor authentication timed out" {
		t.Fatalf("missing editor timeout: %q", got)
	}
	session.readyAt.Store(now.Add(-protectedPathTimeout - time.Second).UnixNano())
	if got := sessionStallReason(session, now, true); got != "no authenticated peer proof" {
		t.Fatalf("missing peer timeout: %q", got)
	}
	if got := sessionStallReason(session, now, false); got != "" {
		t.Fatalf("idle exit node marked stalled: %q", got)
	}
	session.proofAt.Store(now.Add(-time.Second).UnixNano())
	if got := sessionStallReason(session, now, true); got != "" {
		t.Fatalf("live peer marked stalled: %q", got)
	}
	session.expectedClose.Store(true)
	session.proofAt.Store(now.Add(-protectedPathTimeout - time.Second).UnixNano())
	if got := sessionStallReason(session, now, true); got != "" {
		t.Fatalf("planned editor rotation marked stalled: %q", got)
	}
}

func TestRetiredSessionSkipsKeepaliveWrite(t *testing.T) {
	session := &DocSession{done: make(chan struct{})}
	session.retire()
	if err := session.safeWrite(1, []byte("keepalive")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired session write = %v", err)
	}
}
