package main

import (
	"path/filepath"
	"testing"
	"time"
	"universal-bypass-tool/transport/ipc"
)

func TestAuthRequestIdentityAndSnooze(t *testing.T) {
	h := &sessionIPC{pending: map[string]*ipc.CookiesRequestPayload{}, snooze: map[string]time.Time{}}
	path := filepath.Join(t.TempDir(), "profile.snooze")
	h.restoreSnooze(path)
	first := &ipc.CookiesRequestPayload{Transport: "yandex-1", Remote: true}
	h.remember(first)
	if first.RequestID == "" {
		t.Fatal("request has no identity")
	}
	second := &ipc.CookiesRequestPayload{Transport: "yandex-1", Remote: true}
	h.remember(second)
	if second.RequestID != first.RequestID {
		t.Fatal("repeated notification replaced active check")
	}
	local := &ipc.CookiesRequestPayload{Transport: "yandex-1"}
	h.remember(local)
	if local.RequestID == first.RequestID || len(h.pending) != 2 {
		t.Fatal("local and server checks mixed")
	}
	// An old cookie reply must never touch the current request or manager.
	h.OnCookies(&ipc.CookiesOfferPayload{Transport: "yandex-1", Remote: true, RequestID: "stale", Jar: map[string]string{"test": "value"}})
	if len(h.pending) != 2 {
		t.Fatal("stale reply cleared another request")
	}
	h.OnCommand(&ipc.CommandPayload{Action: "cancel-auth", Params: map[string]interface{}{"requestId": first.RequestID}})
	h.remember(&ipc.CookiesRequestPayload{Transport: "yandex-1", Remote: true})
	if len(h.pending) != 1 || time.Until(h.snooze["true/yandex-1"]) < 9*time.Minute {
		t.Fatal("cancelled check immediately returned")
	}
	restarted := &sessionIPC{pending: map[string]*ipc.CookiesRequestPayload{}, snooze: map[string]time.Time{}}
	restarted.restoreSnooze(path)
	restarted.remember(&ipc.CookiesRequestPayload{Transport: "yandex-1", Remote: true})
	if len(restarted.pending) != 0 {
		t.Fatal("worker restart lost cancelled server check")
	}
}
