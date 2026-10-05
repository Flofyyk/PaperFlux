package main

import (
	"maps"
	"testing"
	"time"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/control"
	"universal-bypass-tool/transport/ipc"
	"universal-bypass-tool/transport/manager"
)

type runtimeCookieLane struct {
	*transport.BaseTransport
	jar map[string]string
}

func (p *runtimeCookieLane) Send([]byte) error                        { return nil }
func (p *runtimeCookieLane) FetchCookies() (map[string]string, error) { return maps.Clone(p.jar), nil }
func (p *runtimeCookieLane) ApplyCookies(jar map[string]string) error {
	p.jar = maps.Clone(jar)
	return nil
}

func runtimeCookieFixture(t *testing.T) (*sessionIPC, *runtimeCookieLane, []byte) {
	t.Helper()
	doc := "https://disk.yandex.ru/i/test-only"
	lane := &runtimeCookieLane{BaseTransport: transport.NewBaseTransport(transport.DefaultConfig()), jar: map[string]string{"spravka": "stored-but-not-verified"}}
	m := manager.New(nil, nil, "", "")
	if err := m.Add("yandex-1", "yandex", lane, 100, lane); err != nil {
		t.Fatal(err)
	}
	m.SetURL("yandex-1", doc)
	h := &sessionIPC{manager: m, pending: map[string]*ipc.CookiesRequestPayload{
		"false/yandex-1": {RequestID: "original-id", Transport: "yandex-1", URL: doc},
		"true/yandex-1":  {RequestID: "server-check", Transport: "yandex-1", URL: doc, Remote: true},
	}, snooze: make(map[string]time.Time)}
	body, err := (&control.CookiesPayload{Transport: "yandex-1", Doc: doc, Jar: maps.Clone(lane.jar)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return h, lane, body
}

func TestBackgroundCookiesCannotCompleteBlockedDocumentCheck(t *testing.T) {
	h, lane, body := runtimeCookieFixture(t)
	service := &runtimeCookieLane{BaseTransport: transport.NewBaseTransport(transport.DefaultConfig())}
	service.SetConnected(true)
	if err := h.manager.Add("auth-service", "direct", service, 1000, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		h.onPeerCookies(body)
		h.clearConnectedLocalPending()
		h.remember(&ipc.CookiesRequestPayload{Transport: "yandex-1", URL: "https://disk.yandex.ru/i/test-only"})
		if h.pending["false/yandex-1"].RequestID != "original-id" || len(h.pending) != 2 {
			t.Fatal("cookie snapshot/service connectivity falsely completed check or cycled its ID")
		}
	}
	lane.SetConnected(true)
	h.onPeerCookies(body)
	if h.pending["false/yandex-1"] != nil || h.pending["true/yandex-1"] == nil {
		t.Fatal("real local connection did not clear only the local document check")
	}
}

func TestConnectedOtherDocumentCannotClearBlockedDocumentCheck(t *testing.T) {
	h, lane, _ := runtimeCookieFixture(t)
	other := &runtimeCookieLane{BaseTransport: transport.NewBaseTransport(transport.DefaultConfig()), jar: map[string]string{"spravka": "pass"}}
	other.SetConnected(true)
	if err := h.manager.Add("yandex-2", "yandex", other, 99, other); err != nil {
		t.Fatal(err)
	}
	h.clearConnectedLocalPending()
	if len(h.pending) != 2 {
		t.Fatal("an unrelated healthy document cleared a blocked document")
	}
	lane.SetConnected(true)
	h.clearConnectedLocalPending()
	if len(h.pending) != 1 || h.pending["true/yandex-1"] == nil {
		t.Fatal("local lane recovery incorrectly cleared the remote check")
	}
}
