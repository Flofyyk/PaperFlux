package yandex

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"universal-bypass-tool/transport"
)

func TestCollaborativeAuthUnlockDoesNotChangeContent(t *testing.T) {
	written := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, p, err := c.ReadMessage()
		if err == nil {
			written <- p
		}
	}))
	defer server.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tpt := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	tpt.handleMessage(&DocSession{Conn: c}, []byte(`42["message", {"type": "connectState", "waitAuth": true}]`))
	select {
	case p := <-written:
		var envelope []json.RawMessage
		if len(p) < 2 || json.Unmarshal(p[2:], &envelope) != nil || len(envelope) != 2 {
			t.Fatal("invalid unlock envelope")
		}
		var fields map[string]interface{}
		if json.Unmarshal(envelope[1], &fields) != nil {
			t.Fatal("invalid unlock body")
		}
		if len(fields) != 4 || fields["type"] != "unLockDocument" || fields["unlock"] != true || fields["isSave"] != false || fields["releaseLocks"] != false {
			t.Fatalf("unsafe auth unlock: %s", p)
		}
	case <-time.After(time.Second):
		t.Fatal("collaborative authentication lock not completed")
	}
	if tpt.IsConnected() {
		t.Fatal("unlock request must not itself prove authentication")
	}
}

func TestEditorControlParserIgnoresEmbeddedEventText(t *testing.T) {
	for _, frame := range []string{
		`42["other",{"type":"connectState","waitAuth":true}]`,
		`42["message",{"type":"cursor","cursor":"type:connectState,waitAuth:true"}]`,
		`42["message",{"type":"connectState","waitAuth":"true"}]`,
	} {
		if e := parseEditorEvent([]byte(frame)); e.Type == "connectState" && e.WaitAuth {
			t.Fatalf("false control event: %s", frame)
		}
	}
	if e := parseEditorEvent([]byte(`42["message",{"type":"disconnectReason","code":4007,"description":"private"}]`)); e.Type != "disconnectReason" || e.Code != 4007 {
		t.Fatal("numeric disconnect diagnostics lost")
	}
}

func TestReconnectBackoffFastFirstRetryAndBoundedFailureStreak(t *testing.T) {
	for i := 0; i < 100; i++ {
		if d := reconnectBackoff(0); d < 350*time.Millisecond || d >= 600*time.Millisecond {
			t.Fatalf("healthy retry too slow: %s", d)
		}
		if d := reconnectBackoff(10); d > 30*time.Second || d < 20*time.Second {
			t.Fatalf("failure retry unbounded: %s", d)
		}
		if d := reconnectBackoff(1); d < 1500*time.Millisecond {
			t.Fatal("immediate failure loop")
		}
	}
}
