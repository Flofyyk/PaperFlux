package yandex

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"universal-bypass-tool/transport"
)

func TestCollaborativeLockAndAuthChangesAck(t *testing.T) {
	ack := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, p, err := c.ReadMessage()
		if err == nil {
			ack <- string(p)
		}
	}))
	defer server.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	carrier := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	session := &DocSession{Conn: c}
	carrier.session = session
	carrier.handleMessage(session, []byte(`42["message",{"type":"waitAuth"}]`))
	if !carrier.IsConnected() {
		t.Fatal("collaborative lock blocked cursor relay")
	}
	carrier.handleMessage(session, []byte(`42["message",{"type":"authChanges"}]`))
	select {
	case p := <-ack:
		if p != `42["message",{"type":"authChangesAck"}]` {
			t.Fatalf("wrong ack: %q", p)
		}
	case <-time.After(time.Second):
		t.Fatal("authChanges was not acknowledged")
	}
}
