package mailru

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"universal-bypass-tool/transport"
)

func TestHandshakeOrderPingTimeoutRejectionAndStop(t *testing.T) {
	for _, mode := range []string{"success", "timeout", "reject", "stop"} {
		t.Run(mode, func(t *testing.T) {
			serverDone := make(chan error, 1)
			up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := up.Upgrade(w, r, nil)
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				if mode != "success" {
					if mode == "reject" {
						_ = conn.WriteMessage(websocket.TextMessage, []byte(`44{"message":"rejected"}`))
					}
					_, _, err = conn.ReadMessage()
					serverDone <- err
					return
				}
				for _, frame := range []string{"2", `0{"sid":"engine","pingInterval":25000,"pingTimeout":20000}`} {
					if err = conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
						serverDone <- err
						return
					}
				}
				_, pong, err := conn.ReadMessage()
				if err != nil || string(pong) != "3" {
					serverDone <- http.ErrAbortHandler
					return
				}
				_, connect, err := conn.ReadMessage()
				if err != nil || string(connect) != `40{"token":"test"}` {
					serverDone <- http.ErrAbortHandler
					return
				}
				err = conn.WriteMessage(websocket.TextMessage, []byte(`40{"sid":"socket"}`))
				serverDone <- err
			}))
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
			_ = tr.BaseTransport.Start()
			session := &DocSession{Conn: conn}
			tr.pending = session
			done := make(chan error, 1)
			go func() { done <- waitMailruSocketIO(session, "test", 80*time.Millisecond) }()
			if mode == "stop" {
				_ = tr.Stop()
			}
			select {
			case err = <-done:
				if (err == nil) != (mode == "success") {
					t.Fatalf("handshake result %v", err)
				}
				if mode == "success" && (session.enginePingInterval != 25000 || session.enginePingTimeout != 20000 || session.enginePings.Load() != 1 || session.enginePongs.Load() != 1) {
					t.Fatal("Engine.IO heartbeat metadata/counters lost")
				}
			case <-time.After(time.Second):
				t.Fatal("handshake stuck")
			}
			if mode == "stop" && tr.publishSession(session) {
				t.Fatal("stopped handshake published")
			}
			_ = conn.Close()
			select {
			case err = <-serverDone:
				if mode == "success" && err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("server stuck")
			}
			_ = tr.Stop()
		})
	}
}

func TestAllCursorEntriesDelivered(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	var got []string
	tr.Receive(func(data []byte) { got = append(got, string(data)) })
	tr.handleMessage(&DocSession{}, []byte(`42["message",{"messages":[{"cursor":"18;---KA---"},{"cursor":"18;YQ=="},{"cursor":"18;invalid?"},{"cursor":"18;Yg=="}]}]`))
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("delivered %v", got)
	}
}
