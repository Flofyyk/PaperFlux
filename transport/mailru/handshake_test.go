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
	session := &DocSession{}
	session.editorAuthed.Store(true)
	tr.handleMessage(session, []byte(`42["message",{"messages":[{"cursor":"18;---KA---"},{"cursor":"18;YQ=="},{"cursor":"18;invalid?"},{"cursor":"18;Yg=="}]}]`))
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("delivered %v", got)
	}
}

func TestEditorAuthorizationIsStructuredAndRequired(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	session := &DocSession{}
	delivered := 0
	tr.Receive(func([]byte) { delivered++ })
	for _, frame := range []string{
		`42["message",{"type":"cursor","cursor":"18;YQ=="}]`,
		`42["other",{"type":"auth","result":1}]`,
		`42["message",{"type":"auth","result":10}]`,
		`42["message",{"type":"cursor","note":"\"type\":\"auth\",\"result\":1"}]`,
	} {
		tr.handleMessage(session, []byte(frame))
	}
	if session.editorAuthed.Load() || delivered != 0 {
		t.Fatal("accepted data or auth before editor authorization")
	}
	tr.handleMessage(session, []byte(`42["message", { "type": "auth", "result": 1 }]`))
	if !session.editorAuthed.Load() {
		t.Fatal("valid whitespace-formatted authorization ignored")
	}
	tr.handleMessage(session, []byte(`42["message",{"type":"cursor","cursor":"18;YQ=="}]`))
	if delivered != 1 {
		t.Fatal("authorized cursor not delivered")
	}
}

func TestWaitEditorAuthSuccessRejectTimeoutAndStop(t *testing.T) {
	for _, mode := range []string{"success", "reject", "timeout", "stop"} {
		t.Run(mode, func(t *testing.T) {
			ready := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				close(ready)
				if mode == "success" {
					_ = conn.WriteMessage(websocket.TextMessage, []byte("2"))
					_, _, _ = conn.ReadMessage()
					_ = conn.WriteMessage(websocket.TextMessage, []byte(`42["message", {"type":"auth", "result":1}]`))
				} else if mode == "reject" {
					_ = conn.WriteMessage(websocket.TextMessage, []byte(`42["message",{"type":"auth","result":0}]`))
				}
				_, _, _ = conn.ReadMessage()
			}))
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			<-ready
			tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
			_ = tr.BaseTransport.Start()
			session := &DocSession{Conn: conn}
			tr.pending = session
			done := make(chan error, 1)
			go func() { done <- tr.waitEditorAuth(session, 100*time.Millisecond) }()
			if mode == "stop" {
				_ = tr.Stop()
			}
			select {
			case err = <-done:
				if (err == nil) != (mode == "success") {
					t.Fatalf("unexpected result in %s: %v", mode, err)
				}
				if tr.IsConnected() {
					t.Fatal("waiting must not publish session readiness")
				}
				if session.editorAuthed.Load() != (mode == "success") {
					t.Fatal("incorrect editor auth state")
				}
			case <-time.After(time.Second):
				t.Fatal("editor auth did not stop")
			}
			_ = tr.Stop()
		})
	}
}
