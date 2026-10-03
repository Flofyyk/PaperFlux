package mailru

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"universal-bypass-tool/transport"
)

func TestDisconnectDetailsDoNotDependOnSecretErrorText(t *testing.T) {
	code, timeout := mailruDisconnectDetails(fmt.Errorf("private editor URL: %w", &websocket.CloseError{Code: 1005, Text: "private token"}))
	if code != 1005 || timeout {
		t.Fatalf("code=%d timeout=%t", code, timeout)
	}
	code, timeout = mailruDisconnectDetails(fmt.Errorf("private URL: %w", os.ErrDeadlineExceeded))
	if code != 0 || !timeout {
		t.Fatalf("code=%d timeout=%t", code, timeout)
	}
}

func TestEditorSessionControl(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"collaboration", `42["message", {"type":"connectState", "waitAuth":true}]`, `42["message",{"type":"unLockDocument","unlock":true,"isSave":false,"releaseLocks":false}]`},
		{"changesAck", `42["message",{"type":"authChanges","changes":[]}]`, `42["message",{"type":"authChangesAck"}]`},
		{"otherEvent", `42["other",{"type":"connectState","waitAuth":true}]`, ""},
		{"embedded", `42["message",{"type":"cursor","cursor":"type:connectState,waitAuth:true"}]`, ""},
		{"wrongType", `42["message",{"type":"connectState","waitAuth":"true"}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testSessionWrites(t, func(s *DocSession) {
				tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
				tr.handleMessage(s, []byte(tc.input))
				if tr.IsConnected() {
					t.Fatal("control response is not proof of connectivity")
				}
			}, tc.want)
		})
	}
}

func TestEditorKeepAliveExtendsOnlyAuthenticatedSession(t *testing.T) {
	for _, authed := range []bool{false, true} {
		t.Run(fmt.Sprint(authed), func(t *testing.T) {
			want := []string{}
			if authed {
				want = append(want, `42["message",{"type":"extendSession","idletime":0}]`)
			}
			want = append(want, `42["message",{"type":"cursor","cursor":"18;---KA---"}]`)
			testSessionWrites(t, func(s *DocSession) {
				s.editorAuthed.Store(authed)
				if err := s.sendEditorKeepAlive(); err != nil {
					t.Fatal(err)
				}
			}, want...)
		})
	}
}

func testSessionWrites(t *testing.T, send func(*DocSession), want ...string) {
	t.Helper()
	written := make(chan []string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			written <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		var got []string
		for {
			_, p, err := c.ReadMessage()
			if err != nil {
				break
			}
			got = append(got, string(p))
		}
		written <- got
	}))
	defer server.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	send(&DocSession{Conn: c})
	select {
	case got := <-written:
		if len(want) == 1 && want[0] == "" {
			want = nil
		}
		if len(got) != len(want) {
			t.Fatalf("frames %q, want %q", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("frame %q, want %q", got[i], want[i])
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}
}
