package mailru

import (
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMailruNegotiatedReadTimeout(t *testing.T) {
	for _, tc := range []struct {
		frame string
		want  time.Duration
	}{
		{`0{"pingInterval":25000,"pingTimeout":20000}`, 60 * time.Second},
		{`0{"pingInterval":60000,"pingTimeout":30000}`, 105 * time.Second},
		{`0{}`, 90 * time.Second}, {`0{"pingInterval":-1,"pingTimeout":999999999}`, 90 * time.Second},
	} {
		if got := mailruReadTimeout(tc.frame); got != tc.want {
			t.Fatalf("%s: %v", tc.frame, got)
		}
	}
}

func TestMailruReadWatchdogRenewsThenDetectsSilence(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := upgrader.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		for i := 0; i < 4; i++ {
			time.Sleep(40 * time.Millisecond)
			if c.WriteMessage(websocket.TextMessage, []byte("2")) != nil {
				return
			}
		}
		<-stop
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	session := &DocSession{Conn: conn, readTimeout: 120 * time.Millisecond}
	for i := 0; i < 4; i++ {
		if _, _, err := session.readMessage(); err != nil {
			t.Fatalf("healthy heartbeat %d: %v", i, err)
		}
	}
	start := time.Now()
	if _, _, err := session.readMessage(); err == nil {
		t.Fatal("silent socket stayed alive")
	}
	if time.Since(start) > time.Second {
		t.Fatal("read watchdog did not expire")
	}
}
