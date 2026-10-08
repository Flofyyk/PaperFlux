package yandex

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"universal-bypass-tool/transport"
)

func TestLargeCursorBatchPreservesEveryPacket(t *testing.T) {
	carrier := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	var received [][]byte
	carrier.Receive(func(p []byte) { received = append(received, append([]byte(nil), p...)) })
	var records []map[string]string
	var expected [][]byte
	records = append(records, map[string]string{"cursor": "18;---KA---"})
	for i := 0; i < 200; i++ {
		p := bytes.Repeat([]byte{byte(i), 0xff, 0x00}, 500)
		expected = append(expected, p)
		records = append(records, map[string]string{"cursor": "18;" + base64.StdEncoding.EncodeToString(p)})
	}
	records = append(records, map[string]string{"cursor": "18;---KA---"})
	payload, err := json.Marshal([]interface{}{"message", map[string]interface{}{"type": "cursor", "messages": records}})
	if err != nil {
		t.Fatal(err)
	}
	carrier.handleMessage(nil, append([]byte("42"), payload...))
	if len(received) != len(expected) {
		t.Fatalf("got=%d expected=%d", len(received), len(expected))
	}
	for i := range expected {
		if !bytes.Equal(received[i], expected[i]) {
			t.Fatalf("changed/reordered packet=%d", i)
		}
	}
	t.Logf("frame_bytes=%d packets=%d corrupted=0 skipped=0", len(payload)+2, len(received))
}

func TestLargeAuthChangesIsParsed(t *testing.T) {
	for _, size := range []int{1024, 300 * 1024, 2 * 1024 * 1024} {
		payload := []byte(`42["message",{"type":"authChanges","changes":"` + strings.Repeat("x", size) + `"}]`)
		event := parseEditorEvent(payload)
		t.Logf("bytes=%d parsed_type=%q", len(payload), event.Type)
		if size < 256*1024 && event.Type != "authChanges" {
			t.Fatal("small control not parsed")
		}
		if size > 256*1024 && event.Type != "authChanges" {
			t.Fatal("large control not parsed")
		}
	}
}

func TestControlEnvelopeRejectsEmbeddedAndMalformedEvents(t *testing.T) {
	for _, p := range []string{
		`42["other",{"type":"disconnectReason"}]`,
		`42["message",{"type":"cursor","messages":[{"type":"disconnectReason"}]}]`,
		`42["message",{"type":"authChanges"},{}]`,
		`42["message",{"type":"authChanges"}] trailing`,
		`42["message",{"type":"authChanges","changes":}]`,
	} {
		e := parseEditorEvent([]byte(p))
		if e.Type == "authChanges" || e.Type == "disconnectReason" {
			t.Fatalf("invalid control accepted: %q", p)
		}
	}
	if e := parseEditorEvent([]byte(`42[ "message" , {"type":"authChanges", "changes":[{"type":"cursor"}]} ]`)); e.Type != "authChanges" {
		t.Fatal("whitespace/history control lost")
	}
}

func TestEditorActivityDoesNotChangeContentAndDisconnectClosesSocket(t *testing.T) {
	got := make(chan []byte, 2)
	closed := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			_, p, err := c.ReadMessage()
			if err != nil {
				closed <- true
				return
			}
			got <- p
		}
	}))
	defer server.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	carrier := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	carrier.session = &DocSession{Conn: c}
	if carrier.extendEditorSession() {
		t.Fatal("activity sent before authentication")
	}
	carrier.SetConnected(true)
	if !carrier.extendEditorSession() {
		t.Fatal("activity not sent")
	}
	select {
	case p := <-got:
		var envelope []json.RawMessage
		if json.Unmarshal(p[2:], &envelope) != nil || len(envelope) != 2 {
			t.Fatal("bad activity envelope")
		}
		var body map[string]interface{}
		if json.Unmarshal(envelope[1], &body) != nil || len(body) != 2 || body["type"] != "extendSession" || body["idletime"] != float64(0) {
			t.Fatal("activity changed document or requested wrong operation")
		}
	case <-time.After(time.Second):
		t.Fatal("activity message missing")
	}
	stale := &DocSession{}
	carrier.handleMessage(stale, []byte(`42["message",{"type":"disconnectReason","code":4002}]`))
	if !carrier.IsConnected() {
		t.Fatal("old reader disconnected replacement")
	}
	carrier.handleMessage(carrier.session, []byte(`42["message",{"type":"disconnectReason","code":4002}]`))
	if carrier.IsConnected() {
		t.Fatal("rejected connection still active")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("reader not unblocked for reconnect")
	}
	if carrier.extendEditorSession() {
		t.Fatal("activity sent after rejection")
	}
}

func TestEditorDisconnectClearsConnected(t *testing.T) {
	for _, kind := range []string{"disconnectReason", "error", "drop"} {
		carrier := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
		carrier.SetConnected(true)
		carrier.handleMessage(nil, []byte(fmt.Sprintf(`42["message",{"type":%q,"code":1}]`, kind)))
		if carrier.IsConnected() {
			t.Fatal("rejected editor remained connected")
		}
		t.Logf("event=%s connected_after_event=%t", kind, carrier.IsConnected())
	}
}

func TestSmallAndLargeAuthChangesAck(t *testing.T) {
	received := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			_, p, err := c.ReadMessage()
			if err != nil {
				return
			}
			received <- string(p)
		}
	}))
	defer server.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	carrier := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	s := &DocSession{Conn: c}
	carrier.session = s
	carrier.handleMessage(s, []byte(`42["message",{"type":"authChanges"}]`))
	select {
	case p := <-received:
		if !strings.Contains(p, "authChangesAck") {
			t.Fatal("wrong ack")
		}
	case <-time.After(time.Second):
		t.Fatal("small ack missing")
	}
	carrier.handleMessage(s, []byte(`42["message",{"type":"authChanges","changes":"`+strings.Repeat("x", 300*1024)+`"}]`))
	select {
	case p := <-received:
		if !strings.Contains(p, "authChangesAck") {
			t.Fatal("wrong large ack")
		}
	case <-time.After(time.Second):
		t.Fatal("large control produced no ack")
	}
}
