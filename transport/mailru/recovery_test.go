package mailru

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"universal-bypass-tool/transport"
)

func TestMailruControlEnvelopeAndStaleReader(t *testing.T) {
	s, received, _ := mailruTestSocket(t)
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	tr.session = s
	tr.SetConnected(true)
	for _, frame := range []string{
		`42["other",{"type":"disconnectReason"}]`,
		`42["message",{"type":"cursor","messages":[{"type":"disconnectReason"}]}]`,
		`42["message",{"type":"authChanges"},{}]`,
		`42["message",{"type":"authChanges"}] trailing`,
		`42["message",{"type":"authChanges","changes":}]`,
	} {
		tr.handleMessage(s, []byte(frame))
		if !tr.IsConnected() {
			t.Fatal("embedded/malformed control disconnected session")
		}
	}
	tr.handleMessage(&DocSession{}, []byte(`42["message",{"type":"disconnectReason","code":4002}]`))
	tr.handleMessage(&DocSession{}, []byte(`42["message",{"type":"authChanges"}]`))
	if !tr.IsConnected() {
		t.Fatal("stale reader disconnected replacement")
	}
	select {
	case <-received:
		t.Fatal("invalid/stale event acknowledged")
	default:
	}
	tr.handleMessage(s, []byte(`42[ "message" , {"type":"authChanges", "changes":[{"type":"cursor"}]} ]`))
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("valid whitespace envelope lost")
	}
}

func TestMailruLargeHistoryCrossesWebSocket(t *testing.T) {
	frame := []byte(`42["message",{"type":"authChanges","changes":"` + strings.Repeat("x", 5<<20) + `"}]`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.TextMessage, frame)
		_, _, _ = c.ReadMessage()
	}))
	defer server.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadLimit(maxMailruEditorFrameBytes)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, got, err := c.ReadMessage()
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatal("large document history rejected by WebSocket")
	}
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	tr.session = &DocSession{Conn: c}
	tr.handleMessage(tr.session, got)
}

func TestMailruHandshakeRejectsImmediatelyWithoutPrivateBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.TextMessage, []byte(`0{"sid":"test"}`))
		_, _, _ = c.ReadMessage()
		_ = c.WriteMessage(websocket.TextMessage, []byte(`44{"message":"private-document-token"}`))
		_, _, _ = c.ReadMessage() // Leave the socket open until the client closes it.
	}))
	defer server.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	started := time.Now()
	err = waitMailruSocketIO(&DocSession{Conn: c}, "test")
	if err == nil || strings.Contains(err.Error(), "private-document-token") || time.Since(started) > time.Second {
		t.Fatal("handshake rejection delayed or leaked private provider body")
	}
}

func BenchmarkMailruPacketHandling(b *testing.B) {
	for _, count := range []int{1, 16} {
		var entries []string
		packet := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 1500))
		for i := 0; i < count; i++ {
			entries = append(entries, cursorEntry(packet))
		}
		frame := []byte(`42["message",{"type":"cursor","messages":[` + strings.Join(entries, ",") + `]}]`)
		for _, revised := range []bool{false, true} {
			b.Run(fmt.Sprintf("packets%d/revised%t", count, revised), func(b *testing.B) {
				tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
				tr.Receive(func([]byte) {})
				b.SetBytes(int64(1500 * count))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if revised {
						tr.handleMessage(nil, frame)
						continue
					}
					// Published upstream-style handler, without test-only shortcuts.
					text := string(frame)
					if strings.Contains(text, `"type":"auth"`) && strings.Contains(text, `"result":1`) {
						continue
					}
					if strings.Contains(text, "cursor") {
						for _, p := range cursorPayloads(text) {
							decoded, err := base64.StdEncoding.DecodeString(p)
							if err != nil {
								continue
							}
							tr.RecordReceive(len(decoded))
							tr.CallReceive(decoded)
						}
					}
				}
			})
		}
	}
}

func mailruTestSocket(t *testing.T) (*DocSession, <-chan string, <-chan struct{}) {
	t.Helper()
	received := make(chan string, 8)
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		defer close(closed)
		for {
			_, p, err := c.ReadMessage()
			if err != nil {
				return
			}
			received <- string(p)
		}
	}))
	t.Cleanup(server.Close)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &DocSession{Conn: c}, received, closed
}

func TestMailruAuthChangesAlwaysAcknowledged(t *testing.T) {
	s, received, _ := mailruTestSocket(t)
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	tr.session = s
	for _, size := range []int{0, 300 << 10, 5 << 20} {
		frame := []byte(`42["message",{"type":"authChanges","changes":"` + strings.Repeat("x", size) + `"}]`)
		tr.handleMessage(s, frame)
		select {
		case p := <-received:
			if p != `42["message",{"type":"authChangesAck"}]` {
				t.Fatal("incorrect acknowledgement")
			}
		case <-time.After(time.Second):
			t.Fatalf("authChanges acknowledgement missing: history_bytes=%d", size)
		}
	}
}

func TestMailruEditorRejectionUnblocksReader(t *testing.T) {
	for _, frame := range []string{
		`42["message",{"type":"disconnectReason","code":4002}]`,
		`42["message",{"type":"error","code":1}]`,
		`42["message",{"type":"drop"}]`,
		`42["message",{"type":"auth","result":0}]`,
		`42["message",{"type":"auth","result":10}]`,
		`41`, `1`, `44{"message":"private-token"}`,
	} {
		t.Run(frame[:min(20, len(frame))], func(t *testing.T) {
			s, _, closed := mailruTestSocket(t)
			tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
			tr.session = s
			tr.SetConnected(true)
			tr.handleMessage(s, []byte(frame))
			if tr.IsConnected() {
				t.Fatal("rejected editor still marked connected")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("socket reader remains blocked")
			}
			if !tr.dropSession(s) {
				t.Fatal("reader cannot own the reconnect after rejection")
			}
		})
	}
}

func TestMailruLargePacketBatchPreservesAllBytesAndOrder(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	var received, expected [][]byte
	tr.Receive(func(p []byte) { received = append(received, append([]byte(nil), p...)) })
	var entries []string
	entries = append(entries, cursorEntry("---KA---"))
	for i := 0; i < 200; i++ {
		p := bytes.Repeat([]byte{byte(i), 0xff, 0}, 500)
		expected = append(expected, p)
		entries = append(entries, cursorEntry(base64.StdEncoding.EncodeToString(p)))
		if i%10 == 0 {
			entries = append(entries, cursorEntry("---KA---"))
		}
	}
	frame := []byte(`42["message",{"type":"cursor","messages":[` + strings.Join(entries, ",") + `]}]`)
	tr.handleMessage(nil, frame)
	if len(received) != len(expected) {
		t.Fatalf("lost packets: got=%d want=%d", len(received), len(expected))
	}
	for i, p := range expected {
		if !bytes.Equal(p, received[i]) {
			t.Fatalf("corruption/reordering at packet=%d", i)
		}
	}
	t.Logf("frame_bytes=%d packets=%d dropped=0 corrupted=0", len(frame), len(received))
}
