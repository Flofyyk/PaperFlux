package mailru

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Document history is not a VPN packet and can be several MiB. Keep a hard
// memory bound without the old 256 KiB control / 4 MiB WebSocket cutoffs.
const maxMailruEditorFrameBytes = 64 << 20

type mailruEditorEvent struct {
	Type   string `json:"type"`
	Result *int   `json:"result"`
	Code   int    `json:"code"`
}

func parseMailruEditorEvent(data []byte) mailruEditorEvent {
	if len(data) > maxMailruEditorFrameBytes {
		return mailruEditorEvent{}
	}
	// The normal packet envelope matches upstream exactly. It needs no
	// control decoding/history validation on the hot data path; retain the
	// published cursor extractor and its throughput/allocation behaviour.
	if bytes.HasPrefix(data, []byte(`42["message",{"type":"cursor",`)) {
		return mailruEditorEvent{Type: "cursor"}
	}
	if !bytes.HasPrefix(data, []byte("42[")) || !json.Valid(data[2:]) {
		return mailruEditorEvent{}
	}
	// Read the event name from a bounded prefix. Decode only small top-level
	// control fields, never copy the document history into maps/RawMessages.
	decoder := json.NewDecoder(bytes.NewReader(data[2:min(len(data), 258)]))
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return mailruEditorEvent{}
	}
	var name string
	if decoder.Decode(&name) != nil || name != "message" {
		return mailruEditorEvent{}
	}
	body := bytes.TrimSpace(data[2+int(decoder.InputOffset()):])
	if len(body) < 3 || body[0] != ',' || body[len(body)-1] != ']' {
		return mailruEditorEvent{}
	}
	var event mailruEditorEvent
	if json.Unmarshal(body[1:len(body)-1], &event) != nil {
		return mailruEditorEvent{}
	}
	return event
}

func mailruSocketRejected(text string) bool {
	return text == "1" || text == "41" || strings.HasPrefix(text, "44")
}

func (t *MailruDocsTransport) retireEditorSession(session *DocSession) {
	t.Mu.Lock()
	if session != nil && t.session != session {
		t.Mu.Unlock()
		return
	}
	t.SetConnected(false)
	t.Mu.Unlock()
	if session != nil && session.Conn != nil {
		_ = session.Conn.Close()
	}
	// Do not clear t.session here: its reader owns dropSession and exactly
	// one reconnect. Closing also unblocks a server that left its socket open.
}
