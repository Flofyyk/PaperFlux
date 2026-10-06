package mailru

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Handshake is bounded and the pending connection is owned by Stop even
// before it can become the active document session. No token/frame logging.
func waitMailruSocketIO(session *DocSession, token string, timeout time.Duration) error {
	if err := session.Conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer session.Conn.SetReadDeadline(time.Time{})
	waitFor := func(prefix string) error {
		for {
			kind, frame, err := session.Conn.ReadMessage()
			if err != nil {
				return err
			}
			if kind != websocket.TextMessage {
				continue
			}
			text := string(frame)
			if text == "2" {
				session.enginePings.Add(1)
				if err := session.safeWrite(websocket.TextMessage, []byte("3")); err != nil {
					return err
				}
				session.enginePongs.Add(1)
				continue
			}
			if text == "1" || text == "41" || strings.HasPrefix(text, "44") {
				return fmt.Errorf("mailru handshake rejected")
			}
			if strings.HasPrefix(text, prefix) {
				var data struct {
					SID          string `json:"sid"`
					PingInterval int    `json:"pingInterval"`
					PingTimeout  int    `json:"pingTimeout"`
				}
				if json.Unmarshal(frame[len(prefix)-1:], &data) != nil || data.SID == "" {
					return fmt.Errorf("mailru malformed handshake")
				}
				if prefix == "0{" {
					session.enginePingInterval, session.enginePingTimeout = data.PingInterval, data.PingTimeout
					log.Printf("[PAPERFLUX_MAILRU] engine_open ping_interval_ms=%d ping_timeout_ms=%d", data.PingInterval, data.PingTimeout)
				}
				return nil
			}
		}
	}
	if err := waitFor("0{"); err != nil {
		return fmt.Errorf("mailru Engine.IO open: %w", err)
	}
	auth, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return err
	}
	if err := session.safeWrite(websocket.TextMessage, append([]byte("40"), auth...)); err != nil {
		return err
	}
	if err := waitFor("40{"); err != nil {
		return fmt.Errorf("mailru Socket.IO connect: %w", err)
	}
	return nil
}

func (t *MailruDocsTransport) waitEditorAuth(session *DocSession, timeout time.Duration) error {
	if err := session.Conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer session.Conn.SetReadDeadline(time.Time{})
	for t.IsRunning() {
		kind, frame, err := session.Conn.ReadMessage()
		if err != nil {
			return err
		}
		if kind != websocket.TextMessage {
			continue
		}
		event := parseMailruEditorEvent(frame)
		if string(frame) == "1" || string(frame) == "41" || strings.HasPrefix(string(frame), "44") || event.Type == "error" || event.Type == "disconnectReason" {
			return fmt.Errorf("Mail.ru editor rejected the session")
		}
		if event.Type == "auth" && (event.Result == nil || *event.Result != 1) {
			return fmt.Errorf("Mail.ru editor did not authorize editing")
		}
		t.handleMessage(session, frame)
		if session.editorAuthed.Load() {
			return nil
		}
	}
	return fmt.Errorf("Mail.ru transport stopped")
}
