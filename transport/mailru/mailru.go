// Package mailru implements a transport that tunnels packets through
// Mail.ru's cloud document editor (docs.datacloudmail.ru), the same
// coauthoring backend family as Yandex.Docs. Two peers open the same
// public document and smuggle packets through the "cursor" field of the
// collaborative editing protocol.
package mailru

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

const mailruUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"

var cursorPayloadRe = regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)

type MailruDocsInfo struct {
	Token        string
	DocKey       string
	WsURL        string
	FileType     string
	DocURL       string
	DocTitle     string
	Permissions  map[string]interface{}
	CallbackURL  string
	EditorUserID string
}

type DocSession struct {
	Info               MailruDocsInfo
	Conn               *websocket.Conn
	WriteQueue         chan []byte
	UserID             string
	writeMu            sync.Mutex
	enginePings        atomic.Uint64
	enginePongs        atomic.Uint64
	enginePingInterval int
	enginePingTimeout  int
	editorAuthed       atomic.Bool
}

func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.Conn.WriteMessage(messageType, data)
}

type MailruDocsTransport struct {
	*transport.BaseTransport

	weblink    string
	session    *DocSession
	pending    *DocSession
	writeQueue chan []byte

	userCounter   atomic.Int32
	writeFailures atomic.Uint64
	baseUserID    string
}

// NewMailruDocsTransport accepts either a bare weblink ("AbCdEfGh1/IjKlMnOp2")
// or a full public URL ("https://cloud.mail.ru/public/AbCdEfGh1/IjKlMnOp2"),
// normalizing the latter to the former.
func NewMailruDocsTransport(weblink string, config transport.TransportConfig) *MailruDocsTransport {
	t := &MailruDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		weblink:       normalizeWeblink(weblink),
	}
	t.baseUserID = randUserID()
	return t
}

func normalizeWeblink(weblink string) string {
	weblink = strings.TrimSpace(weblink)
	for _, prefix := range []string{
		"https://cloud.mail.ru/public/",
		"http://cloud.mail.ru/public/",
		"https://cloud.mail.ru/",
		"http://cloud.mail.ru/",
	} {
		if strings.HasPrefix(weblink, prefix) {
			return strings.Trim(strings.TrimPrefix(weblink, prefix), "/")
		}
	}
	return weblink
}

func (t *MailruDocsTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	t.Mu.Lock()
	t.writeQueue = make(chan []byte, t.GetConfig().MaxQueueSize)
	t.Mu.Unlock()
	utils.SafeGo("mailru.writer", t.writerLoop)
	utils.SafeGo("mailru.keepAlive", t.keepAliveLoop)
	t.connectToDoc(0)

	return nil
}

func (t *MailruDocsTransport) Stop() error {
	_ = t.BaseTransport.Stop()
	t.Mu.Lock()
	session := t.session
	pending := t.pending
	t.session = nil
	t.pending = nil
	t.writeQueue = nil
	t.Mu.Unlock()
	if session != nil && session.Conn != nil {
		_ = session.Conn.Close()
	}
	if pending != nil && pending.Conn != nil {
		_ = pending.Conn.Close()
	}
	return nil
}

func (t *MailruDocsTransport) Send(data []byte) error {
	if !t.IsConnected() {
		return fmt.Errorf("transport not connected")
	}

	t.Mu.RLock()
	session := t.session
	queue := t.writeQueue
	t.Mu.RUnlock()

	if session == nil || queue == nil {
		return fmt.Errorf("no active session")
	}

	select {
	case queue <- append([]byte(nil), data...):
		return nil
	default:
		return fmt.Errorf("write queue full")
	}
}

func (t *MailruDocsTransport) Stats() transport.TransportStats {
	st := t.BaseTransport.Stats()
	t.Mu.RLock()
	st.QueuePackets = uint64(len(t.writeQueue))
	t.Mu.RUnlock()
	st.WriteFailures = t.writeFailures.Load()
	return st
}

func (t *MailruDocsTransport) LaneHealth() transport.LaneHealth {
	t.Mu.RLock()
	queue := t.writeQueue
	t.Mu.RUnlock()
	load := 0.0
	if queue != nil && cap(queue) > 0 {
		load = float64(len(queue)) / float64(cap(queue))
	}
	return transport.LaneHealth{Connected: t.IsConnected(), QueueLoad: load, WriteFailures: t.Stats().WriteFailures}
}

func (t *MailruDocsTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}

	utils.Debugf("[M-DOCS] connectToDoc attempt %d", attempt)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				utils.Debugf("[PANIC] recovered in mailru.connect: %v", r)
			}
		}()
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		var userID string
		if existingSession != nil {
			userID = existingSession.UserID
		} else {
			suffix := fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
			userID = t.baseUserID + suffix
		}

		info, err := t.fetchDocInfo(t.weblink)
		if err != nil {
			utils.Debugf("[M-DOCS] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}

		dialer := websocket.Dialer{
			HandshakeTimeout: 15 * time.Second,
			NetDialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		headers := http.Header{}
		headers.Set("User-Agent", mailruUserAgent)
		headers.Set("Origin", "https://docs.datacloudmail.ru")

		utils.Debugf("[M-DOCS] WebSocket dial %s", info.WsURL)
		conn, resp, err := dialer.Dial(info.WsURL, headers)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			utils.Debugf("[M-DOCS] WebSocket dial failed (http %d): %v", status, err)
			t.scheduleReconnect(attempt)
			return
		}
		utils.Debugf("[M-DOCS] WebSocket connected")
		conn.SetReadLimit(1 << 20)

		if !t.IsRunning() {
			_ = conn.Close()
			return
		}
		t.Mu.RLock()
		writeQueue := t.writeQueue
		t.Mu.RUnlock()
		if writeQueue == nil {
			_ = conn.Close()
			return
		}

		session := &DocSession{
			Info:       info,
			Conn:       conn,
			WriteQueue: writeQueue,
			UserID:     userID,
		}

		t.Mu.Lock()
		if !t.IsRunning() || t.pending != nil || t.session != nil {
			t.Mu.Unlock()
			_ = conn.Close()
			return
		}
		t.pending = session
		t.Mu.Unlock()
		handshakeErr := waitMailruSocketIO(session, info.Token, 15*time.Second)
		t.Mu.Lock()
		current := t.pending == session && t.IsRunning()
		if (handshakeErr != nil || !current) && t.pending == session {
			t.pending = nil
		}
		if handshakeErr != nil || !current {
			t.Mu.Unlock()
			_ = conn.Close()
			if current {
				t.scheduleReconnect(attempt)
			}
			return
		}
		t.Mu.Unlock()

		authMsg := map[string]interface{}{
			"type":                "auth",
			"docid":               info.DocKey,
			"documentCallbackUrl": info.CallbackURL,
			"token":               "fghhfgsjdgfjs",
			"user": map[string]interface{}{
				"id":        info.EditorUserID,
				"username":  userID,
				"indexUser": -1,
			},
			"editorType":         0,
			"lastOtherSaveTime":  -1,
			"block":              []interface{}{},
			"documentFormatSave": 65,
			"view":               false,
			"isCloseCoAuthoring": false,
			"openCmd": map[string]interface{}{
				"c":               "open",
				"id":              info.DocKey,
				"userid":          info.EditorUserID,
				"format":          info.FileType,
				"url":             info.DocURL,
				"title":           info.DocTitle,
				"lcid":            25,
				"nobase64":        true,
				"convertToOrigin": ".pdf.xps.oxps.djvu",
			},
			"lang":                  "ru",
			"mode":                  "edit",
			"permissions":           info.Permissions,
			"IsAnonymousUser":       false,
			"timezoneOffset":        -180,
			"coEditingMode":         "fast",
			"jwtOpen":               info.Token,
			"time":                  1000,
			"supportAuthChangesAck": true,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authMsg})
		if err := session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart)))); err != nil {
			_ = conn.Close()
			t.Mu.Lock()
			if t.pending == session {
				t.pending = nil
			}
			t.Mu.Unlock()
			t.scheduleReconnect(attempt)
			return
		}
		if !t.publishSession(session) {
			_ = conn.Close()
			return
		}

		connectedAt := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[M-DOCS] Read error: %v", err)
				current := t.dropSession(session)
				_ = conn.Close()
				if !current {
					return
				}
				code, timedOut := mailruDisconnectDetails(err)
				// Never log editor URLs, JWTs or a remote error's free-form text.
				log.Printf("[PAPERFLUX_MAILRU] connection_lost uptime=%s close_code=%d timeout=%t engine_pings=%d engine_pongs=%d editor_auth=%t", time.Since(connectedAt).Round(time.Millisecond), code, timedOut, session.enginePings.Load(), session.enginePongs.Load(), session.editorAuthed.Load())

				next := attempt
				if time.Since(connectedAt) > 15*time.Second {
					next = -1
				}
				t.scheduleReconnect(next)
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			t.handleMessage(session, message)
		}
	}()
}

func mailruDisconnectDetails(err error) (int, bool) {
	var closeErr *websocket.CloseError
	var networkErr net.Error
	code := 0
	if errors.As(err, &closeErr) {
		code = closeErr.Code
	}
	timedOut := errors.As(err, &networkErr) && networkErr.Timeout()
	return code, timedOut
}

func (t *MailruDocsTransport) publishSession(session *DocSession) bool {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	if !t.IsRunning() || t.pending != session {
		return false
	}
	t.pending = nil
	t.session = session
	t.SetConnected(true)
	return true
}

// Only the reader that still owns the active connection may change state.
func (t *MailruDocsTransport) dropSession(session *DocSession) bool {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	if t.session != session {
		return false
	}
	t.session = nil
	t.SetConnected(false)
	return true
}

func (t *MailruDocsTransport) writerLoop() {
	t.Mu.RLock()
	queue := t.writeQueue
	t.Mu.RUnlock()
	done := t.Done()

	var pending []byte
	for t.IsRunning() {
		if pending == nil {
			select {
			case <-done:
				return
			case packet := <-queue:
				pending = packet
			}
		}

		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()
		if session == nil || session.Conn == nil {
			// Mid-reconnect: hold the packet and retry rather than drop it.
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}

		payload := base64.StdEncoding.EncodeToString(pending)
		msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)
		if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
			t.writeFailures.Add(1)
			utils.Debugf("[M-DOCS] Write error: %v", err)
			_ = session.Conn.Close() // Wake the reader so it can reconnect.
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue // keep pending; the reconnect will bring up a new conn
		}
		t.RecordSend(len(pending))
		pending = nil
	}
}

func (t *MailruDocsTransport) keepAliveLoop() {
	interval := t.GetConfig().KeepAliveInterval
	if interval <= 0 || interval > 15*time.Second {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for t.IsRunning() {
		select {
		case <-t.Done():
			return
		case <-ticker.C:
		}
		t.Mu.Lock()
		session := t.session
		t.Mu.Unlock()

		if session != nil && session.Conn != nil {
			if err := session.sendEditorKeepAlive(); err != nil {
				utils.Debugf("[M-DOCS] Keep-alive failed: %v", err)
				t.Mu.RLock()
				if t.session == session {
					t.SetConnected(false)
				}
				t.Mu.RUnlock()
				_ = session.Conn.Close()
			}
		}
	}
}

func (s *DocSession) sendEditorKeepAlive() error {
	// Engine.IO heartbeat and cursor traffic do not extend the editor's
	// separate idle lease. Use the editor client's standard session message,
	// without editing or saving document contents. Never send before auth.
	if s.editorAuthed.Load() {
		if err := s.safeWrite(websocket.TextMessage, []byte(`42["message",{"type":"extendSession","idletime":0}]`)); err != nil {
			return err
		}
	}
	return s.safeWrite(websocket.TextMessage, []byte(`42["message",{"type":"cursor","cursor":"18;---KA---"}]`))
}

func (t *MailruDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)
	event := parseMailruEditorEvent(data)
	if session != nil && session.Conn != nil {
		var response string
		switch {
		case event.Type == "authChanges":
			response = `42["message",{"type":"authChangesAck"}]`
		case event.Type == "connectState" && event.WaitAuth:
			// Complete only our own collaborative authentication lock. The
			// server checks ownership; no save, deletion or edit-lock release.
			response = `42["message",{"type":"unLockDocument","unlock":true,"isSave":false,"releaseLocks":false}]`
		}
		if response != "" {
			if err := session.safeWrite(websocket.TextMessage, []byte(response)); err != nil {
				_ = session.Conn.Close()
			} else {
				log.Printf("[PAPERFLUX_MAILRU] editor_control_completed type=%s", event.Type)
			}
			return
		}
	}

	// Socket.IO ping - respond with pong
	if text == "2" {
		if session != nil && session.Conn != nil {
			session.enginePings.Add(1)
			if session.safeWrite(websocket.TextMessage, []byte("3")) == nil {
				session.enginePongs.Add(1)
			}
		}
		return
	}
	if text == "3" {
		return
	}

	if strings.Contains(text, `"type":"auth"`) && strings.Contains(text, `"result":1`) {
		if session != nil {
			session.editorAuthed.Store(true)
		}
		utils.Debugf("[M-DOCS] Auth OK for user %s", session.UserID)
		return
	}
	if !strings.Contains(text, "cursor") && strings.HasPrefix(text, "42[") && len(text) < 65536 {
		var event []json.RawMessage
		if json.Unmarshal(data[2:], &event) == nil && len(event) > 1 {
			var notice struct {
				Type     string `json:"type"`
				Code     int    `json:"code"`
				Interval int    `json:"interval"`
			}
			if json.Unmarshal(event[1], &notice) == nil {
				switch notice.Type {
				case "session", "disconnectReason", "error":
					log.Printf("[PAPERFLUX_MAILRU] editor_event type=%s code=%d interval_ms=%d", notice.Type, notice.Code, notice.Interval)
				}
			}
		}
	}

	if strings.Contains(text, "cursor") {
		for _, base64Str := range transport.EditorPayloads(text) {
			decoded, err := base64.StdEncoding.DecodeString(base64Str)
			if err != nil {
				utils.Debugf("[M-DOCS] Base64 decode error: %v", err)
				continue
			}

			t.RecordReceive(len(decoded))
			t.CallReceive(decoded)
		}
	}
}

type mailruEditorEvent struct {
	Type     string `json:"type"`
	WaitAuth bool   `json:"waitAuth"`
}

func parseMailruEditorEvent(data []byte) mailruEditorEvent {
	// Do not act on strings embedded inside cursor payloads or events on
	// other Socket.IO namespaces. Parse only bounded editor envelopes.
	if len(data) > 256*1024 || !bytes.HasPrefix(data, []byte("42[")) {
		return mailruEditorEvent{}
	}
	var envelope []json.RawMessage
	if json.Unmarshal(data[2:], &envelope) != nil || len(envelope) != 2 {
		return mailruEditorEvent{}
	}
	var name string
	if json.Unmarshal(envelope[0], &name) != nil || name != "message" {
		return mailruEditorEvent{}
	}
	var event mailruEditorEvent
	if json.Unmarshal(envelope[1], &event) != nil {
		return mailruEditorEvent{}
	}
	return event
}

func (t *MailruDocsTransport) extractBase64String(response string) string {
	matches := cursorPayloadRe.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (t *MailruDocsTransport) scheduleReconnect(attempt int) {
	next := attempt + 1
	if !t.IsRunning() || next >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	d := reconnectBackoff(next)
	utils.Debugf("[M-DOCS] reconnecting in %v (attempt %d)", d, next)
	select {
	case <-t.Done():
		return
	case <-time.After(d):
	}
	if !t.IsRunning() {
		return
	}

	t.RecordReconnect()
	t.connectToDoc(next)
}

// reconnectBackoff returns an exponential backoff with jitter, capped at 15s.
func reconnectBackoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	shift := n - 1
	if shift > 5 {
		shift = 5
	}
	d := 500 * time.Millisecond * time.Duration(1<<uint(shift))
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	// add up to +50% jitter
	d += time.Duration(rand.Int63n(int64(d/2) + 1))
	return d
}

// fetchDocInfo POSTs to Mail.ru's public-document editor API and parses the
// response into the fields needed to open the collaborative WebSocket.
func (t *MailruDocsTransport) fetchDocInfo(weblink string) (MailruDocsInfo, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	reqBody := map[string]string{
		"x-email":  "anonym",
		"public":   "/" + weblink,
		"platform": "desktop_web",
	}
	jsonData, _ := json.Marshal(reqBody)

	apiURL := "https://cloud.mail.ru/api/v4/r7/edit"
	utils.Debugf("[M-DOCS] fetchDocInfo POST %s", apiURL)

	req, _ := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", mailruUserAgent)
	req.Header.Set("X-Api-Version", "4")
	req.Header.Set("Referer", fmt.Sprintf("https://cloud.mail.ru/public/%s?weblink=%s", weblink, weblink))

	resp, err := client.Do(req)
	if err != nil {
		return MailruDocsInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MailruDocsInfo{}, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)

	var res map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return MailruDocsInfo{}, fmt.Errorf("failed to parse JSON: %w", err)
	}

	apiBase, _ := res["api"].(string)
	token, _ := res["token"].(string)

	document, ok := res["document"].(map[string]interface{})
	if !ok || document == nil {
		return MailruDocsInfo{}, fmt.Errorf("document object missing")
	}

	docKey, _ := document["key"].(string)
	fileType, _ := document["fileType"].(string)
	docURL, _ := document["url"].(string)
	docTitle, _ := document["title"].(string)
	// document.permissions is an object of booleans (comment/edit/download/…),
	// not a number - sending it as anything else makes the editor server
	// reject the auth message with "access deny".
	permissions, _ := document["permissions"].(map[string]interface{})
	if permissions == nil {
		permissions = make(map[string]interface{})
	}

	editorConfig, ok := res["editorConfig"].(map[string]interface{})
	if !ok || editorConfig == nil {
		return MailruDocsInfo{}, fmt.Errorf("editorConfig object missing")
	}
	callbackURL, _ := editorConfig["callbackUrl"].(string)

	userObj, _ := editorConfig["user"].(map[string]interface{})
	var editorUserID string
	if userObj != nil {
		editorUserID, _ = userObj["id"].(string)
	}

	wsBase := strings.Replace(apiBase, "https://", "wss://", 1)
	wsURL := fmt.Sprintf("%s/doc/%s/c/?EIO=4&transport=websocket", wsBase, docKey)

	return MailruDocsInfo{
		Token:        token,
		DocKey:       docKey,
		WsURL:        wsURL,
		FileType:     fileType,
		DocURL:       docURL,
		DocTitle:     docTitle,
		Permissions:  permissions,
		CallbackURL:  callbackURL,
		EditorUserID: editorUserID,
	}, nil
}

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}
