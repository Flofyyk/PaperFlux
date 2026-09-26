package yandex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	legacy "universal-bypass-tool/transport/yandex"
	"universal-bypass-tool/utils"
)

// ErrCaptchaRequired signals that the transport hit a SmartCaptcha challenge
// (showcaptcha?cc=1) which cannot be solved by the internal PoW solver.
// The caller is expected to obtain fresh cookies out of band (e.g. WebView
// on the client) and hand them over via CookieExchanger.ApplyCookies.
var ErrCaptchaRequired = errors.New("yandex docs: captcha required")

// ErrLoginRequired signals a redirect to the passport login page. The
// document is not public from this IP / account.
var ErrLoginRequired = errors.New("yandex docs: login required")

// Precompiled once. cursorPayloadRe in particular runs on every inbound
// message, so compiling it per call (as before) was pure overhead on the hot
// receive path.
var (
	laneCounter     atomic.Uint32
	cursorPayloadRe = regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)
	clientConfigRe  = regexp.MustCompile(`(?s)<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
)

type YandexDocsInfo struct {
	CookieStr   string
	Token       string
	DocID       string
	CallbackURL string
	UserID      string
	Origin      string
	Host        string
	WsURL       string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

type DocSession struct {
	Info       YandexDocsInfo
	Conn       *websocket.Conn
	WriteQueue chan []byte
	UserID     string
	writeMu    sync.Mutex
}

func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.Conn.WriteMessage(messageType, data)
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url       string
	session   *DocSession
	connectMu sync.Mutex
	laneID    uint32
	queue     chan []byte

	userCounter atomic.Int32
	baseUserID  string

	// cookieJar holds the shared cookie jar for all fetchDocInfo / WebSocket
	// dials. It is preserved across reconnects and can be replaced by
	// ApplyCookies (see CookieExchanger).
	cookieJar *cookiejar.Jar
	jarMu     sync.RWMutex

	errNotifier func(err error, transportName, url, reason string)

	// A single buffered wake survives cookie delivery just before a retry wait.
	cookiesApplied chan struct{}
}

func NewYandexDocsTransport(url string, config transport.TransportConfig) *YandexDocsTransport {
	config.MaxQueueSize = max(1, min(config.MaxQueueSize, 256))
	t := &YandexDocsTransport{
		BaseTransport:  transport.NewBaseTransport(config),
		url:            url,
		cookiesApplied: make(chan struct{}, 1),
		queue:          make(chan []byte, config.MaxQueueSize),
		laneID:         laneCounter.Add(1),
	}
	t.baseUserID = randUserID()
	jar, _ := cookiejar.New(nil)
	t.cookieJar = jar
	return t
}

func (t *YandexDocsTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	utils.SafeGo("yandex.keepAlive", t.keepAliveLoop)
	utils.SafeGo("yandex.writer", t.writerLoop)
	t.connectToDoc(0)

	return nil
}

// Stop also closes the document connection. Otherwise the reader sits in
// ReadMessage until the server's next message and then leaves the socket
// open, keeping a participant attached to the document after the transport
// is gone.
func (t *YandexDocsTransport) Stop() error {
	err := t.BaseTransport.Stop()
	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()
	if session != nil && session.Conn != nil {
		_ = session.Conn.Close()
	}
	return err
}

func (t *YandexDocsTransport) Send(data []byte) error {
	if !t.IsConnected() {
		return fmt.Errorf("transport not connected")
	}

	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()

	if session == nil {
		return fmt.Errorf("no active session")
	}

	select {
	case t.queue <- append([]byte(nil), data...):
		t.RecordSend(len(data))
		return nil
	default:
		return fmt.Errorf("write queue full")
	}
}

func (t *YandexDocsTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}

	utils.Debugf("[YDOCS] connectToDoc attempt ...")

	go func() {
		t.connectMu.Lock()
		defer t.connectMu.Unlock()
		if !t.IsRunning() || t.IsConnected() {
			return
		}
		defer func() {
			if r := recover(); r != nil {
				utils.Debugf("[PANIC] recovered in yandex.connect: %v", r)
			}
		}()
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		userID := randUserID() + fmt.Sprintf("%06d", t.userCounter.Add(1))

		info, err := t.fetchDocInfo(t.url, userID)
		if err != nil {
			if errors.Is(err, ErrCaptchaRequired) || errors.Is(err, ErrLoginRequired) {
				utils.Debugf("[YDOCS] fetchDocInfo needs external help: %v", err)
				reason := "smartcaptcha"
				if errors.Is(err, ErrLoginRequired) {
					reason = "login"
				}
				if t.errNotifier != nil {
					t.errNotifier(err, "yandex", t.url, reason)
				}
				t.scheduleReconnectNoCaptcha(attempt)
				return
			}
			utils.Debugf("[YDOCS] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}

		// Hard TCP dial timeout so a stuck connect/DNS to the balancer host
		// can't hang the whole transport (HandshakeTimeout alone proved
		// insufficient on iOS).
		dialer := websocket.Dialer{
			HandshakeTimeout: 15 * time.Second,
			NetDialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", info.CookieStr)
		headers.Set("Host", info.Host)

		utils.Debugf("[YDOCS] WebSocket dial")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		watchDone := make(chan struct{})
		go func() {
			select {
			case <-t.Done():
				cancel()
			case <-watchDone:
			}
		}()
		conn, err := legacy.ConnectSessionEngineIO(ctx, info.WsURL, headers, &dialer)
		close(watchDone)
		cancel()
		if err != nil {
			utils.Debugf("[YDOCS] Engine.IO handshake failed")
			log.Printf("[PAPERFLUX_YDOCS] lane=%d phase=engine-upgrade failed", t.laneID)
			t.scheduleReconnect(attempt)
			return
		}
		utils.Debugf("[YDOCS] WebSocket connected to %s", info.Host)

		if !t.IsRunning() {
			conn.Close()
			return
		}
		if existingSession != nil {
			existingSession.Conn.Close()
		}

		session := &DocSession{
			Info:       info,
			Conn:       conn,
			WriteQueue: t.queue,
			UserID:     userID,
		}

		t.Mu.Lock()
		t.session = session
		t.SetConnected(false)
		t.Mu.Unlock()

		// Auth - use safeWrite
		auth1 := fmt.Sprintf(`40{"token":"%s"}`, info.Token)
		if err := session.safeWrite(websocket.TextMessage, []byte(auth1)); err != nil {
			conn.Close()
			t.scheduleReconnect(attempt)
			return
		}

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			"user": map[string]interface{}{"id": userID}, "editorType": 0,
			"lastOtherSaveTime": -1, "permissions": info.Permissions,
			"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
			"documentCallbackUrl": info.CallbackURL, "supportAuthChangesAck": true,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authData})
		if err := session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart)))); err != nil {
			conn.Close()
			t.scheduleReconnect(attempt)
			return
		}

		connectedAt := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(25 * time.Second))
		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[YDOCS] Read error: %v", err)
				code := 0
				var closeError *websocket.CloseError
				if errors.As(err, &closeError) {
					code = closeError.Code
				}
				log.Printf("[PAPERFLUX_YDOCS] lane=%d closed code=%d authenticated=%t lifetime=%s", t.laneID, code, t.IsConnected(), time.Since(connectedAt).Round(time.Millisecond))
				t.SetConnected(false)
				conn.Close()
				// If the session was healthy for a while, treat the next
				// connect as fresh (attempt -1 -> next attempt 0) so backoff
				// doesn't keep growing across normal long-lived reconnects.
				next := attempt
				if time.Since(connectedAt) > 15*time.Second {
					next = -1
				}
				t.scheduleReconnect(next)
				return
			}
			if !t.IsConnected() && legacy.EditorAuthenticated(message) {
				t.SetConnected(true)
				log.Printf("[PAPERFLUX_YDOCS] lane=%d editor authenticated", t.laneID)
				utils.Debugf("[YDOCS] editor authorization confirmed")
			}
			t.handleMessage(session, message)
			if t.IsConnected() {
				_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			}
		}
	}()
}

func (t *YandexDocsTransport) writerLoop() {
	// The write queue is created once and preserved across reconnects, so we
	// capture it and block on it instead of polling with a 10ms sleep. The old
	// poll added up to 10ms of latency to every send and woke the CPU 100x/sec
	// while idle.
	queue := t.queue
	if queue == nil {
		return
	}

	var pending []byte
	var pendingAt time.Time
	for t.IsRunning() {
		if pending == nil {
			select {
			case packet, ok := <-queue:
				if !ok {
					return
				}
				pending = packet
				pendingAt = time.Now()
			case <-t.Done():
				return
			}
		}
		if time.Since(pendingAt) > 15*time.Second {
			pending = nil
			continue
		}

		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()
		if session == nil || session.Conn == nil || !t.IsConnected() {
			// Mid-reconnect: hold the packet and retry rather than drop it.
			time.Sleep(15 * time.Millisecond)
			continue
		}

		payload := base64.StdEncoding.EncodeToString(pending)
		msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)
		if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
			utils.Debugf("[YDOCS] Write error: %v", err)
			session.Conn.Close()
			time.Sleep(15 * time.Millisecond)
			continue // keep pending; the reconnect will bring up a new conn
		}
		pending = nil
	}
}

func (t *YandexDocsTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()
	keepAliveMsg := `42["message",{"type":"cursor","cursor":"18;---KA---"}]`

	for t.IsRunning() {
		select {
		case <-ticker.C:
		case <-t.Done():
			return
		}
		t.Mu.Lock()
		session := t.session
		t.Mu.Unlock()

		if session != nil && session.Conn != nil && t.IsConnected() {
			if err := session.safeWrite(websocket.TextMessage, []byte(keepAliveMsg)); err != nil {
				utils.Debugf("[YDOCS] Keep-alive failed: %v", err)
				t.SetConnected(false)
				session.Conn.Close()
			}
		}
	}
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)
	event := parseEditorEvent(data)
	if event.Type == "authChanges" {
		if err := session.safeWrite(websocket.TextMessage, []byte(`42["message",{"type":"authChangesAck"}]`)); err != nil {
			session.Conn.Close()
		}
		return
	}
	if event.Type == "connectState" && event.WaitAuth {
		// Complete our own co-authoring authentication lock, as the editor SDK
		// does after loading. The server checks ownership. No document changes,
		// save, content deletion, or release of editing locks are requested.
		if err := session.safeWrite(websocket.TextMessage, []byte(`42["message",{"type":"unLockDocument","unlock":true,"isSave":false,"releaseLocks":false}]`)); err != nil {
			session.Conn.Close()
		} else {
			log.Printf("[PAPERFLUX_YDOCS] lane=%d collaborative auth lock completed", t.laneID)
		}
		return
	}
	if event.Type == "disconnectReason" || event.Type == "error" {
		// Descriptions can contain private document URLs or tokens. Only a
		// whitelisted event type and numeric code are safe to log.
		log.Printf("[PAPERFLUX_YDOCS] lane=%d editor-event=%s code=%d", t.laneID, event.Type, event.Code)
		return
	}
	if event.Type == "waitAuth" && !t.IsConnected() {
		// Collaborative lock can delay result=1 while cursor relay is already
		// available. Session still requires an authenticated peer envelope on
		// this lane, then a real DNS/TCP probe, before exposing a working VPN.
		t.SetConnected(true)
		log.Printf("[PAPERFLUX_YDOCS] lane=%d awaiting collaborative lock", t.laneID)
		return
	}

	if strings.Contains(text, "---KA---") {
		return
	}

	// Socket.IO ping - respond with pong (use safeWrite)
	if text == "2" {
		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, []byte("3")); err != nil {
				session.Conn.Close()
			}
		}
		return
	}
	if text == "3" {
		return
	}

	if strings.Contains(text, "saveChanges") || strings.Contains(text, "cursor") {
		base64Str := t.extractBase64String(text)
		if base64Str == "" {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			utils.Debugf("[YDOCS] Base64 decode error: %v", err)
			return
		}

		t.RecordReceive(len(decoded))
		t.CallReceive(decoded)
	}
}

type editorEvent struct {
	Type     string `json:"type"`
	WaitAuth bool   `json:"waitAuth"`
	Code     int    `json:"code"`
}

func parseEditorEvent(data []byte) editorEvent {
	// Control messages are small. Do not parse large cursor/data batches a
	// second time, and never interpret event-looking text inside a payload.
	if len(data) > 256*1024 || !strings.HasPrefix(string(data), "42[") {
		return editorEvent{}
	}
	var envelope []json.RawMessage
	if json.Unmarshal(data[2:], &envelope) != nil || len(envelope) != 2 {
		return editorEvent{}
	}
	var name string
	if json.Unmarshal(envelope[0], &name) != nil || name != "message" {
		return editorEvent{}
	}
	var event editorEvent
	if json.Unmarshal(envelope[1], &event) != nil {
		return editorEvent{}
	}
	return event
}

func (t *YandexDocsTransport) extractBase64String(response string) string {
	if strings.Contains(response, "saveChanges") {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(response, marker) + len(marker)
		if left < len(marker) {
			return ""
		}
		right := strings.Index(response[left:], `"`)
		if right == -1 {
			return ""
		}
		return response[left : left+right]
	}

	matches := cursorPayloadRe.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (t *YandexDocsTransport) scheduleReconnect(attempt int) {
	next := attempt + 1
	if !t.IsRunning() || next >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	// Back off before retrying so a server that closes us immediately doesn't
	// turn into a tight connect/close loop (previously reconnect was instant).
	d := reconnectBackoff(next)
	utils.Debugf("[YDOCS] reconnecting in %v (attempt %d)", d, next)
	select {
	case <-time.After(d):
	case <-t.cookiesApplied:
	case <-t.Done():
		return
	}
	if !t.IsRunning() {
		return
	}

	t.RecordReconnect()
	t.connectToDoc(next)
}

// SetErrorNotifier installs a callback for out-of-band errors such as
// ErrCaptchaRequired or ErrLoginRequired. Called once by the manager.
func (t *YandexDocsTransport) SetErrorNotifier(fn func(err error, transportName, url, reason string)) {
	t.errNotifier = fn
}

// scheduleReconnectNoCaptcha is called when fetchDocInfo returned a sentinel
// error (ErrCaptchaRequired / ErrLoginRequired). Retrying with a backoff would
// just hit the same captcha again, so we slow down to a fixed long delay and
// rely on external cookie injection to break the cycle.
func (t *YandexDocsTransport) scheduleReconnectNoCaptcha(attempt int) {
	if !t.IsRunning() {
		return
	}
	const longDelay = 30 * time.Second
	utils.Debugf("[YDOCS] external solver needed; waiting %v before next attempt", longDelay)
	select {
	case <-time.After(longDelay):
	case <-t.cookiesApplied:
	case <-t.Done():
		return
	}
	if !t.IsRunning() {
		return
	}
	t.RecordReconnect()
	t.connectToDoc(attempt + 1)
}

// A healthy connection gets one fast retry; consecutive failures back off
// to avoid accumulating participants or hammering an unavailable editor.
func reconnectBackoff(n int) time.Duration {
	if n == 0 {
		return 350*time.Millisecond + time.Duration(rand.Int63n(int64(250*time.Millisecond)))
	}
	if n < 1 {
		n = 1
	}
	shift := n - 1
	if shift > 4 {
		shift = 4
	}
	d := 1500 * time.Millisecond * time.Duration(1<<uint(shift))
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	// add up to +50% jitter
	d += time.Duration(rand.Int63n(int64(d/2) + 1))
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// ---- CookieExchanger ----

// FetchCookies returns a snapshot of the transport's current cookie jar as
// name -> value. Used by the exit node to answer a SubtypeCookiesRequest.
func (t *YandexDocsTransport) FetchCookies() (map[string]string, error) {
	t.jarMu.RLock()
	jar := t.cookieJar
	t.jarMu.RUnlock()
	if jar == nil {
		return nil, fmt.Errorf("ydocs: cookie jar is nil")
	}
	// cookiejar.Cookies(u) needs a URL; use the document URL because every
	// cookie we care about was set on that host.
	u := mustParseURL(t.url)
	out := make(map[string]string)
	for _, c := range jar.Cookies(u) {
		out[c.Name] = c.Value
	}
	return out, nil
}

// ApplyCookies replaces the transport's cookie jar with the provided values
// and forces the current session to reconnect so the next fetchDocInfo uses
// the new cookies. It is idempotent.
func (t *YandexDocsTransport) ApplyCookies(values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	if len(values) > 128 {
		return fmt.Errorf("too many verification cookies")
	}
	for name, value := range values {
		if len(value) > 8192 || (&http.Cookie{Name: name, Value: value}).Valid() != nil {
			return fmt.Errorf("invalid verification cookie")
		}
	}
	u := mustParseURL(t.url)
	jar, _ := cookiejar.New(nil)
	cookies := siteCookies(u, values)
	jar.SetCookies(u, cookies)

	t.jarMu.Lock()
	t.cookieJar = jar
	t.jarMu.Unlock()

	utils.Debugf("[YDOCS] applied %d cookies, forcing reconnect", len(cookies))

	// Drop the current session so the next connectToDoc re-runs fetchDocInfo
	// with the new jar.
	t.Mu.Lock()
	session := t.session
	t.session = nil
	t.SetConnected(false)
	t.Mu.Unlock()
	if session != nil && session.Conn != nil {
		_ = session.Conn.Close()
	}
	if t.IsRunning() {
		select {
		case t.cookiesApplied <- struct{}{}:
			// The captcha wait reconnects now; a second reconnect here would
			// open a duplicate session to the document.
		default:
			// A wake is already pending; one serialized connector consumes it.
		}
	}
	return nil
}

// ---- fetchDocInfo ----

func (t *YandexDocsTransport) fetchDocInfo(url, userID string) (YandexDocsInfo, error) {
	t.jarMu.RLock()
	jar := t.cookieJar
	t.jarMu.RUnlock()
	if jar == nil {
		var err error
		jar, err = cookiejar.New(nil)
		if err != nil {
			return YandexDocsInfo{}, err
		}
	}

	client := &http.Client{
		Jar: jar,
		// НЕ следуем редиректам автоматически — обрабатываем вручную.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if t.BaseTransport != nil {
		go func() {
			select {
			case <-t.Done():
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	htmlBytes, resp, err := legacy.FetchSessionAuthPage(ctx, url, client)
	if err != nil {
		switch legacy.AuthReason(err) {
		case "smartcaptcha":
			return YandexDocsInfo{}, ErrCaptchaRequired
		case "login":
			return YandexDocsInfo{}, ErrLoginRequired
		}
		return YandexDocsInfo{}, err
	}
	html := string(htmlBytes)
	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	for _, c := range jar.Cookies(resp.Request.URL) {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	matches := clientConfigRe.FindStringSubmatch(html)
	if len(matches) < 2 {
		hint := "no client-config script"
		if strings.Contains(html, "passport") || strings.Contains(strings.ToLower(html), "login") {
			hint = "looks like a login page (doc not public?)"
		}
		return YandexDocsInfo{}, fmt.Errorf("config not found: %s (status %d)", hint, resp.StatusCode)
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("client-config is not valid JSON: %w", err)
	}

	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok || officeAction == nil {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData missing - will reconnect")
	}

	editorConfigRaw, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfigRaw == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config nil - will reconnect")
	}

	balancerURL, ok := officeAction["balancer_url"].(string)
	if !ok || balancerURL == "" {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData.balancer_url missing - will reconnect")
	}
	host := strings.TrimPrefix(balancerURL, "https://")

	document, ok := editorConfigRaw["document"].(map[string]interface{})
	if !ok || document == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.document missing - will reconnect")
	}

	token, ok := editorConfigRaw["token"].(string)
	if !ok || token == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.token missing - will reconnect")
	}

	docKey, ok := document["key"].(string)
	if !ok || docKey == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.document.key missing - will reconnect")
	}

	perms, _ := document["permissions"].(map[string]interface{})
	if perms == nil {
		perms = make(map[string]interface{})
	}
	callback := ""
	if editor, ok := editorConfigRaw["editorConfig"].(map[string]interface{}); ok {
		callback, _ = editor["callbackUrl"].(string)
	}

	return YandexDocsInfo{
		CookieStr:   strings.Join(cookies, "; "),
		Token:       token,
		DocID:       docKey,
		CallbackURL: callback,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, docKey),
		Permissions: perms,
		OpenCmd: map[string]interface{}{
			"c":      "open",
			"id":     docKey,
			"userid": userID,
			"format": document["fileType"],
			"url":    document["url"],
			"title":  document["title"],
			"lcid":   25,
		},
	}, nil
}

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}

// mustParseURL parses a URL and panics on error. Used only where the input is
// a known-valid document URL.
// siteCookies scopes externally supplied cookies to the document's parent
// domain (disk.yandex.ru -> yandex.ru) instead of host-only: the document
// fetch is redirected across Yandex hosts, and an out-of-band solve (e.g.
// SmartCaptcha's spravka) is issued for .yandex.ru, so a host-only copy
// would never reach the host that actually asked for it.
func siteCookies(u *url.URL, values map[string]string) []*http.Cookie {
	domain := ""
	if u != nil {
		if labels := strings.Split(u.Hostname(), "."); len(labels) >= 3 {
			domain = strings.Join(labels[1:], ".")
		}
	}
	cookies := make([]*http.Cookie, 0, len(values))
	for k, v := range values {
		cookies = append(cookies, &http.Cookie{Name: k, Value: v, Path: "/", Domain: domain})
	}
	return cookies
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}
