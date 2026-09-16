package yandex

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	urlpkg "net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
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
	Info         YandexDocsInfo
	Conn         *websocket.Conn
	WriteQueue   chan queuedPacket
	UserID       string
	done         chan struct{}
	retireOnce   sync.Once
	writeMu      sync.Mutex
	diagFrames   atomic.Uint32
	diagSecure   atomic.Uint32
	pingMs       atomic.Int64
	lastPing     atomic.Int64
	lastActivity atomic.Int64
	// Set for an editor-requested rotation. Its subsequent ReadMessage error
	// is expected, so it must not be treated as a second failure.
	expectedClose atomic.Bool
}

// queuedPacket carries its enqueue timestamp so reconnects never replay old
// IP packets after their TCP state has already moved on.
type queuedPacket struct {
	data     []byte
	queuedAt time.Time
}

func (s *DocSession) retire() {
	if s == nil {
		return
	}
	s.retireOnce.Do(func() {
		close(s.done)
		if s.Conn != nil {
			_ = s.Conn.Close()
		}
	})
}

func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.Conn.WriteMessage(messageType, data)
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url          string
	profileID    string
	profileToken string
	exitRole     bool
	secure       *secureChannel
	proofMu      sync.Mutex
	pendingProof map[uint64]pendingProof
	proofSeq     atomic.Uint64
	lastProof    atomic.Int64
	peerReady    atomic.Bool
	session      *DocSession

	userCounter atomic.Int32
	baseUserID  string

	// A document fetch is an expensive, externally visible operation.  Never
	// let multiple error paths turn it into a reconnect storm.
	connecting       atomic.Bool
	reconnectPending atomic.Bool
	generation       atomic.Uint64
	failedAttempts   atomic.Int32
	captchaUntil     atomic.Int64

	// retryQueue owns batches that a writer had already removed from the
	// session queue when its WebSocket write failed.  Keeping this outside a
	// DocSession lets a replacement session continue the same bounded backlog.
	// queuedAt is never reset: a reconnect must not resurrect stale TCP data.
	queueMu       sync.Mutex
	retryQueue    []queuedPacket
	retryQueued   atomic.Uint64
	expiredDrops  atomic.Uint64
	writeFailures atomic.Uint64
	queuedBytes   atomic.Uint64
	queuedPackets atomic.Uint64
	// Android consumes one statistics stream for a tunnel.  A multi-document
	// tunnel therefore disables per-lane reporting and reports its aggregate
	// from MultiTransport instead.
	statsLogging atomic.Bool
}

type pendingProof struct {
	nonce [16]byte
	sent  time.Time
}

var yandexFramePool = sync.Pool{New: func() interface{} { return make([]byte, 0, 4096) }}

const batchMaxPayload = 32 << 10
const batchMinPayload = 16 << 10
const maxLaneQueuePackets = 2048
const batchCoalesceDelay = 500 * time.Microsecond
const maxQueuedPacketAge = 12 * time.Second
const maxPendingProofs = 8

var yandexBatchPool = sync.Pool{New: func() interface{} { return make([]byte, 0, batchMaxPayload) }}
var cursorBase64RE = regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)

// Channel tag isolates this deployment from older/public OpenFlux clients
// sharing the same Yandex document. It is deliberately part of the framed
// payload, before packet lengths, so foreign cursor/batch data is rejected.
var batchMagic = []byte{'P', 'F', 'M', 'B', 1, 0x7a, 0x31, 0xc4, 0x9e, 0x52, 0x18, 0xd0, 0x6b}

var errCaptchaChallenge = errors.New("yandex returned a CAPTCHA challenge")

func NewYandexDocsTransport(url string, config transport.TransportConfig, identity ...string) *YandexDocsTransport {
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
		pendingProof:  make(map[uint64]pendingProof),
	}
	if len(identity) > 0 {
		t.profileID = identity[0]
	}
	if len(identity) > 1 {
		t.profileToken = identity[1]
	}
	if len(identity) > 2 {
		t.exitRole = identity[2] == "exit"
	}
	t.baseUserID = randUserID()
	t.failedAttempts.Store(0)
	t.captchaUntil.Store(0)
	t.statsLogging.Store(true)
	return t
}

// SetStatsLogging controls only the local PAPERFLUX_STATS diagnostic line.
// It never affects transport traffic or counters.
func (t *YandexDocsTransport) SetStatsLogging(enabled bool) { t.statsLogging.Store(enabled) }

func (t *YandexDocsTransport) Start() error {
	t.generation.Add(1)
	var err error
	t.secure, err = newSecureChannel(t.profileID, t.profileToken, t.url, t.exitRole)
	if err != nil {
		return err
	}
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	// Some legacy OnlyOffice balancers close an otherwise healthy Engine.IO
	// session after ~30 seconds unless the editor channel itself sees activity.
	// This marker is ignored by handleMessage and carries no user data.
	go t.keepAliveLoop()
	if t.statsLogging.Load() {
		go t.statsLoop()
	}
	t.connectToDoc(0)

	return nil
}

// Stop explicitly retires the live WebSocket and drops buffered IP packets.
// Closing only BaseTransport used to leave a reader blocked in ReadMessage and
// let a late write from that retired session race a later Start.
func (t *YandexDocsTransport) Stop() error {
	t.generation.Add(1)
	_ = t.BaseTransport.Stop()
	t.reconnectPending.Store(false)
	t.connecting.Store(false)
	t.peerReady.Store(false)
	t.proofMu.Lock()
	clear(t.pendingProof)
	t.proofMu.Unlock()
	t.queueMu.Lock()
	t.retryQueue = nil
	t.queueMu.Unlock()
	t.Mu.Lock()
	session := t.session
	t.session = nil
	t.Mu.Unlock()
	if session != nil {
		session.retire()
		for {
			select {
			case <-session.WriteQueue:
			default:
				return nil
			}
		}
	}
	return nil
}

func (t *YandexDocsTransport) statsLoop() {
	// This is consumed only by the local Android foreground service, not sent
	// through Yandex Docs. Five seconds keeps notification/UI counters fresh;
	// much shorter intervals previously made the child-process pipe noisy.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for t.IsRunning() {
		<-ticker.C
		s := t.Stats()
		ping := int64(0)
		t.Mu.RLock()
		if t.session != nil {
			ping = t.session.pingMs.Load()
		}
		t.Mu.RUnlock()
		log.Printf("[PAPERFLUX_STATS] rx=%d tx=%d ping=%d", s.BytesReceived, s.BytesSent, ping)
	}
}

func (t *YandexDocsTransport) Send(data []byte) error {
	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()

	if session == nil {
		return fmt.Errorf("transport has no session yet")
	}
	// Leave headroom for control frames and give MultiTransport a chance to
	// move new flows to another document lane before this queue is exhausted.
	// Waiting until the channel is completely full caused a burst to block the
	// writer for 250 ms and then produce a synchronized reconnect storm.
	if cap(session.WriteQueue) > 0 && len(session.WriteQueue) >= cap(session.WriteQueue)*3/4 {
		return fmt.Errorf("write queue backpressure")
	}

	// Keep a bounded amount of TUN traffic while an authenticated session is
	// being re-established.  Previously the IsConnected guard above dropped
	// every packet throughout a reconnect, turning one transient WebSocket
	// close into a visible multi-second outage.  writerLoop only drains this
	// queue once the new session has received editor auth, while the deadline
	// below preserves backpressure if the transport is genuinely stalled.
	select {
	case session.WriteQueue <- queuedPacket{data: data, queuedAt: time.Now()}:
		t.queuedPackets.Add(1)
		t.queuedBytes.Add(uint64(len(data)))
		session.lastActivity.Store(time.Now().UnixNano())
		t.RecordSend(len(data))
		return nil
	default:
	}
	// Only allocate a timer when the queue is actually full. The previous
	// implementation allocated one for every packet, even on the fast path.
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case session.WriteQueue <- queuedPacket{data: data, queuedAt: time.Now()}:
		t.queuedPackets.Add(1)
		t.queuedBytes.Add(uint64(len(data)))
		t.RecordSend(len(data))
		return nil
	case <-timer.C:
		return fmt.Errorf("write queue blocked")
	}
}

// takeRetryBatch gives the writer the batch that failed most recently before
// it reads newer work.  It deliberately does not copy packet data; ownership
// remains in the transport until either a write succeeds or the TTL expires.
func (t *YandexDocsTransport) takeRetryBatch() []queuedPacket {
	t.queueMu.Lock()
	defer t.queueMu.Unlock()
	if len(t.retryQueue) == 0 {
		return nil
	}
	batch := t.retryQueue
	t.retryQueue = nil
	return batch
}

func (t *YandexDocsTransport) requeueBatch(batch []queuedPacket) {
	if len(batch) == 0 {
		return
	}
	now := time.Now()
	kept := batch[:0]
	var bytes uint64
	for _, packet := range batch {
		if now.Sub(packet.queuedAt) > maxQueuedPacketAge {
			t.expiredDrops.Add(1)
			t.queuedPackets.Add(^uint64(0))
			if len(packet.data) > 0 {
				t.queuedBytes.Add(^uint64(len(packet.data) - 1))
			}
			continue
		}
		kept = append(kept, packet)
		bytes += uint64(len(packet.data))
	}
	if len(kept) == 0 {
		return
	}
	t.queueMu.Lock()
	// Keep the older retry data before a retry added by a concurrent writer.
	t.retryQueue = append(kept, t.retryQueue...)
	t.queueMu.Unlock()
	t.retryQueued.Add(uint64(len(kept)))
	_ = bytes
}

func (t *YandexDocsTransport) dequeuePacket(packet queuedPacket) {
	t.queuedPackets.Add(^uint64(0))
	if len(packet.data) > 0 {
		t.queuedBytes.Add(^uint64(len(packet.data) - 1))
	}
}

// Stats includes transport-local queue health used by the Android service and
// the server journal.  BaseTransport remains suitable for transports that do
// not buffer application packets.
func (t *YandexDocsTransport) Stats() transport.TransportStats {
	s := t.BaseTransport.Stats()
	s.RetryQueued = t.retryQueued.Load()
	s.ExpiredDrops = t.expiredDrops.Load()
	s.QueuePackets = t.queuedPackets.Load()
	s.QueueBytes = t.queuedBytes.Load()
	s.WriteFailures = t.writeFailures.Load()
	return s
}

func (t *YandexDocsTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}
	// Reader errors, writer errors, and a timed reconnect can otherwise race
	// and create several simultaneous page loads for the same document.
	if !t.connecting.CompareAndSwap(false, true) {
		return
	}
	generation := t.generation.Load()

	utils.Debugf("[YDOCS] connectToDoc attempt ...")

	go func() {
		attemptStarted := time.Now()
		defer t.connecting.Store(false)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PAPERFLUX] Yandex transport panic recovered: %v", r)
				t.SetConnected(false)
				t.scheduleReconnect(attempt)
			}
		}()
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		// Use a fresh editor identity on every connection. Reusing an identity
		// while the server still holds its prior session often triggers an
		// immediate close with no close code.
		suffix := fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
		userID := t.baseUserID + suffix

		info, err := t.fetchDocInfoRetry(userID)
		if err != nil {
			utils.Debugf("[YDOCS] fetchDocInfo failed: %v", err)
			log.Printf("[PAPERFLUX] document bootstrap failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}
		if !t.IsRunning() || t.generation.Load() != generation {
			return
		}
		log.Printf("[PAPERFLUX] Yandex bootstrap ready in %s", time.Since(attemptStarted).Round(time.Millisecond))

		dialer := websocket.Dialer{
			HandshakeTimeout: 15 * time.Second,
			NetDialContext:   (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ReadBufferSize:   512 << 10,
			WriteBufferSize:  512 << 10,
			// Yandex's WebSocket endpoint supports per-message deflate. This
			// reduces JSON/Base64 framing overhead without changing the wire
			// payload or the Engine.IO/Socket.IO protocol.
			EnableCompression: true,
		}
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", info.CookieStr)
		headers.Set("Host", info.Host)

		conn, err := connectEngineIO(info.WsURL, headers, &dialer)
		if err != nil {
			utils.Debugf("[YDOCS] Engine.IO connect failed: %v", err)
			log.Printf("[PAPERFLUX] Engine.IO upgrade failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}
		if !t.IsRunning() || t.generation.Load() != generation {
			_ = conn.Close()
			return
		}
		log.Printf("[PAPERFLUX] Engine.IO upgrade ready in %s", time.Since(attemptStarted).Round(time.Millisecond))

		queueSize := min(t.GetConfig().MaxQueueSize, maxLaneQueuePackets)
		writeQueue := make(chan queuedPacket, queueSize)
		if existingSession != nil {
			writeQueue = existingSession.WriteQueue
		}

		session := &DocSession{
			Info:       info,
			Conn:       conn,
			WriteQueue: writeQueue,
			UserID:     userID,
			done:       make(chan struct{}),
		}

		// Retire the previous reader before publishing the replacement. Without
		// this, a late error from an old socket could mark the new session down.
		t.Mu.Lock()
		if existingSession != nil {
			existingSession.retire()
		}
		t.session = session
		t.Mu.Unlock()

		if existingSession == nil {
			go t.writerLoop()
		}

		// Socket.IO allows the namespace CONNECT and the first editor event to be
		// written back-to-back.  Some Yandex balancers defer the `40` namespace
		// acknowledgement until their next Engine.IO timer tick (about 25 s).
		// Waiting for that acknowledgement here made every fresh VPN connection
		// appear stuck at "authorisation" even though the session was already
		// upgrade-ready.  Send the editor auth immediately; the normal read loop
		// below still validates the real `{"type":"auth","result":1}` reply
		// before exposing the tunnel as connected.
		if err := session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf(`40{"token":"%s"}`, info.Token))); err != nil {
			log.Printf("[PAPERFLUX] namespace open failed: %v", err)
			_ = conn.Close()
			t.SetConnected(false)
			t.scheduleReconnect(attempt)
			return
		}

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			// Keep the field set compatible with the current editor.  In
			// particular, documentCallbackUrl and authChanges ACK support are
			// required when a document is already opened by the exit node: without
			// them the editor returns waitAuth and never promotes the second peer
			// to an authenticated co-author.  Do not restore legacy fabricated
			// session/JWT fields here: those are rejected by current deployments.
			"documentCallbackUrl":   info.CallbackURL,
			"user":                  map[string]interface{}{"id": userID},
			"editorType":            0,
			"lastOtherSaveTime":     -1,
			"permissions":           info.Permissions,
			"openCmd":               info.OpenCmd,
			"coEditingMode":         "fast",
			"jwtOpen":               info.Token,
			"supportAuthChangesAck": true,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authData})
		if err := session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart)))); err != nil {
			log.Printf("[PAPERFLUX] editor authentication write failed: %v", err)
			_ = conn.Close()
			t.SetConnected(false)
			t.scheduleReconnect(attempt)
			return
		}
		authSentAt := time.Now()
		log.Printf("[PAPERFLUX] editor auth sent")

		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				t.Mu.RLock()
				current := t.session == session
				t.Mu.RUnlock()
				if !current {
					return
				}
				if session.expectedClose.Load() {
					log.Printf("[PAPERFLUX] Yandex document session rotated after %s", time.Since(attemptStarted).Round(time.Millisecond))
					return
				}
				// Close the broken socket immediately instead of waiting for the
				// next connection attempt to retire it (upstream #55).
				session.retire()
				utils.Debugf("[YDOCS] Read error: %v", err)
				log.Printf("[PAPERFLUX] Yandex transport lost after %s: %v", time.Since(attemptStarted).Round(time.Millisecond), err)
				t.SetConnected(false)
				t.scheduleReconnect(attempt)
				return
			}
			frameNo := session.diagFrames.Add(1)
			if frameNo <= 12 || (bytes.Contains(message, []byte(`"auth"`)) || bytes.Contains(message, []byte(`authChanges`))) {
				log.Printf("[PAPERFLUX] Yandex frame #%d type=%s bytes=%d", frameNo, yandexFrameLabel(message), len(message))
			}
			if isSuccessfulAuth(message) && !t.IsConnected() {
				t.SetConnected(true)
				// A real editor-auth response means the namespace is live; future
				// reconnects can start from the short retry delay again.
				t.failedAttempts.Store(0)
				t.captchaUntil.Store(0)
				log.Printf("[PAPERFLUX] YANDEX_AUTH_OK (reply in %s; total %s)", time.Since(authSentAt).Round(time.Millisecond), time.Since(attemptStarted).Round(time.Millisecond))
				// Start PFS2 immediately. The former 10-second keepalive tick made
				// first authentication unnecessarily slow, and could compound over
				// a reconnect when both endpoints were waiting for their next tick.
				t.startSecureSession(session, true)
			}
			t.handleMessage(session, message)
			session.lastActivity.Store(time.Now().UnixNano())
		}
	}()
}

func (t *YandexDocsTransport) fetchDocInfoRetry(userID string) (YandexDocsInfo, error) {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		info, err := t.fetchDocInfo(t.url, userID)
		if err == nil {
			return info, nil
		}
		last = err
		if errors.Is(err, errCaptchaChallenge) || !isTransientBootstrapError(err) {
			break
		}
		log.Printf("[PAPERFLUX] bootstrap retry %d/3: %v", attempt, err)
		time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
	}
	return YandexDocsInfo{}, last
}

func isTransientBootstrapError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "tls handshake timeout") || strings.Contains(text, "connection reset") || strings.Contains(text, "broken pipe")
}

func yandexFrameLabel(message []byte) string {
	if len(message) == 0 {
		return "empty"
	}
	text := string(message)
	if strings.HasPrefix(text, "42") {
		var event []json.RawMessage
		if err := json.Unmarshal(message[2:], &event); err == nil && len(event) > 0 {
			var name string
			_ = json.Unmarshal(event[0], &name)
			if len(event) > 1 {
				var payload map[string]interface{}
				if json.Unmarshal(event[1], &payload) == nil {
					label := "42:" + name
					if kind, ok := payload["type"].(string); ok && kind != "" {
						label += "/" + kind
					}
					if result, ok := payload["result"]; ok {
						label += "/result=" + fmt.Sprint(result)
					}
					return label
				}
			}
			return "42:" + name
		}
	}
	if len(message) <= 8 {
		return text
	}
	return text[:8]
}

func (t *YandexDocsTransport) keepAliveLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	const keepAlive = `42["message",{"type":"cursor","cursor":"18;---KA---"}]`
	for t.IsRunning() {
		<-ticker.C
		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()
		// Keep the editor channel alive as soon as a WebSocket exists, not only
		// after editor auth.  Some legacy balancers delay the auth reply until
		// they receive another client frame; waiting for IsConnected here created
		// an avoidable 25-30 second quiet period during bootstrap/reconnect.
		if session == nil || session.Conn == nil {
			continue
		}
		if t.IsConnected() {
			// PFS2 is started immediately on editor auth. The periodic worker only
			// repairs a missed handshake and sends a lightweight authenticated
			// liveness challenge; it no longer gates initial connection speed.
			t.startSecureSession(session, false)
			if t.secure.ready() {
				t.sendProof(session)
			}
		}
		if t.peerReady.Load() && time.Since(time.Unix(0, t.lastProof.Load())) > 20*time.Second {
			t.peerReady.Store(false)
			log.Printf("[PAPERFLUX] PEER_LOST: no authenticated response for 20s")
		}
		// Empty editor cursor frames are only needed when the channel has been
		// idle for a while. Sending them every five seconds added noise and was
		// observed to trigger resets on stricter Yandex balancers.
		idle := time.Since(time.Unix(0, session.lastActivity.Load()))
		if idle < 20*time.Second {
			continue
		}
		if err := session.safeWrite(websocket.TextMessage, []byte(keepAlive)); err != nil {
			if !t.isCurrentSession(session) {
				continue
			}
			log.Printf("[PAPERFLUX] editor keepalive failed: %v", err)
			t.SetConnected(false)
			_ = session.Conn.Close()
			t.scheduleReconnect(0)
		}
	}
}

// isCurrentSession prevents a late reader/writer from an already retired
// WebSocket from changing the state of the replacement session.
func (t *YandexDocsTransport) isCurrentSession(session *DocSession) bool {
	t.Mu.RLock()
	defer t.Mu.RUnlock()
	return t.session == session
}

// startSecureSession sends the PFS2 hello as soon as editor auth completes.
// A forced hello is used at the beginning of every new WebSocket session so a
// remote restart cannot leave either side relying on old key state.
func (t *YandexDocsTransport) startSecureSession(session *DocSession, force bool) {
	if session == nil || !t.IsConnected() || !t.isCurrentSession(session) {
		return
	}
	if force || !t.secure.ready() {
		if err := t.writeSecureFrame(session, t.secure.hello()); err != nil && t.isCurrentSession(session) {
			log.Printf("[PAPERFLUX] PFS2 hello failed: %v", err)
		}
	}
	if t.secure.ready() {
		t.sendProof(session)
	}
}

// sendProof keeps a small set of outstanding challenges. A delayed valid
// response is matched by ID instead of being discarded because a newer probe
// replaced the one global nonce.
func (t *YandexDocsTransport) sendProof(session *DocSession) {
	if session == nil || !t.isCurrentSession(session) || !t.secure.ready() {
		return
	}
	var nonce [16]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return
	}
	id := t.proofSeq.Add(1)
	now := time.Now()
	t.proofMu.Lock()
	for pendingID, proof := range t.pendingProof {
		if now.Sub(proof.sent) > 30*time.Second || len(t.pendingProof) >= maxPendingProofs {
			delete(t.pendingProof, pendingID)
		}
	}
	t.pendingProof[id] = pendingProof{nonce: nonce, sent: now}
	t.proofMu.Unlock()

	request := make([]byte, 1+8+len(nonce))
	request[0] = 1
	binary.BigEndian.PutUint64(request[1:9], id)
	copy(request[9:], nonce[:])
	sealed, err := t.secure.seal(request)
	if err != nil {
		return
	}
	if err := t.writeSecureFrame(session, sealed); err != nil && t.isCurrentSession(session) {
		log.Printf("[PAPERFLUX] PFS2 proof failed: %v", err)
	}
}

func isSuccessfulAuth(message []byte) bool {
	text := string(message)
	if strings.HasPrefix(text, "42") {
		var event []json.RawMessage
		if json.Unmarshal(message[2:], &event) == nil && len(event) > 1 {
			var payload interface{}
			if json.Unmarshal(event[1], &payload) == nil && containsSuccessfulAuth(payload) {
				return true
			}
		}
	}
	// Keep compatibility with older servers that return a compact JSON shape
	// the decoder above cannot classify.
	return strings.Contains(text, `"type":"auth"`) &&
		(strings.Contains(text, `"result":1`) || strings.Contains(text, `"result":true`))
}

// containsSuccessfulAuth also handles the nested auth result used by newer
// OnlyOffice/Yandex editor builds (the auth object is not always the event's
// top-level payload).
func containsSuccessfulAuth(value interface{}) bool {
	switch item := value.(type) {
	case map[string]interface{}:
		if kind, ok := item["type"].(string); ok && kind == "auth" {
			switch result := item["result"].(type) {
			case float64:
				if result == 1 {
					return true
				}
			case bool:
				if result {
					return true
				}
			case string:
				if result == "1" || strings.EqualFold(result, "true") {
					return true
				}
			}
		}
		for _, child := range item {
			if containsSuccessfulAuth(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range item {
			if containsSuccessfulAuth(child) {
				return true
			}
		}
	}
	return false
}

func (t *YandexDocsTransport) writerLoop() {
	// A periodic wake-up lets the loop observe a replaced session after a
	// reconnect, while packet delivery itself remains immediate.  This avoids
	// polling every millisecond while the VPN is idle.
	refresh := time.NewTicker(250 * time.Millisecond)
	defer refresh.Stop()
	var pending queuedPacket
	hasPending := false
	for t.IsRunning() {
		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()

		if session == nil || session.Conn == nil || !t.IsConnected() || !t.secure.ready() {
			time.Sleep(25 * time.Millisecond)
			continue
		}

		// A failed frame is retried before newer work.  It remains a logical
		// batch, so a short reconnect cannot reorder its constituent packets.
		items := t.takeRetryBatch()
		retrying := len(items) != 0
		if len(items) == 0 {
			var packet queuedPacket
			if hasPending {
				packet, hasPending = pending, false
			} else {
				select {
				case packet = <-session.WriteQueue:
				case <-refresh.C:
					continue
				}
			}
			items = append(items, packet)
		}
		if !t.isCurrentSession(session) {
			t.requeueBatch(items)
			continue
		}

		// Drop expired data before encoding it.  The counter is decremented only
		// when an item leaves the transport permanently; a retry stays counted.
		live := items[:0]
		for _, item := range items {
			if time.Since(item.queuedAt) > maxQueuedPacketAge || len(item.data) > 0xffff {
				t.expiredDrops.Add(1)
				t.dequeuePacket(item)
				continue
			}
			live = append(live, item)
		}
		items = live
		if len(items) == 0 {
			continue
		}

		// Only newly dequeued data is coalesced below. Retried batches are kept
		// ahead of newer packets so a reconnect cannot reorder the queue.
		{
			// Coalesce packets arriving in the same scheduler window. The
			// length-prefixed binary payload is opaque to Yandex and is decoded
			// symmetrically by handleMessage on the exit node.
			payload := yandexBatchPool.Get().([]byte)
			payload = payload[:0]
			payload = append(payload, batchMagic...)
			payloadLimit := t.batchPayloadLimit(session)
			appendPacket := func(item queuedPacket) bool {
				p := item.data
				if len(p) > 0xffff {
					return false
				}
				// Never drop the first packet solely because it is larger than the
				// coalescing target; the target is a batching hint, not a frame cap.
				if len(payload) > len(batchMagic) && len(payload)+2+len(p) > payloadLimit {
					return false
				}
				var n [2]byte
				binary.BigEndian.PutUint16(n[:], uint16(len(p)))
				payload = append(payload, n[:]...)
				payload = append(payload, p...)
				return true
			}
			encodedItems := make([]queuedPacket, 0, len(items)+8)
			for index, item := range items {
				if appendPacket(item) {
					encodedItems = append(encodedItems, item)
				} else {
					if retrying {
						t.requeueBatch(items[index:])
					} else {
						pending, hasPending = item, true
					}
					break
				}
			}
			if len(encodedItems) == 0 {
				t.requeueBatch(items)
				yandexBatchPool.Put(payload[:0])
				continue
			}
			// One coalescing deadline starts with the first packet. The old
			// nested select created a fresh timer after every queue gap, so a
			// burst could be delayed by many 0.5 ms windows in succession.
			if !retrying {
				batchTimer := time.NewTimer(batchCoalesceDelay)
				batchTimerActive := true
			batchLoop:
				for len(payload) < payloadLimit {
					select {
					case next := <-session.WriteQueue:
						if time.Since(next.queuedAt) > maxQueuedPacketAge || len(next.data) > 0xffff {
							t.expiredDrops.Add(1)
							t.dequeuePacket(next)
							continue
						}
						if !appendPacket(next) {
							pending, hasPending = next, true
							break batchLoop
						}
						encodedItems = append(encodedItems, next)
					case <-batchTimer.C:
						batchTimerActive = false
						break batchLoop
					}
				}
				if batchTimerActive && !batchTimer.Stop() {
					select {
					case <-batchTimer.C:
					default:
					}
				}
			}
			// Build the JSON frame directly into a pooled buffer. This avoids the
			// fmt.Sprintf + intermediate string allocations on every TUN packet,
			// while retaining the compatible Engine.IO/Socket.IO wire format.
			frame := yandexFramePool.Get().([]byte)
			frame = frame[:0]
			frame = append(frame, `42["message",{"type":"cursor","cursor":"18;`...)
			wirePayload, sealErr := t.secure.seal(payload)
			if sealErr != nil {
				t.requeueBatch(encodedItems)
				yandexBatchPool.Put(payload[:0])
				yandexFramePool.Put(frame[:0])
				continue
			}
			encodedLen := base64.StdEncoding.EncodedLen(len(wirePayload))
			if cap(frame)-len(frame) < encodedLen+4 {
				grown := make([]byte, len(frame), len(frame)+encodedLen+64)
				copy(grown, frame)
				frame = grown
			}
			start := len(frame)
			frame = frame[:start+encodedLen]
			base64.StdEncoding.Encode(frame[start:], wirePayload)
			frame = append(frame, `"}]`...)
			if err := session.safeWrite(websocket.TextMessage, frame); err != nil {
				t.writeFailures.Add(1)
				t.requeueBatch(encodedItems)
				if !t.isCurrentSession(session) {
					if cap(frame) <= 64<<10 {
						yandexFramePool.Put(frame[:0])
					}
					if cap(payload) <= batchMaxPayload {
						yandexBatchPool.Put(payload[:0])
					}
					continue
				}
				utils.Debugf("[YDOCS] Write error: %v", err)
				log.Printf("[PAPERFLUX] WebSocket write failed: %v", err)
				t.SetConnected(false)
				_ = session.Conn.Close()
				t.scheduleReconnect(0)
				time.Sleep(25 * time.Millisecond)
			} else {
				for _, item := range encodedItems {
					t.dequeuePacket(item)
				}
			}
			if cap(frame) <= 64<<10 {
				yandexFramePool.Put(frame[:0])
			}
			if cap(payload) <= batchMaxPayload {
				yandexBatchPool.Put(payload[:0])
			}
		}
	}
}

// QueueLoad is used by MultiTransport to avoid assigning new flows to a lane
// that is already under pressure. Existing flows keep their lane for ordering.
func (t *YandexDocsTransport) QueueLoad() float64 {
	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()
	if session == nil || cap(session.WriteQueue) == 0 {
		return 0
	}
	return float64(len(session.WriteQueue)) / float64(cap(session.WriteQueue))
}

func (t *YandexDocsTransport) batchPayloadLimit(session *DocSession) int {
	if session == nil || cap(session.WriteQueue) == 0 {
		return batchMaxPayload
	}
	load := float64(len(session.WriteQueue)) / float64(cap(session.WriteQueue))
	switch {
	case load >= 0.75:
		return batchMinPayload
	case load >= 0.50:
		return (batchMaxPayload + batchMinPayload) / 2
	default:
		return batchMaxPayload
	}
}

type engineOpen struct {
	SID string `json:"sid"`
}

// connectEngineIO follows the Engine.IO v4 upgrade sequence used by strict
// OnlyOffice balancers: polling obtains a sid, WebSocket upgrades that sid,
// then 2probe/3probe/5 completes before Socket.IO CONNECT is sent.
func connectEngineIO(wsURL string, headers http.Header, dialer *websocket.Dialer) (*websocket.Conn, error) {
	started := time.Now()
	pollURL, err := enginePollingURL(wsURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, err
	}
	for key, values := range headers {
		if strings.EqualFold(key, "Host") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("engine polling: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine polling status: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	start := strings.IndexByte(string(body), '{')
	if start < 0 {
		return nil, fmt.Errorf("engine polling: open packet missing")
	}
	var open engineOpen
	if err := json.Unmarshal(body[start:], &open); err != nil || open.SID == "" {
		return nil, fmt.Errorf("engine polling: invalid sid")
	}
	log.Printf("[PAPERFLUX] Engine.IO polling sid received in %s", time.Since(started).Round(time.Millisecond))
	ws, err := urlpkg.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	q := ws.Query()
	q.Set("transport", "websocket")
	q.Set("sid", open.SID)
	ws.RawQuery = q.Encode()
	conn, _, err := dialer.Dial(ws.String(), headers)
	if err != nil {
		return nil, fmt.Errorf("engine websocket: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("2probe")); err != nil {
		_ = conn.Close()
		return nil, err
	}
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("engine probe: %w", err)
		}
		if string(message) == "3probe" {
			break
		}
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("5")); err != nil {
		_ = conn.Close()
		return nil, err
	}
	log.Printf("[PAPERFLUX] Engine.IO probe complete in %s", time.Since(started).Round(time.Millisecond))
	// The `5` packet is handled asynchronously by a number of the
	// OnlyOffice/Engine.IO balancers.  If Socket.IO CONNECT is written in the
	// very same scheduler slice, it can be queued on their retiring polling
	// transport and not be consumed until the first server ping (~25 seconds).
	// A tiny settling interval makes the upgrade deterministic without adding a
	// user-visible delay.
	time.Sleep(200 * time.Millisecond)
	_ = conn.SetReadDeadline(time.Time{})
	return conn, nil
}

func enginePollingURL(wsURL string) (string, error) {
	u, err := urlpkg.Parse(wsURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	default:
		return "", fmt.Errorf("unsupported Engine.IO scheme: %s", u.Scheme)
	}
	q := u.Query()
	q.Set("transport", "polling")
	q.Del("sid")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)
	if reason, ok := disconnectReasonSummary(data); ok {
		// Yandex may send disconnectReason (most commonly 4007/drop) before
		// closing the WebSocket.  Do not leave the old session around waiting
		// for a read timeout: that keeps the VPN looking connected and lets
		// queued writes target a socket which the editor has already retired.
		log.Printf("[PAPERFLUX] Yandex requested session close: %s", reason)
		t.SetConnected(false)
		t.peerReady.Store(false)
		if session != nil && t.isCurrentSession(session) {
			session.expectedClose.Store(true)
			session.retire()
			t.scheduleRotationReconnect()
		}
		return
	}
	if strings.Contains(text, `"type":"waitAuth"`) && !t.IsConnected() {
		// OnlyOffice emits waitAuth when a document is already being opened by
		// the peer.  The WebSocket is live and it continues to relay cursor
		// events, but a result=1 message is deferred until the collaborative lock
		// settles.  Treat it as a transport-ready intermediate state; the Android
		// service still exposes the VPN only after the separate encrypted peer and
		// DNS/TCP checks succeed.
		t.SetConnected(true)
		// waitAuth is already a live editor session. Do not let a later normal
		// 4007/drop inherit a backoff accumulated before this connection.
		t.failedAttempts.Store(0)
		log.Printf("[PAPERFLUX] YANDEX_WAIT_AUTH: editor session is live; awaiting collaborative lock")
		t.startSecureSession(session, true)
		return
	}
	if strings.Contains(text, `"type":"error"`) {
		// An editor-side rejection used to look like an ordinary frame in the
		// diagnostic log, leaving a client stuck at authentication for 75s.
		// Log only the small, non-secret reason fields; never expose refresh
		// tokens, document links, cookies, or the complete editor payload.
		log.Printf("[PAPERFLUX] Yandex editor rejected auth: %s", editorErrorSummary(data))
	}
	if strings.Contains(text, `"type":"paperfluxIdentity"`) {
		log.Printf("[PAPERFLUX] peer profile identity received")
		return
	}
	if strings.Contains(text, "---KA---") {
		return
	}

	// Socket.IO ping - respond with pong (use safeWrite)
	if text == "2" {
		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, []byte("3")); err != nil {
				log.Printf("[PAPERFLUX] Engine.IO pong write failed: %v", err)
				t.SetConnected(false)
				t.scheduleReconnect(0)
			} else {
				log.Printf("[PAPERFLUX] Engine.IO ping → pong")
			}
		}
		return
	}
	if text == "3" {
		return
	}
	// During document authentication the editor may send a batch of changes
	// under the authChanges event. The browser client acknowledges this even
	// before applying the batch; omitting the ack makes the OnlyOffice session
	// expire on strict balancers after roughly one minute.
	if strings.Contains(text, `"type":"authChanges"`) {
		ack := `42["message",{"type":"authChangesAck"}]`
		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, []byte(ack)); err != nil {
				log.Printf("[PAPERFLUX] authChangesAck write failed: %v", err)
			}
		}
		return
	}

	if strings.Contains(text, "saveChanges") || strings.Contains(text, "cursor") {
		base64Str := t.extractBase64String(text)
		if base64Str == "" {
			if session != nil && session.diagSecure.Add(1) <= 4 {
				log.Printf("[PAPERFLUX] secure frame ignored: editor event contained no supported payload")
			}
			return
		}
		if len(base64Str) > base64.StdEncoding.EncodedLen(maxSecureFrame+secureHeader+16) {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			utils.Debugf("[YDOCS] Base64 decode error: %v", err)
			return
		}
		if len(decoded) >= 5 && bytes.Equal(decoded[:4], secureMagic) && (decoded[4] == 1 || decoded[4] == 2) {
			if session != nil && session.diagSecure.Add(1) <= 8 {
				log.Printf("[PAPERFLUX] PFS2 handshake received kind=%d bytes=%d", decoded[4], len(decoded))
			}
			if ack, e := t.secure.receiveHandshake(decoded); e == nil && ack != nil {
				if session != nil && session.diagSecure.Add(1) <= 8 {
					log.Printf("[PAPERFLUX] PFS2 handshake accepted; sending acknowledgement")
				}
				_ = t.writeSecureFrame(session, ack)
			} else if e != nil && session != nil && session.diagSecure.Add(1) <= 8 {
				// The event body is intentionally not logged: it can contain editor
				// metadata.  Kind and byte length are sufficient to diagnose protocol
				// compatibility without exposing document content or credentials.
				log.Printf("[PAPERFLUX] PFS2 handshake rejected kind=%d bytes=%d", decoded[4], len(decoded))
			}
			// If this was the peer ACK, the channel is now ready. Send the
			// authenticated liveness challenge in the same turn instead of
			// waiting for the periodic keepalive.
			t.startSecureSession(session, false)
			return
		}
		decoded, err = t.secure.open(decoded)
		if err != nil {
			return
		}
		if len(decoded) == 17 && decoded[0] == 1 {
			// Compatibility with a client still being upgraded. New endpoints use
			// the ID-bearing 25-byte format below, but accepting the legacy probe
			// keeps a server-first rollout from interrupting an active session.
			decoded[0] = 2
			if sealed, e := t.secure.seal(decoded); e == nil {
				_ = t.writeSecureFrame(session, sealed)
			}
			return
		}
		if len(decoded) == 25 && decoded[0] == 1 {
			decoded[0] = 2
			if sealed, e := t.secure.seal(decoded); e == nil {
				_ = t.writeSecureFrame(session, sealed)
			}
			return
		}
		if len(decoded) == 25 && decoded[0] == 2 {
			id := binary.BigEndian.Uint64(decoded[1:9])
			t.proofMu.Lock()
			proof, valid := t.pendingProof[id]
			if valid && !bytes.Equal(decoded[9:], proof.nonce[:]) {
				valid = false
			}
			if valid {
				delete(t.pendingProof, id)
			}
			rtt := time.Since(proof.sent).Milliseconds()
			t.proofMu.Unlock()
			if valid {
				t.lastProof.Store(time.Now().UnixNano())
				if session != nil {
					session.pingMs.Store(rtt)
				}
				if !t.peerReady.Swap(true) {
					log.Printf("[PAPERFLUX] PEER_READY: encrypted exit channel confirmed")
				}
			}
			return
		}

		// Only our versioned batch format is tunnel data.  OnlyOffice cursor
		// events may contain unrelated base64 text; forwarding a decoded cursor
		// as a raw IP packet fabricated random SYNs and saturated the exit node.
		// Both peers emit PFMB/1, so reject any legacy/unframed payload strictly.
		if !unpackBatch(decoded, func(packet []byte) {
			t.RecordReceive(len(packet))
			t.CallReceive(packet)
		}) {
			return
		}
	}
}

// disconnectReasonSummary extracts only the small diagnostic fields from an
// editor disconnect frame.  The full frame can contain document metadata and
// must never be copied to logs.
func disconnectReasonSummary(message []byte) (string, bool) {
	if !bytes.HasPrefix(message, []byte("42")) {
		return "", false
	}
	var event []json.RawMessage
	if json.Unmarshal(message[2:], &event) != nil || len(event) < 2 {
		return "", false
	}
	var eventName string
	if json.Unmarshal(event[0], &eventName) != nil || eventName != "message" {
		return "", false
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(event[1], &payload) != nil {
		return "", false
	}
	var eventType string
	if raw, ok := payload["type"]; !ok || json.Unmarshal(raw, &eventType) != nil || eventType != "disconnectReason" {
		return "", false
	}
	var code interface{}
	if raw, ok := payload["code"]; ok {
		var numeric int
		if json.Unmarshal(raw, &numeric) == nil {
			code = numeric
		} else {
			var text string
			if json.Unmarshal(raw, &text) == nil {
				code = text
			}
		}
	}
	var description string
	for _, key := range []string{"description", "message"} {
		if raw, ok := payload[key]; ok && json.Unmarshal(raw, &description) == nil && description != "" {
			break
		}
	}
	if code != nil && description != "" {
		return fmt.Sprintf("code=%v description=%q", code, description), true
	}
	if code != nil {
		return fmt.Sprintf("code=%v", code), true
	}
	return "disconnectReason", true
}

func editorErrorSummary(message []byte) string {
	if !bytes.HasPrefix(message, []byte("42")) {
		return "unrecognised error frame"
	}
	var event []json.RawMessage
	if err := json.Unmarshal(message[2:], &event); err != nil || len(event) < 2 {
		return "malformed error frame"
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(event[1], &payload); err != nil {
		return "error payload unavailable"
	}
	parts := make([]string, 0, 3)
	for _, key := range []string{"code", "message", "error", "description"} {
		value, ok := payload[key]
		if !ok || len(parts) == 3 {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) == nil {
			parts = append(parts, key+"="+strconv.Quote(text))
			continue
		}
		var number json.Number
		if json.Unmarshal(value, &number) == nil {
			parts = append(parts, key+"="+number.String())
		}
	}
	if len(parts) == 0 {
		return "no public reason fields"
	}
	return strings.Join(parts, " ")
}

func (t *YandexDocsTransport) writeSecureFrame(session *DocSession, payload []byte) error {
	if session == nil || session.Conn == nil {
		return errSecure
	}
	if len(payload) >= 5 && bytes.Equal(payload[:4], secureMagic) && (payload[4] == 1 || payload[4] == 2) && session.diagSecure.Add(1) <= 8 {
		log.Printf("[PAPERFLUX] PFS2 handshake sent kind=%d bytes=%d", payload[4], len(payload))
	}
	frame := []byte(`42["message",{"type":"cursor","cursor":"18;` + base64.StdEncoding.EncodeToString(payload) + `"}]`)
	return session.safeWrite(websocket.TextMessage, frame)
}

// unpackBatch validates the complete length-prefixed payload before emitting
// packets, so a truncated/corrupt frame cannot produce partial traffic.
func unpackBatch(data []byte, emit func([]byte)) bool {
	if len(data) < len(batchMagic) || !bytes.Equal(data[:len(batchMagic)], batchMagic) {
		return false
	}
	pos, count := len(batchMagic), 0
	for pos < len(data) {
		if pos+2 > len(data) {
			return false
		}
		n := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if n == 0 || pos+n > len(data) {
			return false
		}
		count++
		pos += n
	}
	if count == 0 {
		return false
	}
	pos = len(batchMagic)
	for pos < len(data) {
		n := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		emit(data[pos : pos+n])
		pos += n
	}
	return true
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

	matches := cursorBase64RE.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (t *YandexDocsTransport) scheduleReconnect(attempt int) {
	if !t.IsRunning() || attempt >= t.GetConfig().MaxReconnectAttempts {
		return
	}
	if !t.reconnectPending.CompareAndSwap(false, true) {
		return
	}
	generation := t.generation.Load()

	t.RecordReconnect()
	_ = attempt // Attempts are tracked centrally so concurrent failures coalesce.
	failed := t.failedAttempts.Add(1)
	base := t.GetConfig().ReconnectDelay
	if base < 1500*time.Millisecond {
		base = 1500 * time.Millisecond
	}
	// Respect upstream #55's minimum retry interval to reduce document-room
	// participant churn. Preserve our longer cap and CAPTCHA cooldown.
	// Exponential delay is capped at two minutes. A small positive jitter
	// keeps client and exit-node retries from becoming synchronized.
	shift := min(int(failed-1), 6)
	delay := base * time.Duration(1<<shift)
	if delay > 2*time.Minute {
		delay = 2 * time.Minute
	}
	if delay > 0 {
		delay += time.Duration(rand.Int63n(int64(delay/4) + 1))
	}
	if until := time.Unix(0, t.captchaUntil.Load()); until.After(time.Now()) {
		delay = time.Until(until)
	}
	time.AfterFunc(delay, func() {
		t.reconnectPending.Store(false)
		if !t.IsRunning() || t.generation.Load() != generation {
			return
		}
		t.connectToDoc(0)
	})
}

// scheduleRotationReconnect is reserved for the editor's explicit 4007/drop
// rotation.  This is not a failed dial: the old participant is being retired
// by Yandex, and retrying with a fresh user ID after a short settling window
// avoids both a long outage and an immediate ghost-participant collision.
func (t *YandexDocsTransport) scheduleRotationReconnect() {
	if !t.IsRunning() || !t.reconnectPending.CompareAndSwap(false, true) {
		return
	}
	generation := t.generation.Load()
	t.failedAttempts.Store(0)
	delay := 1500*time.Millisecond + time.Duration(rand.Int63n(int64(500*time.Millisecond)))
	time.AfterFunc(delay, func() {
		t.reconnectPending.Store(false)
		if !t.IsRunning() || t.generation.Load() != generation {
			return
		}
		t.connectToDoc(0)
	})
}

func (t *YandexDocsTransport) fetchDocInfo(url, userID string) (YandexDocsInfo, error) {
	captchaRedirect := false
	transportHTTP := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.Contains(req.URL.Path, "showcaptcha") {
				captchaRedirect = true
				return http.ErrUseLastResponse
			}
			return nil
		},
		Timeout:   35 * time.Second,
		Transport: transportHTTP,
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return YandexDocsInfo{}, fmt.Errorf("cookie jar: %w", err)
	}
	client.Jar = jar

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	defer resp.Body.Close()
	if captchaRedirect || resp.Header.Get("X-Yandex-Captcha") != "" || strings.Contains(resp.Request.URL.Path, "showcaptcha") {
		// This is not a transport failure.  Leave the IP alone for a while rather
		// than turning the challenge into hundreds of repeated requests.
		t.captchaUntil.Store(time.Now().Add(10 * time.Minute).UnixNano())
		return YandexDocsInfo{}, errCaptchaChallenge
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return YandexDocsInfo{}, fmt.Errorf("document request returned HTTP %d", resp.StatusCode)
	}

	htmlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	html := string(htmlBytes)

	// Keep the complete cookie session across redirects.  OnlyOffice may set
	// the editor/balancer cookies before the final document response; using
	// resp.Cookies() alone silently discarded those values.
	cookieValues := make(map[string]string)
	for _, c := range jar.Cookies(resp.Request.URL) {
		cookieValues[c.Name] = c.Value
	}
	for _, c := range resp.Cookies() {
		cookieValues[c.Name] = c.Value
	}
	var cookies []string
	for name, value := range cookieValues {
		cookies = append(cookies, fmt.Sprintf("%s=%s", name, value))
	}

	re := regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) < 2 {
		return YandexDocsInfo{}, fmt.Errorf("config not found")
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("invalid client config: %w", err)
	}
	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok || officeAction == nil {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData missing")
	}

	editorConfigRaw, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfigRaw == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config nil - will reconnect")
	}

	balancerURL, ok := officeAction["balancer_url"].(string)
	if !ok || balancerURL == "" {
		return YandexDocsInfo{}, fmt.Errorf("balancer_url missing")
	}
	host := strings.TrimPrefix(balancerURL, "https://")
	document, ok := editorConfigRaw["document"].(map[string]interface{})
	if !ok || document == nil {
		return YandexDocsInfo{}, fmt.Errorf("document config missing")
	}
	token, ok := editorConfigRaw["token"].(string)
	if !ok || token == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor token missing")
	}
	docID, ok := document["key"].(string)
	if !ok || docID == "" {
		return YandexDocsInfo{}, fmt.Errorf("document key missing")
	}

	perms, _ := document["permissions"].(map[string]interface{})
	if perms == nil {
		perms = make(map[string]interface{})
	}

	return YandexDocsInfo{
		CookieStr:   strings.Join(cookies, "; "),
		Token:       token,
		DocID:       docID,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, docID),
		Permissions: perms,
		OpenCmd: map[string]interface{}{
			"c":      "open",
			"id":     docID,
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
