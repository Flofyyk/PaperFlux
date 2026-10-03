package yandex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// A public link can resolve to a preview rather than an editable document.
// Retrying such a page every few seconds only increases provider throttling.
var errVolgaEditorUnavailable = errors.New("Volga editor is unavailable for this document")

type VolgaConfig struct {
	MaxIdleConnsPerHost int
	MaxIdleConns        int
	IdleConnTimeout     time.Duration
	RelayTimeout        time.Duration

	WorkerCount int
	QueueSize   int

	BatchSize     int
	BatchTimeout  time.Duration
	BatchMaxBytes int

	MaxPayloadBytes int
	MinPayloadBytes int

	ReconnectMinDelay   time.Duration
	ReconnectMaxDelay   time.Duration
	ReconnectMultiplier float64

	WSHandshakeTimeout time.Duration
	WSReadTimeout      time.Duration
	KeepAliveInterval  time.Duration
	MaxSessionAge      time.Duration
}

func DefaultVolgaConfig() VolgaConfig {
	return VolgaConfig{
		MaxIdleConnsPerHost: 8,
		MaxIdleConns:        16,
		IdleConnTimeout:     90 * time.Second,
		RelayTimeout:        30 * time.Second,

		WorkerCount: 4,
		QueueSize:   512,

		BatchSize:     20,
		BatchTimeout:  2 * time.Millisecond,
		BatchMaxBytes: 32 * 1024,

		MaxPayloadBytes: 65535,
		MinPayloadBytes: 200,

		ReconnectMinDelay:   500 * time.Millisecond,
		ReconnectMaxDelay:   30 * time.Second,
		ReconnectMultiplier: 1.5,

		WSHandshakeTimeout: 10 * time.Second,
		WSReadTimeout:      60 * time.Second,
		KeepAliveInterval:  10 * time.Second,
		MaxSessionAge:      30 * time.Minute,
	}
}

const volgaUserAgent = authUserAgent

var reClientConfig = regexp.MustCompile(`(?s)<script[^>]*id="client-config"[^>]*>(.*?)</script>`)

var (
	b64BufPool = sync.Pool{
		New: func() interface{} { return make([]byte, 0, 64*1024) },
	}
	jsonBufPool = sync.Pool{
		New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 128*1024)) },
	}
	blobBufPool = sync.Pool{
		New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 64*1024)) },
	}
)

func base64Encode(data []byte) string {
	buf := b64BufPool.Get().([]byte)
	need := base64.StdEncoding.EncodedLen(len(data))
	if cap(buf) < need {
		buf = make([]byte, need)
	} else {
		buf = buf[:need]
	}
	base64.StdEncoding.Encode(buf, data)
	out := string(buf)
	b64BufPool.Put(buf[:0])
	return out
}

type VolgaStats struct {
	PacketsSent    atomic.Uint64
	PacketsRecv    atomic.Uint64
	BytesSent      atomic.Uint64
	BytesReceived  atomic.Uint64
	HTTPReqsSent   atomic.Uint64
	HTTPReqsFailed atomic.Uint64
	WSReconnects   atomic.Uint64
	QueueDrops     atomic.Uint64
	WorkerBusy     atomic.Int64
	BatchesSent    atomic.Uint64
	PacketsBatched atomic.Uint64
	DataQueued     atomic.Uint64
	DataReceived   atomic.Uint64
	RetryQueued    atomic.Uint64
	QueueWaits     atomic.Uint64
	QueueTimeouts  atomic.Uint64
	QueuedPackets  atomic.Int64
	QueuedBytes    atomic.Int64
}

type volgaAuth struct {
	Session     *http.Client
	AccessToken string
	Token       string
	RequestPath string
	ResourceURL string
	DocID       string
	UserID      int
	UserIDStr   string
	Sign        string
	TS          string
	SessionID   string
	Cookies     []*http.Cookie
}

func authorizeWithJar(ctx context.Context, docURL string, jar http.CookieJar) (*volgaAuth, error) {

	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	session := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if err := loadAuthCookies(jar); err != nil {
		return nil, err
	}
	defer session.CloseIdleConnections()
	finalBody, page, err := fetchAuthPage(ctx, docURL, session, func() error { _, err := solveCaptcha(ctx, docURL, jar, volgaUserAgent); return err })
	if err != nil {
		return nil, err
	}
	finalURL := page.Request.URL.String()

	m := reClientConfig.FindSubmatch(finalBody)
	if len(m) < 2 {
		return nil, fmt.Errorf("Volga client-config not found")
	}

	var cfg map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(m[1]))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse client-config: %w", safeAuthError(err))
	}

	office, _ := cfg["officeActionData"].(map[string]interface{})
	editor, _ := cfg["editorParams"].(map[string]interface{})

	if office == nil {
		return nil, fmt.Errorf("%w: officeActionData missing (keys: %v)", errVolgaEditorUnavailable, mapKeys(cfg))
	}

	actionURL := getStr(office, "action_url")
	accessToken := getStr(office, "access_token")
	ttl := office["access_token_ttl"]

	a := &volgaAuth{
		Session:     session,
		AccessToken: accessToken,
		ResourceURL: getStr(office, "resource_url"),
		DocID:       getStr(editor, "idDoc"),
	}

	if actionURL == "" {
		return nil, fmt.Errorf("%w: action_url missing (keys: %v)", errVolgaEditorUnavailable, mapKeys(office))
	}
	if a.AccessToken == "" {
		return nil, fmt.Errorf("%w: access_token missing", errVolgaEditorUnavailable)
	}

	ttlStr := formatTTL(ttl)

	form := url.Values{}
	form.Set("access_token", a.AccessToken)
	form.Set("access_token_ttl", ttlStr)
	body := form.Encode()

	req2, err := volgaAuthRequest(ctx, "POST", actionURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req2.Header.Set("User-Agent", volgaUserAgent)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Origin", "https://disk.yandex.ru")
	req2.Header.Set("Referer", finalURL)
	req2.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req2.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")
	req2.Header.Set("Upgrade-Insecure-Requests", "1")
	req2.Header.Set("Sec-Fetch-Dest", "iframe")
	req2.Header.Set("Sec-Fetch-Mode", "navigate")
	req2.Header.Set("Sec-Fetch-Site", "cross-site")

	resp2, err := session.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("POST auth/initial: %w", safeAuthError(err))
	}
	resp2.Body.Close()

	if resp2.StatusCode != 302 {
		return nil, fmt.Errorf("auth/initial status %d (expected 302)", resp2.StatusCode)
	}

	target, locationErr := resp2.Location()
	if locationErr != nil {
		return nil, fmt.Errorf("auth/initial no Location")
	}
	location := target.String()

	if strings.Contains(location, "/document/error/") {
		return nil, fmt.Errorf("auth/initial returned /document/error/ — check access_token_ttl and Referer")
	}

	locParsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse Location: %w", safeAuthError(err))
	}
	qs := locParsed.Query()

	a.Token = qs.Get("token")
	a.RequestPath = qs.Get("request-path")

	jsonStr := qs.Get("json")
	if jsonStr == "" {
		return nil, fmt.Errorf("no json in Location (token=%v rp=%v)",
			a.Token != "", a.RequestPath != "")
	}

	var jsonData map[string]interface{}
	dec2 := json.NewDecoder(strings.NewReader(jsonStr))
	dec2.UseNumber()
	if err := dec2.Decode(&jsonData); err != nil {
		return nil, fmt.Errorf("parse Location json: %w", safeAuthError(err))
	}

	a.SessionID = getStr(jsonData, "sessionId")
	a.UserID = int(getFloat(jsonData, "userId"))

	if xiva, ok := jsonData["xiva"].(map[string]interface{}); ok {
		a.Sign = getStr(xiva, "sign")
		a.TS = getStr(xiva, "ts")
		a.UserIDStr = getStr(xiva, "user")
	}

	req3, err := volgaAuthRequest(ctx, "GET", location, nil)
	if err != nil {
		return nil, err
	}
	req3.Header.Set("User-Agent", volgaUserAgent)
	req3.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req3.Header.Set("Referer", actionURL)
	resp3, err := session.Do(req3)
	if err != nil {
		return nil, fmt.Errorf("GET Location: %w", safeAuthError(err))
	}
	io.Copy(io.Discard, io.LimitReader(resp3.Body, maxAuthHTML))
	resp3.Body.Close()

	a.Cookies = jar.Cookies(locParsed)

	if a.Token == "" || a.RequestPath == "" || a.UserIDStr == "" || a.Sign == "" {
		return nil, fmt.Errorf("incomplete auth: token=%v rp=%v user=%v sign=%v",
			a.Token != "", a.RequestPath != "", a.UserIDStr != "", a.Sign != "")
	}

	return a, nil
}

func authorize(docURL string) (*volgaAuth, error) {
	return authorizeWithJar(context.Background(), docURL, nil)
}

func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	case int64:
		return float64(v)
	case int:
		return float64(v)
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

func formatTTL(v interface{}) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case string:
		return x
	case nil:
		return "0"
	default:
		return fmt.Sprintf("%v", x)
	}
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type relayClient struct {
	auth   *volgaAuthState
	config VolgaConfig
	stats  *VolgaStats

	httpClient *http.Client
	workers    int
	queue      chan []byte
	batchQueue chan []byte
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc

	bundleID atomic.Uint64
	seq      atomic.Uint64
	localID  atomic.Uint64

	mu          sync.Mutex
	admissionMu sync.Mutex
	frontier    string
}

func newRelayClient(auth *volgaAuth, cfg VolgaConfig, stats *VolgaStats) *relayClient {
	tr := &http.Transport{
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &relayClient{
		config: cfg,
		stats:  stats,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   cfg.RelayTimeout,
		},
		workers:    cfg.WorkerCount,
		queue:      make(chan []byte, cfg.QueueSize),
		batchQueue: make(chan []byte, cfg.QueueSize),
		ctx:        ctx,
		cancel:     cancel,
	}
	r.auth = newVolgaAuthState(ctx, auth)
	r.auth.onPublish = func() { r.SetFrontier("") }
	return r
}

func (r *relayClient) Start() {
	for i := 0; i < r.workers; i++ {
		r.wg.Add(1)
		go r.worker(i)
	}

}

func (r *relayClient) Stop() {
	r.cancel()
	r.auth.stop()
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	r.wg.Wait()
	for {
		select {
		case p := <-r.batchQueue:
			r.releasePackets([][]byte{p}, true)
		default:
			r.httpClient.CloseIdleConnections()
			return
		}
	}
}

func (r *relayClient) Send(data []byte) error {
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	if r.ctx.Err() != nil {
		return r.ctx.Err()
	}
	if len(data) == 0 {
		return nil
	}
	if len(data) > r.config.MaxPayloadBytes {
		return fmt.Errorf("packet too large: %d > %d", len(data), r.config.MaxPayloadBytes)
	}

	cp := make([]byte, len(data))
	copy(cp, data)
	r.stats.QueuedPackets.Add(1)
	r.stats.QueuedBytes.Add(int64(len(cp)))

	select {
	case r.batchQueue <- cp:
		if !isVolgaKeepalive(cp) {
			r.stats.DataQueued.Add(1)
		}
		return nil
	default:
		r.stats.QueueWaits.Add(1)
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case r.batchQueue <- cp:
			if !isVolgaKeepalive(cp) {
				r.stats.DataQueued.Add(1)
			}
			return nil
		case <-r.ctx.Done():
			r.releasePackets([][]byte{cp}, false)
			return r.ctx.Err()
		case <-timer.C:
			r.releasePackets([][]byte{cp}, false)
			r.stats.QueueTimeouts.Add(1)
			return fmt.Errorf("Volga queue admission timed out")
		}
	}
}

func (r *relayClient) releasePackets(batch [][]byte, dropped bool) {
	var size int64
	for _, p := range batch {
		size += int64(len(p))
	}
	r.stats.QueuedPackets.Add(-int64(len(batch)))
	r.stats.QueuedBytes.Add(-size)
	if dropped {
		r.stats.QueueDrops.Add(uint64(len(batch)))
	}
}

func (r *relayClient) worker(id int) {
	defer r.wg.Done()

	batch := make([][]byte, 0, r.config.BatchSize)
	totalBytes := 0
	timer := time.NewTimer(r.config.BatchTimeout)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.stats.WorkerBusy.Add(1)
		deadline := time.Now().Add(15 * time.Second)
		backoff := 25 * time.Millisecond
		delivered := false
		for r.ctx.Err() == nil {
			if err := r.sendBatch(batch); err == nil {
				r.stats.HTTPReqsSent.Add(1)
				r.stats.BatchesSent.Add(1)
				delivered = true
				break
			}
			r.stats.HTTPReqsFailed.Add(1)
			if time.Now().After(deadline) {
				break
			}
			r.stats.RetryQueued.Add(1)
			timer := time.NewTimer(backoff)
			select {
			case <-r.ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
			backoff = min(backoff*2, 500*time.Millisecond)
		}
		r.releasePackets(batch, !delivered)
		r.stats.WorkerBusy.Add(-1)
		batch = batch[:0]
		totalBytes = 0
	}

	for {
		select {
		case <-r.ctx.Done():
			flush()
			return

		case pkt, ok := <-r.batchQueue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, pkt)
			totalBytes += len(pkt)

			if len(batch) >= r.config.BatchSize || totalBytes >= r.config.BatchMaxBytes {
				flush()
			} else if len(batch) == 1 {
				timer.Reset(r.config.BatchTimeout)
			}

		case <-timer.C:
			flush()
		}
	}
}

func (r *relayClient) sendBatch(batch [][]byte) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	snapshot := r.auth.snapshot()
	if snapshot.auth == nil {
		return fmt.Errorf("authorization unavailable")
	}
	blob := blobBufPool.Get().(*bytes.Buffer)
	blob.Reset()

	var lenBuf [2]byte
	var totalBytes int
	for _, p := range batch {
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))
		blob.Write(lenBuf[:])
		blob.Write(p)
		totalBytes += len(p)
	}

	encoded := base64Encode(blob.Bytes())
	blobBufPool.Put(blob)

	err := r.sendBatchOnce(snapshot.auth, encoded)
	if errors.Is(err, errVolgaUnauthorized) {
		r.auth.reject(snapshot)
		fresh, refreshErr := r.auth.refresh(r.ctx, snapshot)
		if refreshErr != nil {
			return refreshErr
		}
		if err := r.ctx.Err(); err != nil {
			return err
		}
		// Only explicit auth rejection gets an immediate replay. Use the same
		// packet blob but rebuild operation fields from the new generation.
		err = r.sendBatchOnce(fresh.auth, encoded)
		if errors.Is(err, errVolgaUnauthorized) {
			r.auth.reject(fresh)
		}
	}
	if err != nil {
		return err
	}
	r.stats.PacketsSent.Add(uint64(len(batch)))
	r.stats.PacketsBatched.Add(uint64(len(batch)))
	r.stats.BytesSent.Add(uint64(totalBytes))
	return nil
}

func (r *relayClient) sendBatchOnce(auth *volgaAuth, encoded string) error {

	frontier := r.getFrontier()
	opID := fmt.Sprintf("1-%d.%d", auth.UserID, r.seq.Add(1))
	relayOpID := fmt.Sprintf("1-%d.%d", auth.UserID, r.seq.Add(1))

	bundle := []interface{}{
		map[string]interface{}{
			"id":         opID,
			"frontier":   frontier,
			"undoable":   true,
			"actionName": "textInsert",
			"ops":        []interface{}{[]interface{}{"it", "vyd:t/00000000000008", 0, "A"}},
			"sideEffect": false,
			"localId":    r.localID.Add(1),
		},
		map[string]interface{}{
			"id":         relayOpID,
			"frontier":   []interface{}{opID},
			"undoable":   false,
			"actionName": "setCaret",
			"ops": []interface{}{
				[]interface{}{"us", auth.UserID, []interface{}{
					[]interface{}{
						[]interface{}{"vyd:t/00000000000008", 0, -1},
						[]interface{}{"vyd:t/00000000000008", 0, -1},
					},
				}},
			},
			"sideEffect": true,
			"localId":    r.localID.Add(1),
		},
		encoded,
	}

	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"bundleId": r.bundleID.Add(1),
			"bundle":   bundle,
		},
		"targetUserId": nil,
	}

	buf := jsonBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		jsonBufPool.Put(buf)
		return err
	}
	bodyCopy := make([]byte, buf.Len())
	copy(bodyCopy, buf.Bytes())
	jsonBufPool.Put(buf)

	urlStr := fmt.Sprintf("https://volga.yandex.ru/session/main/%s/relay", auth.RequestPath)
	req, err := http.NewRequestWithContext(r.ctx, "POST", urlStr, bytes.NewReader(bodyCopy))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", volgaUserAgent)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://volga.yandex.ru")
	req.Header.Set("Referer", "https://volga.yandex.ru/document/?request-path="+auth.RequestPath)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.ContentLength = int64(len(bodyCopy))

	var cookieParts []string
	for _, c := range auth.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	if len(cookieParts) > 0 {
		req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
	}

	client := *r.httpClient
	if auth.Session != nil {
		client.Jar = auth.Session.Jar
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return errVolgaUnauthorized
	}
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	return nil
}

func (r *relayClient) SetFrontier(opID string) {
	r.mu.Lock()
	r.frontier = opID
	r.mu.Unlock()
}

func (r *relayClient) setFrontierForGeneration(opID string, generation uint64) {
	r.auth.mu.Lock()
	defer r.auth.mu.Unlock()
	if generation != 0 && generation != r.auth.generation {
		return
	}
	r.SetFrontier(opID)
}

func (r *relayClient) getFrontier() []interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frontier == "" {
		return []interface{}{}
	}
	return []interface{}{r.frontier}
}

type wsListener struct {
	auth            *volgaAuthState
	authorizeFn     func(context.Context) (*volgaAuth, error)
	config          VolgaConfig
	stats           *VolgaStats
	relay           *relayClient
	onData          func([]byte)
	connMu          sync.Mutex
	conn            *websocket.Conn
	connected       atomic.Bool
	frameGeneration uint64 // owned by the WS reader, never by refresh workers
	dialFn          func(context.Context, string, http.Header) (*websocket.Conn, error)

	ctx    context.Context
	cancel context.CancelFunc
}

func newWSListener(auth *volgaAuth, cfg VolgaConfig, stats *VolgaStats,
	relay *relayClient, onData func([]byte)) *wsListener {

	ctx, cancel := context.WithCancel(context.Background())
	w := &wsListener{
		auth:   relay.auth,
		config: cfg,
		stats:  stats,
		relay:  relay,
		onData: onData,
		ctx:    ctx,
		cancel: cancel,
	}
	// Installed before any workers start; every refresh shares this callback.
	w.auth.authorize = func(parent context.Context) (*volgaAuth, error) {
		ctx, cancel := context.WithCancel(parent)
		stop := context.AfterFunc(w.ctx, cancel)
		defer func() { stop(); cancel() }()
		if w.authorizeFn == nil || ctx.Err() != nil {
			return nil, errVolgaAuthRefresh
		}
		fresh, err := w.authorizeFn(ctx)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return fresh, err
	}
	return w
}

func (w *wsListener) Start() {
	go w.run()
}

func (w *wsListener) Stop() {
	w.cancel()
	w.auth.cancelRefresh()
	w.RequestReconnect()
	w.connected.Store(false)
}

func (w *wsListener) RequestReconnect() {
	w.connMu.Lock()
	if w.conn != nil {
		_ = w.conn.Close()
	}
	w.connMu.Unlock()
}

func (w *wsListener) refreshAuth() error {
	_, err := w.auth.refresh(w.ctx, w.auth.snapshot())
	return err
}

func nextReconnectDelay(current, connectedFor time.Duration, cfg VolgaConfig) time.Duration {
	if connectedFor >= 2*cfg.WSReadTimeout {
		return cfg.ReconnectMinDelay
	}
	return current
}

func (w *wsListener) run() {
	delay := w.config.ReconnectMinDelay

	for {
		select {
		case <-w.ctx.Done():
			return
		default:
		}

		if w.ctx.Err() != nil {
			return
		}
		connectedAt := time.Now()
		snapshot := w.auth.snapshot()
		err := w.connectSnapshot(snapshot)
		externallyRefreshed := w.auth.snapshot().generation != snapshot.generation
		if err != nil && w.ctx.Err() == nil {
			// Refresh the generation the failed socket actually used. If HTTP
			// already refreshed it, reuse that result without another login.
			_, _ = w.auth.refresh(w.ctx, snapshot)
		}
		if w.ctx.Err() != nil {
			return
		}

		w.stats.WSReconnects.Add(1)
		delay = nextReconnectDelay(delay, time.Since(connectedAt), w.config)
		if externallyRefreshed {
			// A live HTTP refresh is not another failed WS dial. Do not carry
			// an old failure backoff into the new authorization generation.
			delay = w.config.ReconnectMinDelay
		}

		select {
		case <-time.After(delay):
		case <-w.ctx.Done():
			return
		}

		delay = time.Duration(float64(delay) * w.config.ReconnectMultiplier)
		if delay > w.config.ReconnectMaxDelay {
			delay = w.config.ReconnectMaxDelay
		}
	}
}

func (w *wsListener) connect() error {
	return w.connectSnapshot(w.auth.snapshot())
}

func (w *wsListener) connectSnapshot(snapshot volgaAuthSnapshot) error {
	auth := snapshot.auth
	if auth == nil {
		return fmt.Errorf("authorization unavailable")
	}
	ctx, cancel := context.WithCancel(w.ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-snapshot.changed:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); <-watchDone }()
	wsURL := "wss://push.yandex.ru/v2/subscribe/websocket?" +
		"service=volga" +
		"&user=" + url.QueryEscape(auth.UserIDStr) +
		"&sign=" + auth.Sign +
		"&ts=" + auth.TS +
		"&client=web" +
		"&session=" + auth.SessionID +
		"&fetch_history=" + url.QueryEscape(auth.UserIDStr+":volga:0:1") +
		"&x_request_attempt=0"

	header := http.Header{}
	header.Set("User-Agent", volgaUserAgent)
	header.Set("Origin", "https://volga.yandex.ru")

	var cookieParts []string
	for _, c := range auth.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	header.Set("Cookie", strings.Join(cookieParts, "; "))

	dialer := websocket.Dialer{
		HandshakeTimeout: w.config.WSHandshakeTimeout,
		ReadBufferSize:   64 << 10,
		WriteBufferSize:  64 << 10,
	}

	dial := w.dialFn
	if dial == nil {
		dial = func(ctx context.Context, url string, header http.Header) (*websocket.Conn, error) {
			conn, _, err := dialer.DialContext(ctx, url, header)
			return conn, err
		}
	}
	conn, err := dial(ctx, wsURL, header)
	if err != nil {
		return fmt.Errorf("dial: %w", safeAuthError(err))
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	w.connMu.Lock()
	if ctx.Err() != nil {
		w.connMu.Unlock()
		conn.Close()
		return ctx.Err()
	}
	w.conn = conn
	w.connected.Store(true)
	w.connMu.Unlock()
	conn.SetReadLimit(maxAuthHTML)
	started := time.Now()
	defer func() {
		w.connMu.Lock()
		if w.conn == conn {
			w.conn = nil
			w.connected.Store(false)
		}
		w.connMu.Unlock()
		conn.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		deadline := time.Now().Add(w.config.WSReadTimeout)
		if w.config.MaxSessionAge > 0 {
			if rotate := started.Add(w.config.MaxSessionAge); rotate.Before(deadline) {
				deadline = rotate
			}
		}
		conn.SetReadDeadline(deadline)
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", safeAuthError(err))
		}

		// Old-generation frames must not rewrite the new relay frontier.
		if ctx.Err() != nil || w.auth.snapshot().generation != snapshot.generation {
			return context.Canceled
		}
		w.frameGeneration = snapshot.generation
		w.handleMessage(msg)
	}
}

func (w *wsListener) handleMessage(raw []byte) {
	var envelope struct {
		Operation string `json:"operation"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return
	}

	if envelope.Operation == "ping" {
		return
	}
	if envelope.Operation != "SESSION" && envelope.Operation != "WORKER" {
		return
	}
	if envelope.Message == "" {
		return
	}

	var inner struct {
		T       string          `json:"t"`
		UserID  int             `json:"userId"`
		Bundle  json.RawMessage `json:"bundle"`
		Message json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal([]byte(envelope.Message), &inner); err != nil {
		return
	}

	if auth := w.auth.Load(); auth != nil && inner.UserID == auth.UserID {
		return
	}

	switch inner.T {
	case "relay":
		w.handleRelayMessage(inner.Message)
	case "exchange":
		w.handleBundle(inner.Bundle)
	}
}

func (w *wsListener) handleRelayMessage(raw json.RawMessage) {
	var relay struct {
		Bundle []json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &relay); err != nil {
		return
	}
	for _, item := range relay.Bundle {
		w.handleBundleItem(item)
	}
}

func (w *wsListener) handleBundle(raw json.RawMessage) {
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err == nil {
		for _, item := range asArray {
			w.handleBundleItem(item)
		}
		return
	}

	var asObject struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		for _, item := range asObject.Value {
			w.handleBundleItem(item)
		}
	}
}

func (w *wsListener) handleBundleItem(raw json.RawMessage) {
	var asObj struct {
		ID     string `json:"id"`
		Action string `json:"actionName"`
	}
	if err := json.Unmarshal(raw, &asObj); err == nil && asObj.Action != "" {
		if asObj.ID != "" {
			w.relay.setFrontierForGeneration(asObj.ID, w.frameGeneration)
		}
		return
	}

	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil && asStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(asStr)
		if err != nil {
			return
		}
		packets := decodeBatch(decoded)
		w.stats.PacketsRecv.Add(uint64(len(packets)))
		w.stats.BytesReceived.Add(uint64(len(decoded)))
		for _, pkt := range packets {
			if !isVolgaKeepalive(pkt) {
				w.stats.DataReceived.Add(1)
			}
			if w.onData != nil {
				w.onData(pkt)
			}
		}
	}
}

func decodeBatch(decoded []byte) [][]byte {
	var packets [][]byte
	for len(decoded) >= 2 {
		ln := int(binary.BigEndian.Uint16(decoded[:2]))
		decoded = decoded[2:]
		if ln == 0 || len(decoded) < ln {
			break
		}
		packets = append(packets, decoded[:ln])
		decoded = decoded[ln:]
	}
	if len(packets) == 0 && len(decoded) > 0 {
		packets = append(packets, decoded)
	}
	return packets
}
