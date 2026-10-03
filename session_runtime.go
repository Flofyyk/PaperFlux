package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/authrelay"
	"universal-bypass-tool/transport/control"
	"universal-bypass-tool/transport/cupsonline"
	"universal-bypass-tool/transport/ipc"
	"universal-bypass-tool/transport/mailru"
	"universal-bypass-tool/transport/manager"
	"universal-bypass-tool/transport/yandex"
	sessionYandex "universal-bypass-tool/transport/yandexsession"
	"universal-bypass-tool/tunnel"
)

type sessionRuntime struct {
	*manager.Manager
	session  *transport.Session
	ipc      *ipc.Server
	relay    *authrelay.Relay
	listener net.Listener
	auth     *sessionIPC
	done     chan struct{}
	once     sync.Once
	rx, tx   atomic.Uint64
	cups     *cupsonline.CupsonlineTransport
	exit     bool
	quiet    bool
}

func newSessionRuntime(provider string, urls []string, volgaURL string, cfg transport.TransportConfig, exit bool, ipcPath, authAddress string) (*sessionRuntime, error) {
	return newProfileSessionRuntime(provider, urls, volgaURL, cfg, exit, ipcPath, authAddress, sessionIdentity{
		ID: profileID, Token: profileToken, CookiePath: os.Getenv("PAPERFLUX_SESSION_COOKIES"),
	})
}

// Identity is explicit: different profiles in one process must never share
// package-global keys, cookie paths or mutate process-wide environment values.
type sessionIdentity struct {
	ID, Token, CookiePath string
	Quiet                 bool
}

func profileCookieKey(provider, resource string) string {
	digest := sha256.Sum256([]byte(provider + "\x00" + resource))
	return hex.EncodeToString(digest[:])
}

// A profile owns its Yandex document cookies. A newly added document has no
// saved jar, while a healthy sibling often has the same account-wide Yandex
// cookies. Seed only absent jars from another configured document in this
// profile; never read a different profile store or overwrite its own jar.
func seedProfileYandexCookies(store *transport.CookieStore, urls []string, volgaURL string) error {
	if store == nil {
		return nil
	}
	var source map[string]string
	for _, raw := range urls {
		resource := strings.TrimSpace(raw)
		if resource != "" {
			if jar := store.Load(profileCookieKey("yandex", resource)); len(jar) > 0 {
				source = jar
				break
			}
		}
	}
	if len(source) == 0 && validVolgaDocument(volgaURL) {
		source = store.Load(profileCookieKey("vyandex", volgaURL))
	}
	if len(source) == 0 {
		return nil
	}
	for _, raw := range urls {
		resource := strings.TrimSpace(raw)
		if resource == "" {
			continue
		}
		key := profileCookieKey("yandex", resource)
		if len(store.Load(key)) == 0 {
			if err := store.Save(key, source); err != nil {
				return err
			}
		}
	}
	if validVolgaDocument(volgaURL) {
		key := profileCookieKey("vyandex", volgaURL)
		if len(store.Load(key)) == 0 {
			return store.Save(key, source)
		}
	}
	return nil
}

func newProfileSessionRuntime(provider string, urls []string, volgaURL string, cfg transport.TransportConfig, exit bool, ipcPath, authAddress string, identity sessionIdentity) (*sessionRuntime, error) {
	if identity.ID == "" || len(identity.Token) < 16 {
		return nil, fmt.Errorf("Session requires a profile ID and a secret of at least 16 characters")
	}
	sess, err := transport.NewSession(transport.PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP | control.CapabilityUDP, MaxPacketSize: 65000}, exit)
	if err != nil {
		return nil, err
	}
	sess.SetHandshakeTimeout(5 * time.Minute)
	if identity.Quiet {
		if err := sess.SetBatchByteLimit(256 << 10); err != nil {
			return nil, err
		}
	}
	context := "paperflux-session-v1/profile/" + identity.ID
	m := manager.New(sess, nil, identity.Token, context)
	out := &sessionRuntime{Manager: m, session: sess, done: make(chan struct{}), exit: exit, quiet: identity.Quiet}
	success := false
	defer func() {
		if !success {
			out.Stop()
		}
	}()
	var cookieStore *transport.CookieStore
	if path := identity.CookiePath; path != "" {
		cookieStore, err = transport.NewCookieStore(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read private session cookie store")
		}
		if provider == "yandex" {
			if err := seedProfileYandexCookies(cookieStore, urls, volgaURL); err != nil {
				return nil, fmt.Errorf("cannot prepare profile Yandex cookies: %w", err)
			}
		}
	}
	add := func(name, typ, resource string, raw transport.Transport, priority int, onlyControl bool) error {
		if err := sess.AddTransport(name, raw, identity.Token, context, priority); err != nil {
			return err
		}
		if onlyControl {
			sess.SetControlOnly(name)
		}
		cookies, _ := raw.(manager.CookieProvider)
		if err := m.Add(name, typ, raw, priority, cookies); err != nil {
			return err
		}
		m.SetURL(name, resource)
		if cookieStore != nil && cookies != nil {
			return m.UseCookieStore(cookieStore, name, profileCookieKey(typ, resource))
		}
		return nil
	}
	for i, resource := range urls {
		resource = strings.TrimSpace(resource)
		if resource == "" && provider != "cupsonline" {
			continue
		}
		name := fmt.Sprintf("%s-%d", provider, i+1)
		var raw transport.Transport
		switch provider {
		case "yandex":
			raw = sessionYandex.NewYandexDocsTransport(resource, cfg)
		case "vyandex":
			raw = yandex.NewYandexVolgaTransport(resource, cfg)
		case "cupsonline":
			out.cups = cupsonline.NewCupsonlineTransport(resource, cfg, !exit)
			raw = out.cups
		case "mailru":
			raw = mailru.NewMailruDocsTransport(resource, cfg)
		default:
			return nil, fmt.Errorf("unsupported Session transport")
		}
		if err := add(name, provider, resource, raw, 100, false); err != nil {
			return nil, err
		}
	}
	if volgaURL != "" {
		if provider != "yandex" || !validVolgaDocument(volgaURL) {
			return nil, fmt.Errorf("Volga fallback needs a separate editable Yandex document")
		}
		for _, resource := range urls {
			if strings.TrimSpace(resource) == volgaURL {
				return nil, fmt.Errorf("Volga fallback must not share a WebSocket document")
			}
		}
		if err := add("volga-1", "vyandex", volgaURL, yandex.NewYandexVolgaTransport(volgaURL, cfg), 80, false); err != nil {
			return nil, err
		}
	}
	if authAddress != "" {
		dc := transport.DefaultDirectConfig()
		dc.AuthSecret = identity.Token
		dc.ReadTimeout = 45 * time.Second
		dc.ReconnectMinDelay = 2 * time.Second
		dc.ReconnectMaxDelay = 30 * time.Second
		dc.IsExit = exit
		if exit {
			dc.ListenAddr = authAddress
		} else {
			dc.DialAddr = authAddress
		}
		if err := add("auth-service", "direct", "", transport.NewDirectTransport(cfg, dc), 1000, true); err != nil {
			return nil, err
		}
	}
	out.relay = authrelay.New(exit, m.SendControl)
	// Only pass through authenticated cookie exchange and auth notifications;
	// remote transport lifecycle commands remain disabled for this app.
	sess.SetControlHandler(func(sub control.Subtype, p []byte) {
		switch sub {
		case authrelay.Subtype:
			out.relay.Handle(sub, p)
		case control.SubtypeAuthRequired, control.SubtypeCookiesRequest,
			control.SubtypeCookiesResponse, control.SubtypeCookiesOffer:
			m.DispatchControl(sub, p)
			if (sub == control.SubtypeCookiesResponse || sub == control.SubtypeCookiesOffer) && out.auth != nil {
				out.auth.onPeerCookies(p)
			}
		}
	})
	sess.SetRecoveryTiming(3*time.Second, 30*time.Second)
	bridge := &sessionIPC{manager: m, pending: make(map[string]*ipc.CookiesRequestPayload), snooze: make(map[string]time.Time)}
	out.auth = bridge
	if !exit && cookieStore != nil {
		bridge.restoreSnooze(cookieStore.Path() + ".snooze")
	}
	sess.SetHandshakePause(func() bool { bridge.mu.Lock(); defer bridge.mu.Unlock(); return len(bridge.pending) > 0 })
	notify := func(name, url, reason string, remote bool) {
		request := &ipc.CookiesRequestPayload{Transport: name, URL: url, Reason: reason, Remote: remote}
		if remote && out.listener != nil {
			request.Proxy = out.listener.Addr().String()
		}
		bridge.remember(request)
		log.Printf("[PAPERFLUX_AUTH_REQUIRED] remote=%t transport=%s reason=%s", remote, name, reason)
	}
	m.SetCaptchaNotifier(func(n, u, r string) { notify(n, u, r, false) })
	m.SetRemoteAuthNotifier(func(n, u, r string) { notify(n, u, r, true) })
	if ipcPath != "" && !exit {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		out.listener = ln
		go func() { _ = tunnel.ServeHTTPProxy(ln, out.relay.Dial) }()
		srv := ipc.NewServer(ipcPath, bridge)
		bridge.server = srv
		out.ipc = srv
		if err := srv.Listen(); err != nil {
			return nil, err
		}
	}
	success = true
	return out, nil
}

var volgaDocumentPath = regexp.MustCompile(`^/i/[A-Za-z0-9_-]+$`)

func validVolgaDocument(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "disk.yandex.ru" &&
		u.User == nil && u.RawQuery == "" && u.Fragment == "" && volgaDocumentPath.MatchString(u.Path)
}
func (s *sessionRuntime) Start() error {
	if !s.quiet {
		go s.stats()
	}
	if err := s.Manager.Start(); err != nil {
		return err
	}
	// Private manager input, never a public application log.
	if s.exit && s.cups != nil && s.cups.RoomList() != "" {
		log.Printf("[PAPERFLUX_ROOMS] %s", s.cups.RoomList())
	}
	return nil
}
func (s *sessionRuntime) Stop() error {
	s.once.Do(func() {
		close(s.done)
		if s.ipc != nil {
			s.ipc.Close()
		}
		if s.listener != nil {
			s.listener.Close()
		}
		if s.relay != nil {
			s.relay.Close()
		}
	})
	return s.Manager.Stop()
}
func (s *sessionRuntime) IsConnected() bool { return s.session.HasDataPath() }
func (s *sessionRuntime) Send(p []byte) error {
	err := s.Manager.Send(p)
	if err == nil {
		s.tx.Add(uint64(len(p)))
	}
	return err
}
func (s *sessionRuntime) Receive(cb func([]byte)) {
	s.Manager.Receive(func(p []byte) { s.rx.Add(uint64(len(p))); cb(p) })
}
func (s *sessionRuntime) ReceiveSessionPackets(cb func(uint64, []byte)) {
	s.session.ReceiveSessionPackets(func(epoch uint64, p []byte) { s.rx.Add(uint64(len(p))); cb(epoch, p) })
}
func (s *sessionRuntime) DataEpoch() uint64 { return s.session.DataEpoch() }
func (s *sessionRuntime) SendSessionPacket(epoch uint64, p []byte) error {
	err := s.session.SendSessionPacket(epoch, p)
	if err == nil {
		s.tx.Add(uint64(len(p)))
	}
	return err
}
func (s *sessionRuntime) Stats() transport.TransportStats {
	st := s.Manager.Stats()
	st.Connected = s.IsConnected()
	st.BytesSent = s.tx.Load()
	st.BytesReceived = s.rx.Load()
	return st
}
func (s *sessionRuntime) stats() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	previous := false
	var lastCookieRequest time.Time
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
		}
		ready := s.IsConnected()
		if s.auth != nil {
			s.auth.clearConnectedLocalPending()
		}
		// A service-channel handshake can succeed while every document is
		// blocked by stale cookies. Ask this profile's authenticated exit for
		// its current jars, without turning the service channel into a data path.
		if !ready && s.session.IsConnected() && time.Since(lastCookieRequest) >= 30*time.Second {
			lastCookieRequest = time.Now()
			if err := s.Manager.RequestPeerCookies(); err != nil {
				log.Printf("[PAPERFLUX] profile cookie refresh unavailable: %v", err)
			}
		}
		if ready && !previous {
			log.Printf("[PAPERFLUX] TRANSPORT_AUTH_OK: encrypted Session data carrier ready")
		}
		if !ready && previous {
			log.Printf("[PAPERFLUX] PEER_LOST: no verified data carrier")
		}
		previous = ready
		st := s.Stats()
		log.Printf("[PAPERFLUX_STATS] rx=%d tx=%d ping=%d queue=%d retry=%d expired=%d queue_bytes=%d queue_waits=%d queue_timeouts=%d write_failures=%d", s.rx.Load(), s.tx.Load(), s.session.DataRTT().Milliseconds(), st.QueuePackets, st.RetryQueued, st.ExpiredDrops, st.QueueBytes, st.QueueWaits, st.QueueTimeouts, st.WriteFailures)
	}
}

type sessionIPC struct {
	manager    *manager.Manager
	server     *ipc.Server
	mu         sync.Mutex
	pending    map[string]*ipc.CookiesRequestPayload
	snooze     map[string]time.Time
	snoozePath string
}

// Keep the ten-minute cancellation across Android worker replacement; otherwise
// a five-minute connection timeout would recreate the same dismissed prompt.
func (h *sessionIPC) restoreSnooze(path string) {
	h.snoozePath = path
	info, err := os.Stat(path)
	if err != nil || info.Size() > 65536 {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var saved map[string]int64
	if json.Unmarshal(data, &saved) != nil || len(saved) > 128 {
		return
	}
	now := time.Now()
	for key, millis := range saved {
		until := time.UnixMilli(millis)
		if until.After(now) && until.Sub(now) <= 10*time.Minute {
			h.snooze[key] = until
		}
	}
}
func (h *sessionIPC) persistSnoozeLocked() {
	if h.snoozePath == "" {
		return
	}
	saved := make(map[string]int64)
	for key, until := range h.snooze {
		if until.After(time.Now()) {
			saved[key] = until.UnixMilli()
		}
	}
	data, err := json.Marshal(saved)
	if err != nil || len(data) > 65536 {
		return
	}
	tmp := h.snoozePath + ".tmp"
	if os.WriteFile(tmp, data, 0600) == nil {
		_ = os.Rename(tmp, h.snoozePath)
	}
}

func (h *sessionIPC) OnConnect() {
	h.mu.Lock()
	for _, p := range h.pending {
		_ = h.server.SendCookiesRequest(p)
	}
	h.mu.Unlock()
}
func (h *sessionIPC) OnDisconnect() {}
func (h *sessionIPC) OnCommand(p *ipc.CommandPayload) {
	if p == nil || p.Action != "cancel-auth" {
		return
	}
	id, _ := p.Params["requestId"].(string)
	h.mu.Lock()
	for key, request := range h.pending {
		if request.RequestID == id {
			if h.snooze == nil {
				h.snooze = make(map[string]time.Time)
			}
			h.snooze[key] = time.Now().Add(10 * time.Minute)
			h.persistSnoozeLocked()
			delete(h.pending, key)
			break
		}
	}
	h.mu.Unlock()
}
func (h *sessionIPC) remember(p *ipc.CookiesRequestPayload) {
	h.mu.Lock()
	key := fmt.Sprintf("%t/%s", p.Remote, p.Transport)
	if time.Now().Before(h.snooze[key]) {
		h.mu.Unlock()
		return
	}
	if prior := h.pending[key]; prior != nil {
		p.RequestID = prior.RequestID
	} else {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			h.mu.Unlock()
			return
		}
		p.RequestID = hex.EncodeToString(nonce[:])
	}
	h.pending[key] = p
	if h.server != nil {
		_ = h.server.SendCookiesRequest(p)
	}
	h.mu.Unlock()
}
func (h *sessionIPC) OnCookies(p *ipc.CookiesOfferPayload) {
	if p == nil || len(p.Jar) == 0 || len(p.Jar) > 128 {
		return
	}
	h.mu.Lock()
	key := fmt.Sprintf("%t/%s", p.Remote, p.Transport)
	request := h.pending[key]
	h.mu.Unlock()
	if request == nil || p.RequestID == "" || request.RequestID != p.RequestID {
		return
	}
	var err error
	if p.Remote {
		err = h.manager.OfferCookiesForDomain(p.Transport, p.Domain, p.Jar)
	} else {
		err = h.manager.AcceptCookiesForDomain(p.Transport, p.Domain, p.Jar)
	}
	if err == nil {
		h.mu.Lock()
		delete(h.pending, key)
		h.mu.Unlock()
		log.Printf("[PAPERFLUX_AUTH_UPDATED] remote=%t", p.Remote)
		if h.server != nil {
			_ = h.server.SendLog("AUTH_UPDATED:" + p.RequestID)
		}
	} else {
		log.Printf("[PAPERFLUX_AUTH_FAILED] cookie update was not accepted")
	}
}

func (h *sessionIPC) onPeerCookies(payload []byte) {
	cp, err := control.DecodeCookies(payload)
	if err != nil {
		return
	}
	name := h.manager.MatchingCookieCarrierForDomain(cp.Transport, cp.Doc, cp.Domain, cp.Jar)
	if name == "" {
		return
	}
	h.mu.Lock()
	key := "false/" + name
	request := h.pending[key]
	if request != nil {
		delete(h.pending, key)
	}
	h.mu.Unlock()
	if request != nil {
		log.Printf("[PAPERFLUX_AUTH_UPDATED] remote=false transport=%s", name)
		if h.server != nil {
			_ = h.server.SendLog("AUTH_UPDATED:" + request.RequestID)
		}
	}
}

func (h *sessionIPC) clearConnectedLocalPending() {
	h.mu.Lock()
	for key, request := range h.pending {
		if request.Remote || !h.manager.IsCookieCarrierConnected(request.Transport) {
			continue
		}
		delete(h.pending, key)
		log.Printf("[PAPERFLUX_AUTH_UPDATED] remote=false transport=%s", request.Transport)
		if h.server != nil {
			_ = h.server.SendLog("AUTH_UPDATED:" + request.RequestID)
		}
	}
	h.mu.Unlock()
}
