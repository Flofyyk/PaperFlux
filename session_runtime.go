package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
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
	done     chan struct{}
	once     sync.Once
	rx, tx   atomic.Uint64
	cups     *cupsonline.CupsonlineTransport
	exit     bool
}

func newSessionRuntime(provider string, urls []string, cfg transport.TransportConfig, exit bool, ipcPath, authAddress string) (*sessionRuntime, error) {
	if profileID == "" || len(profileToken) < 16 {
		return nil, fmt.Errorf("Session requires a profile ID and a secret of at least 16 characters")
	}
	sess, err := transport.NewSession(transport.PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP | control.CapabilityUDP, MaxPacketSize: 65000}, exit)
	if err != nil {
		return nil, err
	}
	sess.SetHandshakeTimeout(5 * time.Minute)
	context := "paperflux-session-v1/profile/" + profileID
	m := manager.New(sess, nil, profileToken, context)
	out := &sessionRuntime{Manager: m, session: sess, done: make(chan struct{}), exit: exit}
	success := false
	defer func() {
		if !success {
			out.Stop()
		}
	}()
	var cookieStore *transport.CookieStore
	if path := os.Getenv("PAPERFLUX_SESSION_COOKIES"); path != "" {
		cookieStore, err = transport.NewCookieStore(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read private session cookie store")
		}
	}
	add := func(name, typ, resource string, raw transport.Transport, priority int, onlyControl bool) error {
		if err := sess.AddTransport(name, raw, profileToken, context, priority); err != nil {
			return err
		}
		if onlyControl {
			sess.SetControlOnly(name)
		}
		cookies, _ := raw.(manager.CookieProvider)
		if err := m.Add(name, typ, raw, priority, cookies); err != nil {
			return err
		}
		if cookieStore != nil && cookies != nil {
			key := sha256.Sum256([]byte(typ + "\x00" + resource))
			return m.UseCookieStore(cookieStore, name, hex.EncodeToString(key[:]))
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
	if authAddress != "" {
		dc := transport.DefaultDirectConfig()
		dc.AuthSecret = profileToken
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
	// Do not accept remote transport lifecycle or cookie-fetch commands. Only
	// explicit cookie offers and auth notifications are necessary for this app.
	sess.SetControlHandler(func(sub control.Subtype, p []byte) {
		switch sub {
		case authrelay.Subtype:
			out.relay.Handle(sub, p)
		case control.SubtypeAuthRequired, control.SubtypeCookiesOffer:
			m.DispatchControl(sub, p)
		}
	})
	sess.SetRecoveryTiming(3*time.Second, 30*time.Second)
	bridge := &sessionIPC{manager: m, pending: make(map[string]*ipc.CookiesRequestPayload), snooze: make(map[string]time.Time)}
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
func (s *sessionRuntime) Start() error {
	go s.stats()
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
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
		}
		ready := s.IsConnected()
		if ready && !previous {
			log.Printf("[PAPERFLUX] TRANSPORT_AUTH_OK: encrypted Session data carrier ready")
		}
		if !ready && previous {
			log.Printf("[PAPERFLUX] PEER_LOST: no verified data carrier")
		}
		previous = ready
		st := s.Stats()
		log.Printf("[PAPERFLUX_STATS] rx=%d tx=%d ping=%d queue=%d retry=%d expired=%d", s.rx.Load(), s.tx.Load(), s.session.DataRTT().Milliseconds(), st.QueuePackets, st.RetryQueued, st.ExpiredDrops)
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
	list := make([]*ipc.CookiesRequestPayload, 0, len(h.pending))
	for _, p := range h.pending {
		list = append(list, p)
	}
	h.mu.Unlock()
	for _, p := range list {
		_ = h.server.SendCookiesRequest(p)
	}
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
	h.mu.Unlock()
	if h.server != nil {
		_ = h.server.SendCookiesRequest(p)
	}
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
		err = h.manager.OfferCookies(p.Transport, p.Jar)
	} else {
		err = h.manager.AcceptCookies(p.Transport, p.Jar)
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
