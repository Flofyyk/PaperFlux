// Package manager coordinates a Session with several transports and exposes
// a single facade for the CLI and the mobile bridge.
//
// The Session holds the handshake state; the manager holds the transports.
// When the client asks the exit to bring up a new transport (via a
// SubtypeTransportStart control packet), the manager uses the Factory to
// build it and adds it to the Session on the fly.
package manager

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/control"
	"universal-bypass-tool/transport/yandexhosts"
	"universal-bypass-tool/utils"
)

// Factory builds a raw transport from a control.TransportConfig.
// main.go provides the concrete implementation because it is the only place
// that knows about every transport package (yandex, mailru, direct, ...).
type Factory func(cfg *control.TransportConfig) (transport.Transport, error)

// CookieProvider is implemented by raw transports that carry cookies.
// Manager delegates per-transport cookie operations to it.
type CookieProvider interface {
	FetchCookies() (map[string]string, error)
	ApplyCookies(jar map[string]string) error
}

// Entry is one transport attached to the manager.
type Entry struct {
	Name     string
	Type     string
	URL      string
	Priority int
	Raw      transport.Transport
	Provider CookieProvider // nil if the transport does not carry cookies
}

// Manager owns a Session and the transports attached to it.
type Manager struct {
	session *transport.Session
	factory Factory
	secret  string
	context string

	mu      sync.RWMutex
	entries map[string]*Entry
	order   []string // transport names, priority-descending

	// Cookie persistence: store key per transport name.
	store      *transport.CookieStore
	cookieKeys map[string]string
	// Serialize cookie read/merge/apply/save across IPC and peer offers.
	cookieMu sync.Mutex

	// Callbacks wired from main.go / mobile bridge.
	dataCallback    func([]byte)
	controlCallback func(sub control.Subtype, payload []byte)
	captchaNotifier CaptchaNotifier
	remoteAuth      CaptchaNotifier

	// authSent rate-limits AuthRequired forwarding per transport.
	authSent map[string]time.Time
}

// authForwardInterval bounds how often the exit re-sends AuthRequired for
// one transport; a stuck transport re-reports about every 30s on its own.
const authForwardInterval = 20 * time.Second

// New creates a Manager around a fresh Session. secret and context are the
// same values used by Session.AddTransport for bootstrap transports; they
// are reused for dynamically started ones.
func New(session *transport.Session, factory Factory, secret, context string) *Manager {
	return &Manager{
		session: session,
		factory: factory,
		secret:  secret,
		context: context,
		entries: make(map[string]*Entry),
	}
}

// Session returns the underlying Session.
func (m *Manager) Session() *transport.Session { return m.session }

// Add attaches an already-built transport. Priority is used to order
// transports for handshake and for control traffic.
func (m *Manager) Add(name, typ string, raw transport.Transport, priority int, provider CookieProvider) error {
	if name == "" {
		return errors.New("manager: empty name")
	}
	if raw == nil {
		return errors.New("manager: nil transport")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[name]; exists {
		return fmt.Errorf("manager: transport %q already attached", name)
	}
	m.entries[name] = &Entry{
		Name:     name,
		Type:     typ,
		Priority: priority,
		Raw:      raw,
		Provider: provider,
	}
	m.order = insertByPriority(m.order, name, priority, m.entries)

	// If the raw transport wants to report out-of-band errors (captcha,
	// login required), subscribe on its behalf. The callback captures the
	// transport name so the notifier can route it back to the right IPC
	// channel.
	if en, ok := raw.(transport.ErrorNotifier); ok {
		transportName := name
		en.SetErrorNotifier(func(_ error, _, url, reason string) {
			m.NotifyCaptcha(transportName, url, reason)
		})
	}
	return nil
}

// SetURL associates a carrier with its document, independently of the local
// carrier name. The URL is only sent inside the encrypted control channel.
func (m *Manager) SetURL(name, url string) {
	m.mu.Lock()
	if entry := m.entries[name]; entry != nil {
		entry.URL = url
	}
	m.mu.Unlock()
}

// Remove detaches a transport from the Session and stops it.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	e, ok := m.entries[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("manager: transport %q not found", name)
	}
	delete(m.entries, name)
	for i, n := range m.order {
		if n == name {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.mu.Unlock()

	if err := m.session.RemoveTransport(name); err != nil {
		// A manager entry can be registered before its Session carrier (for
		// example by callers using the facade only). Still release that raw
		// transport, but do not stop registered carriers twice.
		return e.Raw.Stop()
	}
	return nil
}

// Transports returns the names of attached transports in priority order.
func (m *Manager) Transports() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.order...)
}

// Start brings up the Session, which starts every registered transport. On
// the client it returns once the handshake completed; on the exit node it
// returns right away and the session becomes ready when a client arrives.
func (m *Manager) Start() error {
	m.mu.RLock()
	entries := make([]*Entry, 0, len(m.order))
	for _, name := range m.order {
		entries = append(entries, m.entries[name])
	}
	m.mu.RUnlock()

	if len(entries) == 0 {
		return errors.New("manager: no transports attached")
	}

	// main.go is expected to have already called Session.AddTransport for
	// each entry with the correct secret and context. Manager.Start() only
	// kicks off the handshake and hands the ready session back.
	return m.session.Start()
}

// Stop tears down the Session and every transport.
func (m *Manager) Stop() error {
	return m.session.Stop()
}

// Send routes one IPv4 packet.
func (m *Manager) Send(pkt []byte) error { return m.session.Send(pkt) }

// Receive installs the IPv4 data callback.
func (m *Manager) Receive(cb func([]byte)) {
	m.mu.Lock()
	m.dataCallback = cb
	m.mu.Unlock()
	m.session.Receive(cb)
}

// SendControl sends a control packet through the Session.
func (m *Manager) SendControl(sub control.Subtype, payload []byte) error {
	return m.session.SendControl(sub, payload)
}

// ---- CookieExchanger (per-transport) ----

// FetchCookiesFor returns the cookie jar of one transport.
func (m *Manager) FetchCookiesFor(name string) (map[string]string, error) {
	m.mu.RLock()
	e, ok := m.entries[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("manager: transport %q not found", name)
	}
	if e.Provider == nil {
		return nil, fmt.Errorf("manager: transport %q does not carry cookies", name)
	}
	return e.Provider.FetchCookies()
}

// ApplyCookiesFor replaces the cookie jar of one transport.
func (m *Manager) ApplyCookiesFor(name string, jar map[string]string) error {
	m.mu.RLock()
	e, ok := m.entries[name]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("manager: transport %q not found", name)
	}
	if e.Provider == nil {
		return fmt.Errorf("manager: transport %q does not carry cookies", name)
	}
	return e.Provider.ApplyCookies(jar)
}

// UseCookieStore persists cookies accepted for transport name under key and
// replays what was saved for it before. Call before Start.
func (m *Manager) UseCookieStore(store *transport.CookieStore, name, key string) error {
	m.mu.Lock()
	m.store = store
	if m.cookieKeys == nil {
		m.cookieKeys = make(map[string]string)
	}
	m.cookieKeys[name] = key
	m.mu.Unlock()
	if jar := store.Load(key); len(jar) > 0 {
		if err := m.ApplyCookiesFor(name, jar); err != nil {
			return err
		}
	}
	for _, root := range yandexhosts.Roots() {
		if jar := store.Load(domainStoreKey(key, root)); len(jar) > 0 {
			provider, _, err := m.cookieDomainProvider(name, root)
			if err != nil {
				return err
			}
			if err := provider.ApplyCookiesForDomain(root, jar); err != nil {
				return err
			}
		}
	}
	return nil
}

// AcceptCookies applies a jar to one transport and persists it, whether it
// came from the peer over the control channel or from the local app (IPC).
func (m *Manager) AcceptCookies(name string, jar map[string]string) error {
	return m.AcceptCookiesForDomain(name, "", jar)
}

// cookieTransport resolves a peer's carrier by document URL, then by its
// local name. Older peers may omit the URL or even the name. Type fallback
// is allowed only when there is exactly one cookie carrier of that type.
func (m *Manager) cookieTransport(name, doc string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if name == "" {
		for _, n := range m.order {
			if m.entries[n].Provider != nil {
				return n
			}
		}
		return ""
	}
	if doc != "" {
		for _, n := range m.order {
			if e := m.entries[n]; e.Provider != nil && e.URL == doc {
				return n
			}
		}
		// A matching name may refer to a different document if the client
		// and exit enumerate URLs in a different order. An unmatched URL is
		// safer to reject than to guess by name or type.
		if e := m.entries[name]; e != nil && e.Provider != nil && e.URL == "" {
			return name // An older local configuration did not record URLs.
		}
		return ""
	}
	if e := m.entries[name]; e != nil && e.Provider != nil {
		return name
	}
	typ := name
	if i := strings.LastIndexByte(name, '-'); i > 0 {
		if _, err := strconv.Atoi(name[i+1:]); err == nil {
			typ = name[:i]
		}
	}
	match := ""
	for _, n := range m.order {
		e := m.entries[n]
		if e.Provider != nil && e.Type == typ {
			if match != "" {
				return "" // Ambiguous: never send cookies to an arbitrary document.
			}
			match = n
		}
	}
	return match
}

func (m *Manager) entryURL(name string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if e := m.entries[name]; e != nil {
		return e.URL
	}
	return ""
}

// handleCookies serves the cookie-exchange subtypes. Only the exit answers
// requests; both sides accept responses and unprompted offers.
func (m *Manager) handleCookies(sub control.Subtype, payload []byte) {
	cp, err := control.DecodeCookies(payload)
	if err != nil {
		utils.Debugf("[MANAGER] bad cookies payload: %v", err)
		return
	}
	name := m.cookieTransport(cp.Transport, cp.Doc)
	if name == "" {
		utils.Debugf("[MANAGER] cannot match cookie carrier %q (document supplied=%t)", cp.Transport, cp.Doc != "")
		return
	}
	switch sub {
	case control.SubtypeCookiesRequest:
		if !m.session.IsExit() {
			return
		}
		jar, err := m.fetchCookiesForDomain(name, cp.Domain)
		if err != nil {
			utils.Debugf("[MANAGER] fetch cookies (%s): %v", name, err)
			return
		}
		// A passed check can be shared; the exit owner's account login cannot.
		body, _ := (&control.CookiesPayload{Transport: name, Doc: m.entryURL(name), Domain: cp.Domain, Jar: shareableCookies(jar), Reason: "requested"}).Encode()
		_ = m.SendControl(control.SubtypeCookiesResponse, body)
	case control.SubtypeCookiesResponse, control.SubtypeCookiesOffer:
		if len(cp.Jar) == 0 {
			return
		}
		// An unchanged response must not wake a carrier out of its normal
		// reconnect backoff or rewrite the profile cookie store.
		if current, err := m.fetchCookiesForDomain(name, cp.Domain); err == nil && containsCookies(current, cp.Jar) {
			return
		}
		accept := m.AcceptCookiesForDomain
		if sub == control.SubtypeCookiesResponse {
			accept = m.acceptPeerCookiesForDomain
		}
		if err := accept(name, cp.Domain, cp.Jar); err != nil {
			utils.Debugf("[MANAGER] apply cookies (%s): %v", name, err)
		}
	}
}

// RequestPeerCookies asks the authenticated exit for each configured cookie
// carrier. The document URL prevents an answer for a similarly named carrier
// from being applied to another profile document.
func (m *Manager) RequestPeerCookies() error {
	m.mu.RLock()
	requests := make([]control.CookiesPayload, 0, len(m.order))
	for _, name := range m.order {
		if e := m.entries[name]; e != nil && e.Provider != nil && e.URL != "" {
			requests = append(requests, control.CookiesPayload{Transport: name, Doc: e.URL})
		}
	}
	m.mu.RUnlock()
	var firstErr error
	for _, request := range requests {
		body, err := request.Encode()
		if err == nil {
			err = m.SendControl(control.SubtypeCookiesRequest, body)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// MatchingCookieCarrier confirms that a peer response was applied to the
// intended document before the UI dismisses an outstanding auth prompt.
func (m *Manager) MatchingCookieCarrier(name, doc string, jar map[string]string) string {
	return m.MatchingCookieCarrierForDomain(name, doc, "", jar)
}

func (m *Manager) MatchingCookieCarrierForDomain(name, doc, domain string, jar map[string]string) string {
	if len(jar) == 0 {
		return ""
	}
	local := m.cookieTransport(name, doc)
	if local == "" {
		return ""
	}
	current, err := m.fetchCookiesForDomain(local, domain)
	if err != nil || !containsCookies(current, jar) {
		return ""
	}
	return local
}

// IsCookieCarrierConnected is true only after that document's raw transport
// has established its own connection; a separate service channel is not enough.
func (m *Manager) IsCookieCarrierConnected(name string) bool {
	m.mu.RLock()
	e := m.entries[name]
	m.mu.RUnlock()
	return e != nil && e.Provider != nil && e.Raw.IsConnected()
}

// ---- Control dispatch ----

// DispatchControl is the Session's ControlHandler. It interprets transport
// lifecycle and cookie packets locally and forwards anything else to the
// higher layer.
func (m *Manager) DispatchControl(sub control.Subtype, payload []byte) {
	switch sub {
	case control.SubtypeTransportStart:
		cfg, err := control.DecodeTransportConfig(payload)
		if err != nil {
			utils.Debugf("[MANAGER] bad TransportStart payload: %v", err)
			return
		}
		if err := m.startTransport(cfg); err != nil {
			utils.Debugf("[MANAGER] TransportStart %q: %v", cfg.Name, err)
			m.sendStatus(cfg.Name, cfg.Type, false, err)
			return
		}
		m.sendStatus(cfg.Name, cfg.Type, true, nil)

	case control.SubtypeTransportStop:
		cfg, err := control.DecodeTransportConfig(payload)
		if err != nil {
			utils.Debugf("[MANAGER] bad TransportStop payload: %v", err)
			return
		}
		if err := m.Remove(cfg.Name); err != nil {
			utils.Debugf("[MANAGER] TransportStop %q: %v", cfg.Name, err)
		}

	case control.SubtypeTransportList:
		m.sendList()

	case control.SubtypeCookiesRequest, control.SubtypeCookiesResponse, control.SubtypeCookiesOffer:
		m.handleCookies(sub, payload)

	case control.SubtypeAuthRequired:
		req, err := control.DecodeAuthRequired(payload)
		if err != nil || req.Transport == "" {
			utils.Debugf("[MANAGER] bad AuthRequired payload: %v", err)
			return
		}
		if local := m.cookieTransport(req.Transport, req.Doc); local == "" {
			utils.Debugf("[MANAGER] cannot match auth carrier %q (document supplied=%t)", req.Transport, req.Doc != "")
		}
		m.mu.RLock()
		cb := m.remoteAuth
		m.mu.RUnlock()
		if cb != nil {
			cb(req.Transport, req.URL, req.Reason)
		}

	default:
		m.mu.RLock()
		cb := m.controlCallback
		m.mu.RUnlock()
		if cb != nil {
			cb(sub, payload)
		}
	}
}

// SetControlCallback installs the callback that receives control packets
// not handled locally.
func (m *Manager) SetControlCallback(cb func(sub control.Subtype, payload []byte)) {
	m.mu.Lock()
	m.controlCallback = cb
	m.mu.Unlock()
}

// startTransport builds a transport via the Factory, registers it in the
// Session, and brings it up. Used by SubtypeTransportStart.
//
// The secret and context are the same values main.go uses for bootstrap
// transports; they are stored on the Manager at construction time.
func (m *Manager) startTransport(cfg *control.TransportConfig) error {
	if cfg == nil || cfg.Name == "" {
		return errors.New("manager: empty config")
	}
	raw, err := m.factory(cfg)
	if err != nil {
		return fmt.Errorf("factory: %w", err)
	}
	priority := 50
	if v, ok := cfg.Params["priority"].(float64); ok {
		priority = int(v)
	}
	var provider CookieProvider
	if p, ok := raw.(CookieProvider); ok {
		provider = p
	}

	if err := m.session.AddTransportPostStart(cfg.Name, raw, m.secret, m.context, priority); err != nil {
		return err
	}
	if err := m.Add(cfg.Name, cfg.Type, raw, priority, provider); err != nil {
		// Roll back the Session-side registration.
		_ = m.session.RemoveTransport(cfg.Name)
		return err
	}
	return nil
}

func (m *Manager) sendStatus(name, typ string, connected bool, err error) {
	st := control.TransportStatus{Name: name, Type: typ, Connected: connected}
	if err != nil {
		st.Error = err.Error()
	}
	body, _ := (&control.TransportStatusList{Transports: []control.TransportStatus{st}}).Encode()
	_ = m.session.SendControl(control.SubtypeTransportStatus, body)
}

func (m *Manager) sendList() {
	m.mu.RLock()
	list := make([]control.TransportStatus, 0, len(m.order))
	for _, name := range m.order {
		e := m.entries[name]
		list = append(list, control.TransportStatus{
			Name:      e.Name,
			Type:      e.Type,
			Connected: e.Raw.IsConnected(),
		})
	}
	m.mu.RUnlock()
	body, _ := (&control.TransportStatusList{Transports: list}).Encode()
	_ = m.session.SendControl(control.SubtypeTransportStatus, body)
}

func insertByPriority(order []string, name string, priority int, entries map[string]*Entry) []string {
	pos := len(order)
	for i, n := range order {
		if entries[n].Priority < priority {
			pos = i
			break
		}
	}
	out := make([]string, 0, len(order)+1)
	out = append(out, order[:pos]...)
	out = append(out, name)
	out = append(out, order[pos:]...)
	return out
}

// IsConnected reports whether the Session has completed its handshake and
// at least one transport is live.
func (m *Manager) IsConnected() bool {
	return m.session.IsConnected()
}

// Stats aggregates counters across every transport.
func (m *Manager) Stats() transport.TransportStats {
	return m.session.Stats()
}

// ---- captcha notifications ----

// CaptchaNotifier is called when a transport reports that it needs fresh
// cookies (ErrCaptchaRequired or ErrLoginRequired). Wired to the IPC server
// by main.go.
type CaptchaNotifier func(transportName, url, reason string)

// SetCaptchaNotifier installs the callback.
func (m *Manager) SetCaptchaNotifier(n CaptchaNotifier) {
	m.mu.Lock()
	m.captchaNotifier = n
	m.mu.Unlock()
}

// NotifyCaptcha is called by transports (via ErrorNotifier) when they cannot
// proceed without external help. The local notifier (IPC to the app) gets
// every report. On the exit node there is usually no app, and the check
// has to be passed from the exit's address anyway, so the report also goes
// to the client over whichever carrier still reaches it.
func (m *Manager) NotifyCaptcha(name, url, reason string) {
	m.mu.RLock()
	n := m.captchaNotifier
	m.mu.RUnlock()
	if n != nil {
		n(name, url, reason)
	}
	if m.session.IsExit() {
		m.forwardAuth(name, url, reason)
	}
}

func (m *Manager) forwardAuth(name, url, reason string) {
	now := time.Now()
	m.mu.Lock()
	if m.authSent == nil {
		m.authSent = make(map[string]time.Time)
	}
	if now.Sub(m.authSent[name]) < authForwardInterval {
		m.mu.Unlock()
		return
	}
	m.authSent[name] = now
	m.mu.Unlock()

	body, _ := (&control.AuthRequiredPayload{Transport: name, URL: url, Reason: reason, Doc: m.entryURL(name)}).Encode()
	if err := m.SendControl(control.SubtypeAuthRequired, body); err != nil {
		// No client yet: let the transport's next report try again.
		utils.Debugf("[MANAGER] forward AuthRequired (%s): %v", name, err)
		m.mu.Lock()
		delete(m.authSent, name)
		m.mu.Unlock()
	}
}

// SetRemoteAuthNotifier installs the callback for AuthRequired reports from
// the exit node: the app must pass the check from the exit's address and
// answer with OfferCookies.
func (m *Manager) SetRemoteAuthNotifier(n CaptchaNotifier) {
	m.mu.Lock()
	m.remoteAuth = n
	m.mu.Unlock()
}

// OfferCookies sends a jar for one of the peer's transports (the answer to
// an AuthRequired report).
func (m *Manager) OfferCookies(name string, jar map[string]string) error {
	return m.OfferCookiesForDomain(name, "", jar)
}

func (m *Manager) OfferCookiesForDomain(name, domain string, jar map[string]string) error {
	if domain != "" {
		root, ok := yandexhosts.Root(domain)
		if !ok {
			return fmt.Errorf("unsupported verification cookie domain")
		}
		domain = root
	}
	// name comes from the exit's AuthRequired request. It is the exit's
	// name, not necessarily this side's entry; attaching a local document
	// URL here could reroute the answer to a different exit carrier.
	body, err := (&control.CookiesPayload{Transport: name, Domain: domain, Jar: jar, Reason: "solved"}).Encode()
	if err != nil {
		return err
	}
	return m.SendControl(control.SubtypeCookiesOffer, body)
}
