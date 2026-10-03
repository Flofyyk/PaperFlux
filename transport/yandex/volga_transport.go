package yandex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/yandexhosts"
)

// Volga writes operations to the shared document. It is an explicit provider,
// never an automatic fallback on an existing PaperFlux document.
type YandexVolgaTransport struct {
	*transport.BaseTransport
	docURL   string
	config   VolgaConfig
	stats    *VolgaStats
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	relay    *relayClient
	ws       *wsListener
	started  bool
	stopped  bool
	jar      http.CookieJar
	wake     chan struct{}
	notifier func(error, string, string, string)
}

func NewYandexVolgaTransport(docURL string, cfg transport.TransportConfig) *YandexVolgaTransport {
	ctx, cancel := context.WithCancel(context.Background())
	jar, _ := cookiejar.New(nil)
	return &YandexVolgaTransport{BaseTransport: transport.NewBaseTransport(cfg), docURL: docURL, config: DefaultVolgaConfig(), stats: &VolgaStats{}, ctx: ctx, cancel: cancel, jar: jar, wake: make(chan struct{}, 1)}
}

func (t *YandexVolgaTransport) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return fmt.Errorf("Volga transport already stopped")
	}
	if t.started {
		return nil
	}
	if _, err := captchaRequest(t.ctx, http.MethodGet, t.docURL, nil); err != nil {
		return err
	}
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}
	t.started = true
	go t.supervise()
	return nil
}

func (t *YandexVolgaTransport) Stop() error {
	t.cancel()
	t.mu.Lock()
	t.stopped = true
	w, r := t.ws, t.relay
	t.mu.Unlock()
	if w != nil {
		w.Stop()
	}
	if r != nil {
		r.cancel()
	}
	return t.BaseTransport.Stop()
}

func (t *YandexVolgaTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.IsRunning() && t.ws != nil && t.ws.connected.Load() && t.relay != nil && !t.relay.auth.expired.Load()
}

func (t *YandexVolgaTransport) Send(data []byte) error {
	t.mu.Lock()
	r, w := t.relay, t.ws
	t.mu.Unlock()
	if t.ctx.Err() != nil || r == nil || w == nil || !w.connected.Load() || r.auth.expired.Load() {
		return fmt.Errorf("Volga channel not ready")
	}
	return r.Send(data)
}

func (t *YandexVolgaTransport) Stats() transport.TransportStats {
	s := t.BaseTransport.Stats()
	s.Connected = t.IsConnected()
	s.BytesSent = t.stats.BytesSent.Load()
	s.BytesReceived = t.stats.BytesReceived.Load()
	s.PacketsSent = t.stats.PacketsSent.Load()
	s.PacketsRecv = t.stats.PacketsRecv.Load()
	s.WriteFailures = t.stats.HTTPReqsFailed.Load()
	s.ExpiredDrops = t.stats.QueueDrops.Load()
	s.RetryQueued = t.stats.RetryQueued.Load()
	s.QueuePackets = uint64(max(int64(0), t.stats.QueuedPackets.Load()))
	s.QueueBytes = uint64(max(int64(0), t.stats.QueuedBytes.Load()))
	s.QueueWaits = t.stats.QueueWaits.Load()
	s.QueueTimeouts = t.stats.QueueTimeouts.Load()
	return s
}

func (t *YandexVolgaTransport) QueueLoad() float64 {
	return min(1, float64(t.stats.QueuedPackets.Load())/float64(max(1, t.config.QueueSize)))
}
func (t *YandexVolgaTransport) LaneHealth() transport.LaneHealth {
	return transport.LaneHealth{Connected: t.IsConnected(), QueueLoad: t.QueueLoad(), WriteFailures: t.stats.HTTPReqsFailed.Load()}
}

func (t *YandexVolgaTransport) supervise() {
	jar := t.jar
	delay := 2 * time.Second
	for t.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(t.ctx, 60*time.Second)
		auth, err := authorizeWithJar(ctx, t.docURL, jar)
		cancel()
		if err == nil && t.ctx.Err() == nil {
			r := newRelayClient(auth, t.config, t.stats)
			w := newWSListener(auth, t.config, t.stats, r, t.CallReceive)
			w.authorizeFn = func(parent context.Context) (*volgaAuth, error) {
				ctx, cancel := context.WithTimeout(parent, 60*time.Second)
				defer cancel()
				fresh, err := authorizeWithJar(ctx, t.docURL, jar)
				if errors.Is(err, errCaptchaChallenge) || errors.Is(err, errLoginRequired) {
					t.mu.Lock()
					notify := t.notifier
					t.mu.Unlock()
					if notify != nil && parent.Err() == nil {
						notify(err, "vyandex", t.docURL, AuthReason(err))
					}
				}
				return fresh, err
			}
			t.mu.Lock()
			if t.stopped {
				t.mu.Unlock()
				r.Stop()
				w.Stop()
				return
			}
			t.relay, t.ws = r, w
			r.Start()
			w.Start()
			t.mu.Unlock()
			log.Printf("[PAPERFLUX] Volga authorized; waiting for protected peer")
			started, missing := time.Now(), time.Now()
			var detector stalledTraffic
			lastData, lastReceived := t.stats.DataQueued.Load(), t.stats.DataReceived.Load()
			lastObserve := time.Now()
			tick := time.NewTicker(time.Second)
		wait:
			for {
				select {
				case <-t.ctx.Done():
					break wait
				case <-t.wake:
					break wait
				case <-tick.C:
				}
				if w.connected.Load() {
					missing = time.Now()
				}
				if r.auth.expired.Load() || time.Since(missing) > 30*time.Second {
					w.RequestReconnect()
					missing = time.Now()
				}
				if time.Since(lastObserve) >= 5*time.Second {
					data, received := t.stats.DataQueued.Load(), t.stats.DataReceived.Load()
					if detector.Observe(data-lastData, received-lastReceived) {
						w.RequestReconnect()
					}
					lastData, lastReceived, lastObserve = data, received, time.Now()
				}
			}
			tick.Stop()
			w.Stop()
			r.Stop()
			t.mu.Lock()
			t.relay = nil
			t.ws = nil
			t.mu.Unlock()
			if time.Since(started) > time.Minute {
				delay = 2 * time.Second
			}
		}
		if t.ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("[PAPERFLUX] Volga authorization failed: %v", safeAuthError(err))
			if errors.Is(err, errVolgaEditorUnavailable) {
				// A cookie update cannot turn a preview page into an editor. Avoid
				// hammering Yandex while the other document channels remain usable.
				t.RecordReconnect()
				select {
				case <-t.ctx.Done():
					return
				case <-time.After(5 * time.Minute):
				}
				continue
			}
			if errors.Is(err, errCaptchaChallenge) || errors.Is(err, errLoginRequired) {
				delay = 30 * time.Second
				t.mu.Lock()
				notify := t.notifier
				t.mu.Unlock()
				if notify != nil {
					notify(err, "vyandex", t.docURL, AuthReason(err))
				}
			}
		}
		t.RecordReconnect()
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(delay):
		case <-t.wake:
		}
		if delay < time.Minute {
			delay = min(delay*2, time.Minute)
		}
	}
}

func (t *YandexVolgaTransport) SetErrorNotifier(fn func(error, string, string, string)) {
	t.mu.Lock()
	t.notifier = fn
	t.mu.Unlock()
}
func (t *YandexVolgaTransport) FetchCookies() (map[string]string, error) {
	u, _ := url.Parse("https://disk.yandex.ru/")
	out := map[string]string{}
	for _, c := range t.jar.Cookies(u) {
		out[c.Name] = c.Value
	}
	return out, nil
}
func (t *YandexVolgaTransport) ApplyCookies(values map[string]string) error {
	return t.ApplyCookiesForDomain("yandex.ru", values)
}
func (t *YandexVolgaTransport) FetchCookiesForDomain(domain string) (map[string]string, error) {
	root, ok := yandexhosts.Root(domain)
	if !ok {
		return nil, fmt.Errorf("unsupported verification cookie domain")
	}
	u, _ := url.Parse("https://" + root + "/")
	out := map[string]string{}
	for _, c := range t.jar.Cookies(u) {
		out[c.Name] = c.Value
	}
	return out, nil
}
func (t *YandexVolgaTransport) ApplyCookiesForDomain(domain string, values map[string]string) error {
	root, ok := yandexhosts.Root(domain)
	if !ok {
		return fmt.Errorf("unsupported verification cookie domain")
	}
	u, _ := url.Parse("https://" + root + "/")
	cookies := make([]*http.Cookie, 0, len(values))
	if len(values) > 128 {
		return fmt.Errorf("too many verification cookies")
	}
	for n, v := range values {
		c := &http.Cookie{Name: n, Value: v, Domain: "." + root, Path: "/", Secure: true}
		if c.Valid() != nil || len(v) > 8192 {
			return fmt.Errorf("invalid verification cookie")
		}
		cookies = append(cookies, c)
	}
	t.jar.SetCookies(u, cookies)
	select {
	case t.wake <- struct{}{}:
	default:
	}
	return nil
}

func volgaAuthRequest(ctx context.Context, method, raw string, body io.Reader) (*http.Request, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() != "volga.yandex.ru" || u.Port() != "" || u.User != nil {
		return nil, fmt.Errorf("invalid Volga authentication endpoint")
	}
	return http.NewRequestWithContext(ctx, method, u.String(), body)
}
