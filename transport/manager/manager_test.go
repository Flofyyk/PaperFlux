package manager

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/control"
)

// fakeTransport is a minimal in-process Transport.
type fakeTransport struct {
	mu   sync.Mutex
	cb   func([]byte)
	live bool
}

func (f *fakeTransport) Start() error            { f.mu.Lock(); f.live = true; f.mu.Unlock(); return nil }
func (f *fakeTransport) Stop() error             { f.mu.Lock(); f.live = false; f.mu.Unlock(); return nil }
func (f *fakeTransport) Send(data []byte) error  { return nil }
func (f *fakeTransport) Receive(cb func([]byte)) { f.mu.Lock(); f.cb = cb; f.mu.Unlock() }
func (f *fakeTransport) IsConnected() bool       { f.mu.Lock(); defer f.mu.Unlock(); return f.live }
func (f *fakeTransport) Stats() transport.TransportStats {
	return transport.TransportStats{Connected: f.live}
}

func TestManagerAddRemoveTransport(t *testing.T) {
	sess, err := transport.NewSession(transport.PeerParameters{
		Capabilities:  control.CapabilityIPv4 | control.CapabilityTCP,
		MaxPacketSize: 1500,
	}, false)
	if err != nil {
		t.Fatal(err)
	}

	m := New(sess, nil, "test-secret-long-enough", "test-ctx")
	a := &fakeTransport{}
	b := &fakeTransport{}
	if err := m.Add("first", "fake", a, 100, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("second", "fake", b, 50, nil); err != nil {
		t.Fatal(err)
	}
	got := m.Transports()
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("priority order wrong: %v", got)
	}
	if err := m.Remove("first"); err != nil {
		t.Fatal(err)
	}
	got = m.Transports()
	if len(got) != 1 || got[0] != "second" {
		t.Fatalf("after remove: %v", got)
	}
	_ = sess.Stop()
}

func TestManagerCookieExchangerPerTransport(t *testing.T) {
	sess, err := transport.NewSession(transport.PeerParameters{
		Capabilities:  control.CapabilityIPv4 | control.CapabilityTCP,
		MaxPacketSize: 1500,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	m := New(sess, nil, "test-secret-long-enough", "test-ctx")

	provider := &fakeCookieProvider{jar: map[string]string{"a": "1"}}
	if err := m.Add("yandex", "yandex", &fakeTransport{}, 100, provider); err != nil {
		t.Fatal(err)
	}
	jar, err := m.FetchCookiesFor("yandex")
	if err != nil {
		t.Fatal(err)
	}
	if jar["a"] != "1" {
		t.Fatalf("fetch = %v", jar)
	}
	if err := m.ApplyCookiesFor("yandex", map[string]string{"b": "2"}); err != nil {
		t.Fatal(err)
	}
	jar, _ = m.FetchCookiesFor("yandex")
	if jar["b"] != "2" {
		t.Fatalf("apply failed: %v", jar)
	}

	// Transport without cookies must fail cleanly.
	if err := m.Add("direct", "direct", &fakeTransport{}, 50, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.FetchCookiesFor("direct"); err == nil {
		t.Fatal("expected error for cookie-less transport")
	}
	_ = sess.Stop()
}

type fakeCookieProvider struct {
	mu      sync.Mutex
	jar     map[string]string
	applies int
}

func (f *fakeCookieProvider) FetchCookies() (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.jar))
	for k, v := range f.jar {
		out[k] = v
	}
	return out, nil
}

func (f *fakeCookieProvider) ApplyCookies(jar map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	f.jar = make(map[string]string, len(jar))
	for k, v := range jar {
		f.jar[k] = v
	}
	return nil
}

func TestManagerIgnoresUnchangedCookieResponse(t *testing.T) {
	m := newTestManager(t)
	provider := &fakeCookieProvider{jar: map[string]string{"session": "current"}}
	if err := m.Add("yandex-1", "yandex", &fakeTransport{}, 100, provider); err != nil {
		t.Fatal(err)
	}
	m.SetURL("yandex-1", "https://disk.yandex.ru/i/first")
	body, err := (&control.CookiesPayload{Transport: "yandex-1", Doc: "https://disk.yandex.ru/i/first", Jar: map[string]string{"session": "current"}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	m.DispatchControl(control.SubtypeCookiesResponse, body)
	if provider.applies != 0 {
		t.Fatalf("unchanged jar reapplied %d times", provider.applies)
	}
	body, err = (&control.CookiesPayload{Transport: "yandex-1", Doc: "https://disk.yandex.ru/i/first", Jar: map[string]string{"session": "refreshed"}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	m.DispatchControl(control.SubtypeCookiesResponse, body)
	if provider.applies != 1 {
		t.Fatalf("refreshed jar applied %d times", provider.applies)
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	sess, err := transport.NewSession(transport.PeerParameters{
		Capabilities:  control.CapabilityIPv4 | control.CapabilityTCP,
		MaxPacketSize: 1500,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Stop() })
	return New(sess, nil, "test-secret-long-enough", "test-ctx")
}

func offer(t *testing.T, name string, jar map[string]string) []byte {
	t.Helper()
	body, err := (&control.CookiesPayload{Transport: name, Jar: jar}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Cookie offers reach the transport they name (or, from older peers that
// name none, the highest-priority cookie transport) and are persisted.
func TestManagerRoutesCookiesByTransport(t *testing.T) {
	m := newTestManager(t)
	yandex := &fakeCookieProvider{}
	mailru := &fakeCookieProvider{}
	if err := m.Add("yandex", "yandex", &fakeTransport{}, 100, yandex); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("mailru", "mailru", &fakeTransport{}, 50, mailru); err != nil {
		t.Fatal(err)
	}
	store, err := transport.NewCookieStore(filepath.Join(t.TempDir(), "cookies.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{"yandex": "doc-y", "mailru": "doc-m"} {
		if err := m.UseCookieStore(store, name, key); err != nil {
			t.Fatal(err)
		}
	}

	m.DispatchControl(control.SubtypeCookiesOffer, offer(t, "mailru", map[string]string{"m": "1"}))
	m.DispatchControl(control.SubtypeCookiesResponse, offer(t, "", map[string]string{"y": "2"}))
	if jar, _ := mailru.FetchCookies(); jar["m"] != "1" {
		t.Fatalf("mailru jar = %v", jar)
	}
	if jar, _ := yandex.FetchCookies(); jar["y"] != "2" || jar["m"] != "" {
		t.Fatalf("yandex jar = %v", jar)
	}

	// A restarted process replays what was persisted.
	next := newTestManager(t)
	replayed := &fakeCookieProvider{}
	if err := next.Add("mailru", "mailru", &fakeTransport{}, 50, replayed); err != nil {
		t.Fatal(err)
	}
	reopened, err := transport.NewCookieStore(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := next.UseCookieStore(reopened, "mailru", "doc-m"); err != nil {
		t.Fatal(err)
	}
	if jar, _ := replayed.FetchCookies(); jar["m"] != "1" {
		t.Fatalf("replayed jar = %v", jar)
	}
}

func TestManagerMatchesRenamedCookieCarriersByDocument(t *testing.T) {
	m := newTestManager(t)
	first := &fakeCookieProvider{}
	second := &fakeCookieProvider{}
	if err := m.Add("primary", "yandex", &fakeTransport{}, 100, first); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("backup", "yandex", &fakeTransport{}, 50, second); err != nil {
		t.Fatal(err)
	}
	m.SetURL("primary", "https://disk.yandex.ru/i/first")
	m.SetURL("backup", "https://disk.yandex.ru/i/second")
	body, err := (&control.CookiesPayload{
		Transport: "yandex-2", Doc: "https://disk.yandex.ru/i/second",
		Jar: map[string]string{"session": "second"},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	m.DispatchControl(control.SubtypeCookiesOffer, body)
	if jar, _ := second.FetchCookies(); jar["session"] != "second" {
		t.Fatalf("second carrier did not receive cookies: %v", jar)
	}
	if jar, _ := first.FetchCookies(); len(jar) != 0 {
		t.Fatalf("cookies leaked to first carrier: %v", jar)
	}
	if got := m.MatchingCookieCarrier("yandex-2", "https://disk.yandex.ru/i/second", map[string]string{"session": "second"}); got != "backup" {
		t.Fatalf("applied cookie carrier = %q, want backup", got)
	}
	if got := m.MatchingCookieCarrier("yandex-2", "https://disk.yandex.ru/i/first", map[string]string{"session": "second"}); got != "" {
		t.Fatalf("wrong-document response matched %q", got)
	}

	// An old peer that sends a renamed carrier without a document is
	// ambiguous when there are two of that type: reject rather than guess.
	if got := m.cookieTransport("yandex-3", ""); got != "" {
		t.Fatalf("ambiguous carrier resolved to %q", got)
	}
	if got := m.cookieTransport("primary", ""); got != "primary" {
		t.Fatalf("exact name resolved to %q", got)
	}
	if got := m.cookieTransport("primary", "https://disk.yandex.ru/i/second"); got != "backup" {
		t.Fatalf("swapped document resolved to %q", got)
	}
	if got := m.cookieTransport("primary", "https://disk.yandex.ru/i/unknown"); got != "" {
		t.Fatalf("unknown document resolved to %q", got)
	}
}

type countingTransport struct {
	fakeTransport
	stops int
}

func (c *countingTransport) Stop() error {
	c.stops++
	return c.fakeTransport.Stop()
}

func TestManagerStopsCarrierOnce(t *testing.T) {
	params := transport.PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP, MaxPacketSize: 1500}
	sess, err := transport.NewSession(params, true)
	if err != nil {
		t.Fatal(err)
	}
	m := New(sess, nil, "test-secret-long-enough", "test-ctx")
	raw := &countingTransport{}
	if err := sess.AddTransport("carrier", raw, "test-secret-long-enough", "test-ctx", 100); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("carrier", "yandex", raw, 100, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if raw.stops != 1 {
		t.Fatalf("carrier Stop called %d times, want 1", raw.stops)
	}
}

func TestManagerRemoveStopsCarrierOnce(t *testing.T) {
	params := transport.PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP, MaxPacketSize: 1500}
	sess, err := transport.NewSession(params, true)
	if err != nil {
		t.Fatal(err)
	}
	m := New(sess, nil, "test-secret-long-enough", "test-ctx")
	raw := &countingTransport{}
	if err := sess.AddTransport("carrier", raw, "test-secret-long-enough", "test-ctx", 100); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("carrier", "yandex", raw, 100, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove("carrier"); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if raw.stops != 1 {
		t.Fatalf("carrier Stop called %d times, want 1", raw.stops)
	}
}

func TestManagerDispatchControlForwardsUnknownSubtypes(t *testing.T) {
	m := newTestManager(t)
	got := make(chan control.Subtype, 1)
	m.SetControlCallback(func(sub control.Subtype, payload []byte) { got <- sub })
	m.DispatchControl(control.Subtype(0x7f), nil)
	select {
	case sub := <-got:
		if sub != 0x7f {
			t.Fatalf("forwarded subtype = %v", sub)
		}
	case <-time.After(time.Second):
		t.Fatal("callback not invoked")
	}
}
