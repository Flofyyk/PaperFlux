package manager

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/control"
	ydocs "universal-bypass-tool/transport/yandexsession"
)

func cookieStoreForTest(t *testing.T, m *Manager, name, key string) *transport.CookieStore {
	t.Helper()
	s, err := transport.NewCookieStore(filepath.Join(t.TempDir(), "cookies.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UseCookieStore(s, name, key); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAcceptCookiesPreservesLoginAndPrefersFreshValues(t *testing.T) {
	m := newTestManager(t)
	p := &fakeCookieProvider{jar: map[string]string{"liveOnly": "live", "shared": "live"}}
	if err := m.Add("yandex", "yandex", &fakeTransport{}, 100, p); err != nil {
		t.Fatal(err)
	}
	store := cookieStoreForTest(t, m, "yandex", "doc")
	// A persisted account cookie may not be visible in the current HTTP jar.
	if err := store.Save("doc", map[string]string{"Session_id": "login", "shared": "stale", "spravka": "old"}); err != nil {
		t.Fatal(err)
	}
	offered := map[string]string{"spravka": "new", "newOnly": "fresh"}
	if err := m.AcceptCookies("yandex", offered); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Session_id": "login", "shared": "live", "liveOnly": "live", "spravka": "new", "newOnly": "fresh"}
	if got, _ := p.FetchCookies(); !maps.Equal(got, want) {
		t.Fatal("live cookies lost old auth or fresh values")
	}
	if !maps.Equal(store.Load("doc"), want) {
		t.Fatal("merged cookies not persisted")
	}
	if len(offered) != 2 || offered["spravka"] != "new" {
		t.Fatal("caller offer mutated")
	}
	reopened, err := transport.NewCookieStore(store.Path())
	if err != nil || !maps.Equal(reopened.Load("doc"), want) {
		t.Fatal("merged cookies not restored after restart")
	}
}

func TestEmptyCookieOfferDoesNotEraseLogin(t *testing.T) {
	m := newTestManager(t)
	p := &fakeCookieProvider{jar: map[string]string{"Session_id": "login"}}
	if err := m.Add("yandex", "yandex", &fakeTransport{}, 100, p); err != nil {
		t.Fatal(err)
	}
	store := cookieStoreForTest(t, m, "yandex", "doc")
	if err := m.AcceptCookies("yandex", map[string]string{"spravka": "pass"}); err != nil {
		t.Fatal(err)
	}
	before := store.Load("doc")
	if err := m.AcceptCookies("yandex", nil); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(store.Load("doc"), before) || p.applies != 1 {
		t.Fatal("empty offer erased/reapplied saved cookies")
	}
}

func TestCookieSubsetConfirmsOfferWithoutRepeatedReconnect(t *testing.T) {
	m := newTestManager(t)
	p := &fakeCookieProvider{jar: map[string]string{"Session_id": "login", "spravka": "pass"}}
	if err := m.Add("yandex", "yandex", &fakeTransport{}, 100, p); err != nil {
		t.Fatal(err)
	}
	doc := "https://disk.yandex.ru/i/test"
	m.SetURL("yandex", doc)
	for i := 0; i < 3; i++ {
		m.DispatchControl(control.SubtypeCookiesResponse, offer(t, "yandex", map[string]string{"spravka": "pass"}))
	}
	if p.applies != 0 {
		t.Fatal("unchanged partial response forced reconnect")
	}
	if m.MatchingCookieCarrier("yandex", doc, map[string]string{"spravka": "pass"}) != "yandex" {
		t.Fatal("retained login prevented successful confirmation")
	}
	for _, offered := range []map[string]string{nil, {"missing": ""}, {"spravka": "wrong"}} {
		if m.MatchingCookieCarrier("yandex", doc, offered) != "" {
			t.Fatal("missing or wrong cookie falsely confirmed")
		}
	}
}

func TestConcurrentCookieOffersPreserveAllUpdates(t *testing.T) {
	m := newTestManager(t)
	p := &fakeCookieProvider{jar: map[string]string{"Session_id": "login"}}
	if err := m.Add("yandex", "yandex", &fakeTransport{}, 100, p); err != nil {
		t.Fatal(err)
	}
	store := cookieStoreForTest(t, m, "yandex", "doc")
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := m.AcceptCookies("yandex", map[string]string{fmt.Sprintf("cookie%d", i): "value"}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	current, _ := p.FetchCookies()
	if len(current) != 25 || current["Session_id"] != "login" || !maps.Equal(current, store.Load("doc")) {
		t.Fatal("concurrent read/merge/save lost an offer")
	}
}

func TestCookieMergeNeverImportsAnotherDocument(t *testing.T) {
	m := newTestManager(t)
	p := &fakeCookieProvider{}
	if err := m.Add("first", "yandex", &fakeTransport{}, 100, p); err != nil {
		t.Fatal(err)
	}
	m.SetURL("first", "https://disk.yandex.ru/i/first")
	store := cookieStoreForTest(t, m, "first", "first-doc")
	other := map[string]string{"Session_id": "other-account", "spravka": "other-pass"}
	if err := store.Save("second-doc", other); err != nil {
		t.Fatal(err)
	}
	if err := m.AcceptCookies("first", map[string]string{"spravka": "first-pass"}); err != nil {
		t.Fatal(err)
	}
	jar, _ := p.FetchCookies()
	if len(jar) != 1 || jar["spravka"] != "first-pass" || !maps.Equal(store.Load("second-doc"), other) {
		t.Fatal("cookies crossed document boundaries")
	}
}

func TestRegionalCookieMergeKeepsAccountsAndLegacyUpdatesScoped(t *testing.T) {
	m := newTestManager(t)
	doc := "https://disk.yandex.ru/i/test"
	raw := ydocs.NewYandexDocsTransport(doc, transport.DefaultConfig())
	t.Cleanup(func() { _ = raw.Stop() })
	if err := m.Add("yandex", "yandex", raw, 100, raw); err != nil {
		t.Fatal(err)
	}
	m.SetURL("yandex", doc)
	store := cookieStoreForTest(t, m, "yandex", "doc")
	updates := []struct {
		domain string
		jar    map[string]string
	}{
		{"", map[string]string{"Session_id": "ru-account", "spravka": "ru-old"}},
		{"docs.yandex.kz", map[string]string{"Session_id": "kz-account", "spravka": "kz-old"}},
		{"yandex.kz", map[string]string{"spravka": "kz-new"}},
		{"yandex.ru", map[string]string{"spravka": "ru-new"}},
		{"", map[string]string{"legacy": "ru-only"}},
	}
	for _, update := range updates {
		if err := m.AcceptCookiesForDomain("yandex", update.domain, update.jar); err != nil {
			t.Fatal(err)
		}
	}
	for root, account := range map[string]string{"yandex.ru": "ru-account", "yandex.kz": "kz-account"} {
		jar, err := raw.FetchCookiesForDomain(root)
		if err != nil || jar["Session_id"] != account {
			t.Fatal("account lost or imported from another region")
		}
		key := "doc"
		if root == "yandex.kz" {
			key = domainStoreKey(key, root)
			if jar["spravka"] != "kz-new" || jar["legacy"] != "" {
				t.Fatal("primary update overwrote regional live jar")
			}
		}
		if store.Load(key)["Session_id"] != account {
			t.Fatal("regional account not persisted separately")
		}
	}
	if m.MatchingCookieCarrierForDomain("yandex", doc, "yandex.kz", map[string]string{"spravka": "kz-new"}) != "yandex" {
		t.Fatal("regional partial offer did not confirm")
	}
	if err := m.AcceptCookiesForDomain("yandex", "evil.invalid", map[string]string{"bad": "1"}); err == nil {
		t.Fatal("foreign cookie domain accepted")
	}
}

type rejectingCookieProvider struct{ fakeCookieProvider }

func (p *rejectingCookieProvider) ApplyCookies(map[string]string) error {
	return errors.New("verification rejected")
}

func TestRejectedCookieOfferDoesNotReplacePersistedLogin(t *testing.T) {
	m := newTestManager(t)
	p := &rejectingCookieProvider{fakeCookieProvider{jar: map[string]string{"Session_id": "login"}}}
	if err := m.Add("yandex", "yandex", &fakeTransport{}, 100, p); err != nil {
		t.Fatal(err)
	}
	store := cookieStoreForTest(t, m, "yandex", "doc")
	before := map[string]string{"Session_id": "login", "spravka": "previous"}
	if err := store.Save("doc", before); err != nil {
		t.Fatal(err)
	}
	if err := m.AcceptCookies("yandex", map[string]string{"spravka": "rejected"}); err == nil {
		t.Fatal("rejected offer reported as accepted")
	}
	if !maps.Equal(store.Load("doc"), before) {
		t.Fatal("rejected offer overwritten saved login")
	}
}

func TestShareableCookiesNeverExposeAccountLogin(t *testing.T) {
	jar := map[string]string{"spravka": "pass", "yandexuid": "uid"}
	for _, name := range []string{"Session_id", "sessionid2", "sessar", "sessguard", "L", "yandex_login", "lah", "mda2_beacon"} {
		jar[name] = "private"
	}
	got := shareableCookies(jar)
	if len(got) != 2 || got["spravka"] != "pass" || got["yandexuid"] != "uid" || len(jar) != 10 {
		t.Fatal("account login exposed or source jar mutated")
	}
}

func TestPeerCookieResponseSharesCheckWithoutReplacingClientAccount(t *testing.T) {
	exitProvider := &fakeCookieProvider{jar: map[string]string{"Session_id": "exit-login", "spravka": "server-pass", "peer-only": "shared"}}
	client, exit := connectedManagers(t, exitProvider)
	doc := "https://disk.yandex.ru/i/test"
	client.SetURL("yandex", doc)
	exit.SetURL("yandex", doc)
	clientProvider := &fakeCookieProvider{jar: map[string]string{"Session_id": "client-login", "spravka": "phone-pass"}}
	client.mu.Lock()
	client.entries["yandex"].Provider = clientProvider
	client.mu.Unlock()
	if err := client.RequestPeerCookies(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		jar, _ := clientProvider.FetchCookies()
		if jar["peer-only"] == "shared" {
			if jar["Session_id"] != "client-login" || jar["spravka"] != "phone-pass" {
				t.Fatal("exit account leaked or local login/check overwritten")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing shareable cookie not shared with peer")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPeerSnapshotCannotOverwriteFreshLocalCheckOrWakeLane(t *testing.T) {
	m := newTestManager(t)
	p := &fakeCookieProvider{jar: map[string]string{"Session_id": "local-login", "spravka": "fresh-local", "yandexuid": "local-uid"}}
	m.entries["yandex"] = &Entry{Name: "yandex", Provider: p, URL: "https://disk.yandex.ru/i/test"}
	for i := 0; i < 3; i++ {
		if err := m.acceptPeerCookiesForDomain("yandex", "", map[string]string{"Session_id": "remote-login", "spravka": "stale-remote", "yandexuid": "remote-uid"}); err != nil {
			t.Fatal(err)
		}
	}
	jar, _ := p.FetchCookies()
	if jar["Session_id"] != "local-login" || jar["spravka"] != "fresh-local" || jar["yandexuid"] != "local-uid" || p.applies != 0 {
		t.Fatal("background response changed local auth or restarted the carrier")
	}
	if err := m.AcceptCookies("yandex", map[string]string{"spravka": "new-browser-result"}); err != nil {
		t.Fatal(err)
	}
	jar, _ = p.FetchCookies()
	if jar["spravka"] != "new-browser-result" || p.applies != 1 {
		t.Fatal("explicit browser offer failed to replace an old local value")
	}
}
