package manager

import (
	"path/filepath"
	"testing"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/control"
	ydocs "universal-bypass-tool/transport/yandexsession"
)

func TestRegionalCookiesPersistWithoutCrossDomainOverwrite(t *testing.T) {
	store, err := transport.NewCookieStore(filepath.Join(t.TempDir(), "private.json"))
	if err != nil {
		t.Fatal(err)
	}
	newManager := func() (*Manager, *ydocs.YandexDocsTransport) {
		session, err := transport.NewSession(transport.PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP, MaxPacketSize: 1500}, false)
		if err != nil {
			t.Fatal(err)
		}
		m := New(session, nil, "local-test-secret", "test")
		raw := ydocs.NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
		if err := m.Add("yandex-1", "yandex", raw, 100, raw); err != nil {
			t.Fatal(err)
		}
		m.SetURL("yandex-1", "https://disk.yandex.ru/i/test")
		if err := m.UseCookieStore(store, "yandex-1", "profile/doc"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = raw.Stop(); _ = session.Stop() })
		return m, raw
	}
	m, _ := newManager()
	if err := m.AcceptCookies("yandex-1", map[string]string{"spravka": "ru"}); err != nil {
		t.Fatal(err)
	}
	if err := m.AcceptCookiesForDomain("yandex-1", "yandex.ru", map[string]string{"spravka": "fresh-ru"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Load("profile/doc")["spravka"]; got != "fresh-ru" {
		t.Fatal("primary-domain cookies no longer seed profiles")
	}
	if err := m.AcceptCookiesForDomain("yandex-1", "docs.yandex.kz", map[string]string{"spravka": "kz"}); err != nil {
		t.Fatal(err)
	}
	if err := m.AcceptCookiesForDomain("yandex-1", "evil.invalid", map[string]string{"spravka": "bad"}); err == nil {
		t.Fatal("foreign domain accepted")
	}
	restored, _ := newManager()
	for domain, want := range map[string]string{"yandex.ru": "fresh-ru", "yandex.kz": "kz"} {
		got, err := restored.fetchCookiesForDomain("yandex-1", domain)
		if err != nil || got["spravka"] != want {
			t.Fatalf("persisted %s cookie lost/overwritten", domain)
		}
	}
	if got := restored.MatchingCookieCarrierForDomain("yandex-1", "https://disk.yandex.ru/i/test", "yandex.kz", map[string]string{"spravka": "kz"}); got != "yandex-1" {
		t.Fatal("regional response not matched")
	}
}
