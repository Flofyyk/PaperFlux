package manager

import (
	"path/filepath"
	"testing"
	"universal-bypass-tool/transport"
)

type verificationCookieProvider struct {
	fakeCookieProvider
	save     func(map[string]string) error
	restored map[string]string
}

func (p *verificationCookieProvider) SetCookieSaver(save func(map[string]string) error) {
	p.save = save
}
func (p *verificationCookieProvider) RestoreVerificationCookies(jar map[string]string) {
	p.restored = map[string]string{"solution429": jar["solution429"], "hitw429": jar["hitw429"]}
}

func TestProviderVerificationCookiesPersistAndRestoreLocally(t *testing.T) {
	store, err := transport.NewCookieStore(filepath.Join(t.TempDir(), "cookies.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t)
	provider := &verificationCookieProvider{}
	if err := m.Add("mailru", "mailru", &fakeTransport{}, 100, provider); err != nil {
		t.Fatal(err)
	}
	if err := store.Save("profile/doc", map[string]string{"old": "retained"}); err != nil {
		t.Fatal(err)
	}
	if err := m.UseCookieStore(store, "mailru", "profile/doc"); err != nil {
		t.Fatal(err)
	}
	if provider.save == nil {
		t.Fatal("automatic verification not attached to store")
	}
	if err := provider.save(map[string]string{"solution429": "local-solution", "hitw429": "local-hit"}); err != nil {
		t.Fatal(err)
	}
	reopened, err := transport.NewCookieStore(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Load("profile/doc")["old"] != "retained" {
		t.Fatal("automatic verification erased existing cookies")
	}
	next := newTestManager(t)
	restored := &verificationCookieProvider{}
	if err := next.Add("mailru", "mailru", &fakeTransport{}, 100, restored); err != nil {
		t.Fatal(err)
	}
	if err := next.UseCookieStore(reopened, "mailru", "profile/doc"); err != nil {
		t.Fatal(err)
	}
	if restored.restored["solution429"] != "local-solution" || restored.restored["hitw429"] != "local-hit" {
		t.Fatal("local cookies not restored after reopen")
	}
	if err := next.acceptPeerCookiesForDomain("mailru", "", map[string]string{"solution429": "peer-solution", "hitw429": "peer-hit", "peer": "value"}); err != nil {
		t.Fatal(err)
	}
	if reopened.Load("profile/doc")["solution429"] != "local-solution" {
		t.Fatal("peer replaced persisted address-bound verification")
	}
}
