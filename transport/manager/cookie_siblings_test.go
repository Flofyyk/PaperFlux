package manager

import (
	"path/filepath"
	"testing"
	"time"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/control"
)

func TestConnectedCheckSharedOnlyWithBlockedSameProfileYandexRoot(t *testing.T) {
	m := newTestManager(t)
	store, err := transport.NewCookieStore(filepath.Join(t.TempDir(), "cookies.json"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCookieProvider{jar: map[string]string{"spravka": "passed", "yandexuid": "new-browser", "Session_id": "source-login", "unrelated": "private"}}
	if err := m.Add("source", "yandex", &fakeTransport{live: true}, 100, source); err != nil {
		t.Fatal(err)
	}
	m.SetURL("source", "https://disk.yandex.ru/i/source")
	providers := map[string]*fakeCookieProvider{}
	for _, fixture := range []struct {
		name, typ, doc string
		live           bool
	}{
		{"blocked", "yandex", "https://disk.yandex.ru/i/second", false},
		{"volga", "vyandex", "https://disk.yandex.ru/i/third", false},
		{"healthy", "yandex", "https://disk.yandex.ru/i/fourth", true},
		{"regional", "yandex", "https://disk.yandex.by/i/other", false},
		{"mail", "mailru", "https://cloud.mail.ru/public/test/doc", false},
	} {
		p := &fakeCookieProvider{jar: map[string]string{"spravka": "old", "yandexuid": "old-browser", "Session_id": "own-login"}}
		providers[fixture.name] = p
		if err := m.Add(fixture.name, fixture.typ, &fakeTransport{live: fixture.live}, 1, p); err != nil {
			t.Fatal(err)
		}
		m.SetURL(fixture.name, fixture.doc)
		if err := m.UseCookieStore(store, fixture.name, fixture.name); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range providers {
		p.applies = 0
	}
	m.ShareConnectedYandexCheck()
	m.ShareConnectedYandexCheck()
	for name, p := range providers {
		jar, _ := p.FetchCookies()
		changed := name == "blocked" || name == "volga"
		if changed {
			if p.applies != 1 || jar["spravka"] != "passed" || jar["yandexuid"] != "new-browser" || store.Load(name)["spravka"] != "passed" {
				t.Fatalf("Shared check not applied/persisted once for %s", name)
			}
		} else if p.applies != 0 || jar["spravka"] != "old" {
			t.Fatalf("Unrelated/healthy carrier %s changed", name)
		}
		if jar["Session_id"] != "own-login" || jar["unrelated"] != "" {
			t.Fatal("Account/private cookies crossed document boundary")
		}
	}
	other := newTestManager(t)
	foreign := &fakeCookieProvider{jar: map[string]string{"spravka": "foreign"}}
	if err := other.Add("other-profile", "yandex", &fakeTransport{}, 1, foreign); err != nil {
		t.Fatal(err)
	}
	other.SetURL("other-profile", "https://disk.yandex.ru/i/second")
	other.ShareConnectedYandexCheck()
	if foreign.applies != 0 {
		t.Fatal("Verification crossed profiles")
	}
}

func TestSiblingSharingProtectsFreshBrowserSubmission(t *testing.T) {
	m := newTestManager(t)
	for _, name := range []string{"source", "target"} {
		p := &fakeCookieProvider{jar: map[string]string{"spravka": "accepted", "yandexuid": "uid"}}
		if err := m.Add(name, "yandex", &fakeTransport{live: name == "source"}, 100, p); err != nil {
			t.Fatal(err)
		}
		m.SetURL(name, "https://disk.yandex.ru/i/"+name)
	}
	if err := m.AcceptCookies("target", map[string]string{"spravka": "new-browser-result"}); err != nil {
		t.Fatal(err)
	}
	m.ShareConnectedYandexCheck()
	jar, _ := m.FetchCookiesFor("target")
	if jar["spravka"] != "new-browser-result" {
		t.Fatal("Sibling overwrote a just-submitted result before reconnect")
	}
}

func TestNonceBoundVerificationRecoversWithoutNewCookieOffer(t *testing.T) {
	provider := &fakeCookieProvider{jar: map[string]string{"spravka": "already-passed", "Session_id": "private"}}
	client, exit := connectedManagers(t, provider)
	doc := "https://disk.yandex.ru/i/test-only"
	client.SetURL("yandex", doc)
	exit.SetURL("yandex", doc)
	proofs := make(chan *control.CookiesPayload, 4)
	client.session.SetControlHandler(func(sub control.Subtype, body []byte) {
		if sub == control.SubtypeCookiesResponse {
			if cp, err := control.DecodeCookies(body); err == nil && cp.Reason == "verified" {
				proofs <- cp
			}
		}
		client.DispatchControl(sub, body)
	})
	client.RequestCookieVerification("yandex", "current-request")
	client.RequestCookieVerification("yandex", "current-request")
	select {
	case proof := <-proofs:
		if proof.RequestID != "current-request" || proof.Doc != doc || len(proof.Jar) != 0 {
			t.Fatal("Verification was unscoped or leaked cookies")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Lost/restarted-exit confirmation did not recover")
	}
	select {
	case <-proofs:
		t.Fatal("Status query ignored rate limit")
	case <-time.After(100 * time.Millisecond):
	}
	bad, _ := (&control.CookiesPayload{Transport: "yandex", Doc: "https://disk.yandex.ru/i/other", Reason: "verify", RequestID: "other-request"}).Encode()
	if err := client.SendControl(control.SubtypeCookiesRequest, bad); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proofs:
		t.Fatal("Wrong document accepted")
	case <-time.After(100 * time.Millisecond):
	}
	if provider.applies != 0 {
		t.Fatal("Status query changed/polled provider cookies")
	}
}
