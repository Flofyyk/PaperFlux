package yandex

import (
	"net/url"
	"sync"
	"testing"
	"universal-bypass-tool/transport"
)

func TestRegionalCookiesStayScopedAndPreserveOriginalJar(t *testing.T) {
	tr := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	if err := tr.ApplyCookies(map[string]string{"spravka": "ru"}); err != nil {
		t.Fatal(err)
	}
	if err := tr.ApplyCookiesForDomain("docs.yandex.kz", map[string]string{"spravka": "kz"}); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"docs.yandex.ru": "ru", "docs.yandex.kz": "kz"} {
		u, _ := url.Parse("https://" + host + "/")
		got := ""
		for _, cookie := range tr.cookieJar.Cookies(u) {
			if cookie.Name == "spravka" {
				got = cookie.Value
			}
		}
		if got != want {
			t.Fatalf("%s cookie = %q, want %q", host, got, want)
		}
	}
	if err := tr.ApplyCookiesForDomain("evil.invalid", map[string]string{"spravka": "bad"}); err == nil {
		t.Fatal("foreign cookies accepted")
	}
	var wg sync.WaitGroup
	for _, root := range []string{"yandex.by", "yandex.uz", "yandex.com.tr"} {
		wg.Add(1)
		go func(root string) {
			defer wg.Done()
			if err := tr.ApplyCookiesForDomain(root, map[string]string{"regional": root}); err != nil {
				t.Error(err)
			}
		}(root)
	}
	wg.Wait()
	for _, root := range []string{"yandex.by", "yandex.uz", "yandex.com.tr"} {
		cookies, err := tr.FetchCookiesForDomain(root)
		if err != nil || cookies["regional"] != root {
			t.Fatalf("regional cookie update lost for %s", root)
		}
	}
}
