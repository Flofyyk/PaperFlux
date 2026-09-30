package yandex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"testing"
)

// Opt-in integration probe. Never logs cookies or document URLs.
func TestLiveCaptchaProbe(t *testing.T) {
	doc := os.Getenv("PAPERFLUX_LIVE_DOC")
	path := os.Getenv("PAPERFLUX_LIVE_COOKIE_STORE")
	if doc == "" || path == "" {
		t.Skip("live probe not configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cookie store unavailable")
	}
	var buckets map[string]map[string]string
	if err := json.Unmarshal(data, &buckets); err != nil {
		t.Fatal("cookie store invalid")
	}
	jar, _ := cookiejar.New(nil)
	key := sha256.Sum256([]byte("vyandex\x00" + doc))
	bucket := buckets[hex.EncodeToString(key[:])]
	t.Logf("stored_cookies=%d", len(bucket))
	if len(bucket) > 0 {
		var cookies []*http.Cookie
		for name, value := range bucket {
			cookies = append(cookies, &http.Cookie{Name: name, Value: value, Domain: ".yandex.ru", Path: "/", Secure: true})
		}
		u, _ := url.Parse("https://disk.yandex.ru/")
		jar.SetCookies(u, cookies)
	}
	retpath, err := SolveChallenge(doc, jar, authUserAgent)
	if err != nil {
		t.Fatalf("captcha solver: %v", err)
	}
	t.Logf("captcha solver returned success, retpath_empty=%t", retpath == "")
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	_, _, err = fetchAuthPage(context.Background(), doc, client, func() error { return errCaptchaChallenge })
	if err != nil {
		t.Fatalf("document after solve: %v", err)
	}
}
