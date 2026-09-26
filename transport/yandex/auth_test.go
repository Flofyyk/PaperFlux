package yandex

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"universal-bypass-tool/transport"
)

type authRoundTripper func(*http.Request) (*http.Response, error)

func (f authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCaptchaRetryOnce(t *testing.T) {
	for _, success := range []bool{true, false} {
		calls, solves := 0, 0
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: authRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			status, loc := 302, "/showcaptchafast?secret=private"
			if success && calls > 1 {
				status = 200
				loc = ""
			}
			return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{loc}}, Body: io.NopCloser(strings.NewReader("page")), Request: r}, nil
		})}
		_, _, err := fetchAuthPage(context.Background(), "https://docs.yandex.ru/edit/test", client, func() error { solves++; return nil })
		if solves != 1 || calls != 2 {
			t.Fatalf("unbounded retry: %d/%d", solves, calls)
		}
		if success && err != nil {
			t.Fatal(err)
		}
		if !success && !errors.Is(err, errCaptchaChallenge) {
			t.Fatalf("challenge lost: %v", err)
		}
	}
}

func TestAuthRejectsForeignHostsAndStops(t *testing.T) {
	for _, raw := range []string{"http://docs.yandex.ru/", "https://docs.yandex.ru.evil.invalid/", "https://user:pass@docs.yandex.ru/", "https://127.0.0.1/", "https://docs.yandex.ru:8443/"} {
		if _, err := captchaRequest(context.Background(), "GET", raw, nil); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	x := NewYandexDocsTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	_ = x.Stop()
	_, _, _, err := x.authDocument(x.url)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop did not cancel bootstrap: %v", err)
	}
	uerr := &url.Error{Op: "GET", URL: "https://docs.yandex.ru/?token=secret", Err: context.Canceled}
	if strings.Contains(safeAuthError(uerr).Error(), "secret") {
		t.Fatal("secret logged")
	}
}

func TestCaptchaWorkBounds(t *testing.T) {
	if !captchaCheckComplexity(make([]byte, 32), 256) {
		t.Fatal("full zero hash rejected")
	}
	if captchaCheckComplexity(make([]byte, 32), 257) {
		t.Fatal("invalid complexity accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if nonce, _ := solveCaptchaPoW(ctx, "aa", 1); nonce != "" {
		t.Fatal("cancel ignored")
	}
	if nonce, _ := solveCaptchaPoW(context.Background(), "aa", 25); nonce != "" {
		t.Fatal("work budget ignored")
	}
}
