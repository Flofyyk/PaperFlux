package yandex

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// SolveChallenge shares the bounded, redacted PoW implementation with the
// upstream Session transport. Interactive challenges still require the user.
func SolveChallenge(url string, jar http.CookieJar, userAgent string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return solveCaptcha(ctx, url, jar, userAgent)
}

func FetchSessionAuthPage(ctx context.Context, raw string, client *http.Client) ([]byte, *http.Response, error) {
	return fetchAuthPage(ctx, raw, client, func() error { _, err := solveCaptcha(ctx, raw, client.Jar, authUserAgent); return err })
}
func AuthReason(err error) string {
	if errors.Is(err, errCaptchaChallenge) {
		return "smartcaptcha"
	}
	if errors.Is(err, errLoginRequired) {
		return "login"
	}
	return ""
}
