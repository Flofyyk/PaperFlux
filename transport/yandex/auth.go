package yandex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxAuthHTML = 2 << 20
const authUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:153.0) Gecko/20100101 Firefox/153.0"

var errLoginRequired = errors.New("YANDEX_LOGIN_REQUIRED: откройте документ и подтвердите доступ")
var errVolgaDocument = errors.New("YANDEX_VOLGA_REQUIRED: документ использует Volga, а не старый редактор")

func safeAuthError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// Never follow a document/challenge to a third-party or cleartext endpoint.
func captchaRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" ||
		(u.Hostname() != "disk.yandex.ru" && u.Hostname() != "docs.yandex.ru") {
		return nil, fmt.Errorf("unsupported Yandex authentication endpoint")
	}
	return http.NewRequestWithContext(ctx, method, u.String(), body)
}

// Cookies are supplied through an app-private/admin-owned file, never through
// a profile link, command line, public log or public repository.
func loadAuthCookies(jar http.CookieJar) error {
	path := os.Getenv("PAPERFLUX_YANDEX_COOKIES")
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot open private Yandex cookie file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil || len(b) > 64*1024 {
		return fmt.Errorf("invalid Yandex cookie file size")
	}
	var hosts map[string]map[string]string
	if json.Unmarshal(b, &hosts) != nil {
		return fmt.Errorf("invalid Yandex cookie file")
	}
	for _, host := range []string{"disk.yandex.ru", "docs.yandex.ru"} {
		u, _ := url.Parse("https://" + host + "/")
		var cookies []*http.Cookie
		for name, value := range hosts[host] {
			c := &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, Domain: ".yandex.ru"}
			if err := c.Valid(); err != nil {
				return fmt.Errorf("invalid Yandex cookie")
			}
			cookies = append(cookies, c)
		}
		jar.SetCookies(u, cookies)
	}
	return nil
}

func (t *YandexDocsTransport) authDocument(rawURL string) ([]byte, *http.Response, http.CookieJar, error) {
	t.authMu.Lock()
	if t.authCtx == nil {
		t.authCtx, t.authCancel = context.WithCancel(context.Background())
	}
	ctx := t.authCtx
	if t.cookieJar == nil {
		t.cookieJar, _ = cookiejar.New(nil)
	}
	jar := t.cookieJar
	t.authMu.Unlock()
	if err := loadAuthCookies(jar); err != nil {
		return nil, nil, jar, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := &http.Client{Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, resp, err := fetchAuthPage(ctx, rawURL, client, func() error { _, e := solveCaptcha(ctx, rawURL, jar, authUserAgent); return e })
	if errors.Is(err, errCaptchaChallenge) || errors.Is(err, errLoginRequired) {
		t.captchaUntil.Store(time.Now().Add(10 * time.Minute).UnixNano())
	}
	return body, resp, jar, err
}

func fetchAuthPage(ctx context.Context, original string, client *http.Client, solve func() error) ([]byte, *http.Response, error) {
	current := original
	solved := false
	for redirects := 0; redirects < 12; redirects++ {
		req, err := captchaRequest(ctx, http.MethodGet, current, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("User-Agent", authUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, safeAuthError(err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthHTML+1))
		resp.Body.Close()
		if err != nil {
			return nil, nil, safeAuthError(err)
		}
		if len(body) > maxAuthHTML {
			return nil, nil, fmt.Errorf("document page exceeds size limit")
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			u, err := resp.Location()
			if err != nil {
				return nil, nil, fmt.Errorf("invalid document redirect")
			}
			if u.Hostname() == "passport.yandex.ru" || u.Hostname() == "passport.yandex.com" {
				return nil, nil, errLoginRequired
			}
			if strings.Contains(u.Path, "showcaptcha") {
				if strings.Contains(u.Path, "showcaptchafast") && !solved {
					solved = true
					if err := solve(); err != nil {
						return nil, nil, fmt.Errorf("%w: automatic verification failed", errCaptchaChallenge)
					}
					current = original
					continue
				}
				return nil, nil, fmt.Errorf("%w: interactive verification required", errCaptchaChallenge)
			}
			current = u.String()
			continue
		}
		if resp.Header.Get("X-Yandex-Captcha") != "" || strings.Contains(req.URL.Path, "showcaptcha") {
			return nil, nil, errCaptchaChallenge
		}
		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("document request returned HTTP %d", resp.StatusCode)
		}
		return body, resp, nil
	}
	return nil, nil, fmt.Errorf("too many document redirects")
}
