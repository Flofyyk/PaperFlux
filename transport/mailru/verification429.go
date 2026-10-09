package mailru

import (
	"context"
	"crypto/md5" // The provider's browser confirmation protocol requires MD5.
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var mailru429Status = regexp.MustCompile(`\bWAF_CHECK_RESPONSE_STATUS\s*=\s*429\s*;`)
var mailru429Key = regexp.MustCompile(`url\.searchParams\.(?:set|append)\(\s*["']key["']\s*,\s*SparkMD5\.hash\(hash429\)\s*\)`)

func isMailru429Page(body []byte) bool {
	return mailru429Status.Match(body)
}

// Recognize one known provider instruction; never evaluate received JavaScript.
func mailru429Confirmation(page *url.URL, body []byte) (*url.URL, error) {
	if page == nil || page.Scheme != "https" || page.Host != "cloud.mail.ru" || page.User != nil || page.Fragment != "" || !isMailru429Page(body) || !mailru429Key.Match(body) {
		return nil, fmt.Errorf("Mail.ru browser verification unavailable")
	}
	query, err := url.ParseQuery(page.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("Mail.ru browser verification unavailable")
	}
	for _, name := range []string{"hash429", "redirect", "sign"} {
		if len(query[name]) != 1 || len(query.Get(name)) == 0 || len(query.Get(name)) > 8192 {
			return nil, fmt.Errorf("Mail.ru browser verification unavailable")
		}
	}
	confirmed := *page
	query.Set("key", fmt.Sprintf("%x", md5.Sum([]byte(query.Get("hash429")))))
	confirmed.RawQuery = query.Encode()
	return &confirmed, nil
}

func (t *MailruDocsTransport) confirmMailru429(ctx context.Context, client *http.Client, page *url.URL, body []byte) error {
	confirmed, err := mailru429Confirmation(page, body)
	if err != nil || client.Jar == nil {
		return fmt.Errorf("Mail.ru browser verification unavailable")
	}
	confirmationClient := *client
	// Collect the provider's Set-Cookie on the confirmation response and stop.
	// Its Location may be the metadata API, which requires our original POST.
	confirmationClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, confirmed.String(), nil)
	if err != nil {
		return fmt.Errorf("Mail.ru browser verification unavailable")
	}
	req.Header.Set("User-Agent", mailruUserAgent)
	req.Header.Set("Referer", page.String())
	resp, err := confirmationClient.Do(req)
	if err != nil {
		return fmt.Errorf("Mail.ru browser verification failed")
	}
	confirmationBody, err := readMailruMetadataResponse(resp)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 || isMailru429Page(confirmationBody) {
		return fmt.Errorf("Mail.ru browser verification failed")
	}
	root, _ := url.Parse("https://cloud.mail.ru/")
	service := make(map[string]string)
	for _, cookie := range client.Jar.Cookies(root) {
		if cookie.Name == "solution429" || cookie.Name == "hitw429" {
			service[cookie.Name] = cookie.Value
		}
	}
	if service["solution429"] == "" {
		return fmt.Errorf("Mail.ru browser verification failed")
	}
	// ApplyCookies can replace the jar concurrently while verification is in
	// flight. Preserve this address's freshly verified state in the current jar.
	t.RestoreVerificationCookies(service)
	t.jarMu.RLock()
	save := t.cookieSaver
	t.jarMu.RUnlock()
	if save != nil {
		if err := save(service); err != nil {
			return fmt.Errorf("Mail.ru verification cookies could not be saved")
		}
	}
	return nil
}

// The retry scheduler may continue running, but no HTTP request is issued during
// this transport's cooldown. A failed verification is attempted only once per
// metadata fetch, not on every short reconnect tick.
type mailruVerificationError struct{ RetryAfter time.Duration }

func (e *mailruVerificationError) Error() string {
	return fmt.Sprintf("Mail.ru browser verification limited; retry in %d seconds", int(e.RetryAfter.Seconds()+0.999))
}

func (t *MailruDocsTransport) deferMailruVerification(retryAfter string) error {
	t.verificationFailures++
	shift := t.verificationFailures - 1
	if shift > 4 {
		shift = 4
	}
	delay := time.Minute * time.Duration(1<<shift)
	if delay > 15*time.Minute {
		delay = 15 * time.Minute
	}
	if seconds, err := strconv.ParseInt(strings.TrimSpace(retryAfter), 10, 64); err == nil && seconds > 0 && seconds <= int64((365*24*time.Hour)/time.Second) {
		if duration := time.Duration(seconds) * time.Second; duration > delay {
			delay = duration
		}
	} else if deadline, err := http.ParseTime(retryAfter); err == nil && time.Until(deadline) > delay {
		delay = time.Until(deadline)
	}
	t.verificationRetryAt = time.Now().Add(delay)
	return &mailruVerificationError{RetryAfter: delay}
}

// SetCookieSaver installs the profile's persistent store before Start. Only
// service verification cookies produced here are passed to it; no reconnect is
// triggered by saving a cookie that is already in the HTTP client's jar.
func (t *MailruDocsTransport) SetCookieSaver(save func(map[string]string) error) {
	t.jarMu.Lock()
	t.cookieSaver = save
	t.jarMu.Unlock()
}

// Verification cookies belong to the address that completed the challenge.
// Restore them only from this profile's local store, never from its VPN peer.
func (t *MailruDocsTransport) RestoreVerificationCookies(values map[string]string) {
	root, _ := url.Parse("https://cloud.mail.ru/")
	var cookies []*http.Cookie
	for _, name := range []string{"solution429", "hitw429"} {
		if value := values[name]; value != "" {
			cookies = append(cookies, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true})
		}
	}
	t.jarMu.Lock()
	t.cookieJar.SetCookies(root, cookies)
	t.jarMu.Unlock()
}
