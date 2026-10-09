package mailru

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
	"universal-bypass-tool/transport"
)

const verificationPage = `<html><script>var WAF_CHECK_RESPONSE_STATUS = 429; url.searchParams.set('key', SparkMD5.hash(hash429));</script></html>`
const verificationURL = "https://cloud.mail.ru/waf?hash429=hello&redirect=%2Fapi%2Fv4%2Fr7%2Fedit&sign=test-sign"

type verificationRoundTripper func(*http.Request) (*http.Response, error)

func (f verificationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func verificationResponse(req *http.Request, status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestMailruVerificationPreservesPOSTAndCookies(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	var saved map[string]string
	tr.SetCookieSaver(func(jar map[string]string) error { saved = jar; return nil })
	posts, confirmations, pageGets := 0, 0, 0
	var firstBody string
	client := &http.Client{Jar: tr.cookieJar, Transport: verificationRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("User-Agent") != mailruUserAgent {
			t.Fatal("verification changed user agent")
		}
		if req.URL.Path == "/api/v4/r7/edit" {
			if req.Method != http.MethodPost {
				t.Fatal("followed confirmation into API by GET")
			}
			data, _ := io.ReadAll(req.Body)
			posts++
			if posts == 1 {
				firstBody = string(data)
				return verificationResponse(req, 302, "", http.Header{"Location": {verificationURL}, "Set-Cookie": {"hitw429=hit; Path=/; Secure"}}), nil
			}
			if string(data) != firstBody || req.Header.Get("X-Api-Version") != "4" || req.Header.Get("Content-Type") != "application/json" {
				t.Fatal("original POST body or headers lost")
			}
			cookie, err := req.Cookie("solution429")
			if err != nil || cookie.Value != "verified" {
				t.Fatal("verification cookie missing on POST")
			}
			return verificationResponse(req, 200, testMetadata, nil), nil
		}
		if req.URL.Path != "/waf" || req.Method != http.MethodGet {
			t.Fatal("unexpected provider request")
		}
		q := req.URL.Query()
		if q.Get("key") == "" {
			pageGets++
			return verificationResponse(req, 200, verificationPage, nil), nil
		}
		confirmations++
		if q.Get("key") != "5d41402abc4b2a76b9719d911017c592" || q.Get("hash429") != "hello" || q.Get("sign") != "test-sign" || req.Header.Get("Referer") != verificationURL {
			t.Fatal("provider confirmation instruction not preserved")
		}
		return verificationResponse(req, 302, "", http.Header{"Location": {"https://cloud.mail.ru/api/v4/r7/edit"}, "Set-Cookie": {"solution429=verified; Path=/; Secure", "Mpop=private-account; Path=/; Secure"}}), nil
	})}
	for i := 0; i < 2; i++ {
		if _, err := tr.fetchDocInfoFrom(client, "https://cloud.mail.ru/api/v4/r7/edit", "test/doc"); err != nil {
			t.Fatal(err)
		}
	}
	if posts != 3 || confirmations != 1 || pageGets != 1 || !reflect.DeepEqual(saved, map[string]string{"solution429": "verified", "hitw429": "hit"}) {
		t.Fatal("unbounded confirmation or incorrect persisted cookies")
	}
	shared, _ := tr.FetchCookies()
	if shared["solution429"] != "" || shared["hitw429"] != "" || shared["Mpop"] != "" {
		t.Fatal("local verification/account cookies shared with peer")
	}
	if err := tr.ApplyCookies(map[string]string{"solution429": "other-address", "anonymous": "offered"}); err != nil {
		t.Fatal(err)
	}
	root, _ := url.Parse("https://cloud.mail.ru/")
	for _, cookie := range tr.cookieJar.Cookies(root) {
		if cookie.Name == "solution429" && cookie.Value != "verified" {
			t.Fatal("peer replaced local verification")
		}
	}
}

func TestMailruVerificationFailureIsBounded(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	requests, confirmations := 0, 0
	client := &http.Client{Jar: tr.cookieJar, Transport: verificationRoundTripper(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Path == "/api/v4/r7/edit" {
			return verificationResponse(req, 302, "", http.Header{"Location": {verificationURL}}), nil
		}
		if req.URL.Query().Get("key") != "" {
			confirmations++
			return verificationResponse(req, 302, "", http.Header{"Location": {"/api/v4/r7/edit"}, "Set-Cookie": {"solution429=ineffective; Path=/; Secure"}}), nil
		}
		return verificationResponse(req, 200, verificationPage, nil), nil
	})}
	_, err := tr.fetchDocInfoFrom(client, "https://cloud.mail.ru/api/v4/r7/edit", "test/doc")
	var limited *mailruVerificationError
	if !errors.As(err, &limited) || confirmations != 1 || requests != 5 {
		t.Fatalf("failure did not stop after one confirmation: requests=%d confirmations=%d", requests, confirmations)
	}
	_, err = tr.fetchDocInfoFrom(client, "https://cloud.mail.ru/api/v4/r7/edit", "test/doc")
	if !errors.As(err, &limited) || requests != 5 {
		t.Fatal("cooldown issued another network request")
	}
}

func TestMailruVerificationRejectsUnknownInstructions(t *testing.T) {
	for _, raw := range []string{
		"http://cloud.mail.ru/waf?hash429=hello&redirect=/&sign=s",
		"https://cloud.mail.ru.attacker.invalid/waf?hash429=hello&redirect=/&sign=s",
		"https://private@cloud.mail.ru/waf?hash429=hello&redirect=/&sign=s",
		"https://cloud.mail.ru:444/waf?hash429=hello&redirect=/&sign=s",
		"https://cloud.mail.ru/waf?hash429=hello&hash429=other&redirect=/&sign=s",
		"https://cloud.mail.ru/waf?hash429=hello&redirect=/",
	} {
		page, _ := url.Parse(raw)
		if _, err := mailru429Confirmation(page, []byte(verificationPage)); err == nil || strings.Contains(err.Error(), "hello") {
			t.Fatal("unsafe verification URL accepted or disclosed")
		}
	}
	page, _ := url.Parse(verificationURL)
	if _, err := mailru429Confirmation(page, []byte(`<script>var WAF_CHECK_RESPONSE_STATUS = 429; unknown()</script>`)); err == nil {
		t.Fatal("unrecognized JavaScript accepted")
	}
}

func TestMailruReal429AndUnknownChallengeCooldown(t *testing.T) {
	for _, status := range []int{200, 429} {
		tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
		client := &http.Client{Jar: tr.cookieJar, Transport: verificationRoundTripper(func(req *http.Request) (*http.Response, error) {
			return verificationResponse(req, status, `<script>var WAF_CHECK_RESPONSE_STATUS = 429; changed();</script>`, http.Header{"Retry-After": {"180"}}), nil
		})}
		_, err := tr.fetchDocInfoFrom(client, "https://cloud.mail.ru/api/v4/r7/edit", "test/doc")
		var limited *mailruVerificationError
		if !errors.As(err, &limited) || limited.RetryAfter != 180*time.Second {
			t.Fatal("provider retry-after ignored")
		}
	}
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	for _, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute} {
		if got := tr.deferMailruVerification("").(*mailruVerificationError).RetryAfter; got != want {
			t.Fatal("failed verification backoff did not increase")
		}
	}
	deadline := time.Now().Add(20 * time.Minute).UTC().Truncate(time.Second)
	if got := tr.deferMailruVerification(deadline.Format(http.TimeFormat)).(*mailruVerificationError).RetryAfter; got < 19*time.Minute {
		t.Fatal("retry-after date ignored")
	}
}

func TestMailruVerificationCancellationAndRedirectGuard(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	_ = tr.BaseTransport.Start()
	confirmationStarted := make(chan struct{})
	client := &http.Client{Jar: tr.cookieJar, Transport: verificationRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v4/r7/edit" {
			return verificationResponse(req, 302, "", http.Header{"Location": {verificationURL}}), nil
		}
		if req.URL.Query().Get("key") == "" {
			return verificationResponse(req, 200, verificationPage, nil), nil
		}
		close(confirmationStarted)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	exited := make(chan error, 1)
	go func() {
		_, err := tr.fetchDocInfoFrom(client, "https://cloud.mail.ru/api/v4/r7/edit", "test/doc")
		exited <- err
	}()
	<-confirmationStarted
	_ = tr.Stop()
	select {
	case err := <-exited:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled verification did not preserve lifecycle cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel verification")
	}
	tr = NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/private-token", 302)
	}))
	defer server.Close()
	if _, err := tr.fetchDocInfoFrom(server.Client(), server.URL, "test/doc"); err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatal("off-origin redirect permitted or private URL disclosed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	page, _ := url.Parse(verificationURL)
	if err := tr.confirmMailru429(ctx, &http.Client{Jar: tr.cookieJar}, page, []byte(verificationPage)); err == nil {
		t.Fatal("cancelled confirmation succeeded")
	}
}
