package mailru

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"universal-bypass-tool/transport"
)

const testMetadata = `{"api":"https://docs.datacloudmail.ru","token":"test-jwt","document":{"key":"test-key","fileType":"docx","url":"https://example.invalid/test-file","title":"Test","permissions":{"edit":true}},"editorConfig":{"callbackUrl":"https://example.invalid/callback","user":{"id":"test-user"}}}`

func TestMetadataValidation(t *testing.T) {
	info, err := parseMailruDocInfo([]byte(testMetadata))
	if err != nil || info.WsURL != "wss://docs.datacloudmail.ru/doc/test-key/c/?EIO=4&transport=websocket" {
		t.Fatalf("valid metadata rejected: %v", err)
	}
	for _, item := range []struct{ old, replacement string }{
		{`"edit":true`, `"edit":false`},
		{`"edit":true`, `"edit":"true"`},
		{`https://docs.datacloudmail.ru`, `https://docs.datacloudmail.ru.attacker.invalid`},
		{`https://docs.datacloudmail.ru`, `http://docs.datacloudmail.ru`},
		{`https://docs.datacloudmail.ru`, `https://private@docs.datacloudmail.ru`},
		{`https://docs.datacloudmail.ru`, `https://docs.datacloudmail.ru?private-token`},
		{`"test-jwt"`, `""`},
		{`"test-key"`, `"../../test"`},
		{`"test-user"`, `""`},
	} {
		if _, err := parseMailruDocInfo([]byte(strings.Replace(testMetadata, item.old, item.replacement, 1))); err == nil {
			t.Errorf("accepted invalid %s", item.old)
		}
	}
}

func TestMetadataCookiesSurviveRequests(t *testing.T) {
	tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 {
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "test-cookie" {
				t.Error("lost previous API cookie")
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-cookie", Path: "/"})
		fmt.Fprint(w, testMetadata)
	}))
	defer server.Close()
	client := &http.Client{Jar: tr.cookieJar, Timeout: time.Second}
	for i := 0; i < 2; i++ {
		if _, err := tr.fetchDocInfoFrom(client, server.URL, "test/doc"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMetadataBoundedErrorsAndStop(t *testing.T) {
	for _, mode := range []string{"oversized", "badjson", "denied", "stop"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(started)
				switch mode {
				case "oversized":
					fmt.Fprint(w, strings.Repeat("x", (2<<20)+1))
				case "badjson":
					fmt.Fprint(w, `{"private-token":`)
				case "denied":
					w.WriteHeader(403)
					fmt.Fprint(w, "private-token")
				case "stop":
					select {
					case <-r.Context().Done():
					case <-time.After(time.Second):
					}
				}
			}))
			defer server.Close()
			tr := NewMailruDocsTransport("test/doc", transport.DefaultConfig())
			_ = tr.BaseTransport.Start()
			done := make(chan error, 1)
			go func() {
				_, err := tr.fetchDocInfoFrom(&http.Client{Jar: tr.cookieJar, Timeout: time.Second}, server.URL, "test/doc")
				done <- err
			}()
			<-started
			if mode == "stop" {
				_ = tr.Stop()
			}
			select {
			case err := <-done:
				if err == nil || strings.Contains(err.Error(), "private-token") {
					t.Fatal("unsafe or missing error")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("request did not terminate")
			}
			_ = tr.Stop()
		})
	}
	var fixture map[string]interface{}
	if json.Unmarshal([]byte(testMetadata), &fixture) != nil {
		t.Fatal("fixture invalid")
	}
}
