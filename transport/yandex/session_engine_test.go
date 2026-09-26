package yandex

import (
	"context"
	"encoding/base64"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionEngineUpgradeIncludesSIDAndCookies(t *testing.T) {
	errors := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("transport") == "polling" {
			http.SetCookie(w, &http.Cookie{Name: "poll", Value: "fresh"})
			_, _ = w.Write([]byte("0{\"sid\":\"private-test-sid\"}\x1e2"))
			return
		}
		if r.URL.Query().Get("sid") != "private-test-sid" {
			errors <- "sid missing"
			http.Error(w, "bad", 400)
			return
		}
		if c, e := r.Cookie("poll"); e != nil || c.Value != "fresh" {
			errors <- "poll cookie missing"
		}
		if c, e := r.Cookie("existing"); e != nil || c.Value != "kept" {
			errors <- "existing cookie missing"
		}
		c, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		_, p, e := c.ReadMessage()
		if e != nil || string(p) != "2probe" {
			errors <- "probe missing"
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, []byte("3probe"))
		_, p, e = c.ReadMessage()
		if e != nil || string(p) != "5" {
			errors <- "upgrade missing"
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, []byte("ready"))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := ConnectSessionEngineIO(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/?transport=websocket&EIO=4", http.Header{"Cookie": []string{"existing=kept; poll=stale"}}, &websocket.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, p, e := conn.ReadMessage()
	if e != nil || string(p) != "ready" {
		t.Fatal("upgrade incomplete")
	}
	select {
	case problem := <-errors:
		t.Fatal(problem)
	default:
	}
}

func TestCaptchaFormUsesChallengeOrigin(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte(`{"uniqueKey":"test","pow":{"prefix":"aa","complexity":0}}`))
	html := `window.__SSR_DATA__ = JSON.parse(atob("` + data + `")); <form id="tmgrdfrend-form" action="/check?x=1&amp;y=2">`
	_, action, err := parseCaptchaHTML(html, "https://disk.yandex.ru/showcaptchafast")
	if err != nil || action != "https://disk.yandex.ru/check?x=1&y=2" {
		t.Fatalf("wrong origin: %s %v", action, err)
	}
	for _, target := range []string{"https://evil.example/check", "//evil.example/check", "http://disk.yandex.ru/check"} {
		bad := strings.Replace(html, "/check?x=1&amp;y=2", target, 1)
		if _, _, e := parseCaptchaHTML(bad, "https://disk.yandex.ru/showcaptchafast"); e == nil {
			t.Fatal("unsafe form accepted")
		}
	}
}
