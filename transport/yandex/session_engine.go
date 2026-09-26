package yandex

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ConnectSessionEngineIO shares the strict Engine.IO upgrade with the Session
// carrier, without copying PFS2 framing. No URL/token or response body is logged.
func ConnectSessionEngineIO(ctx context.Context, raw string, headers http.Header, dialer *websocket.Dialer) (*websocket.Conn, error) {
	poll, err := enginePollingURL(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid engine endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", poll, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid polling request")
	}
	req.Header = headers.Clone()
	req.Header.Del("Host")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("engine polling failed: %w", safeAuthError(err))
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65537))
	resp.Body.Close()
	if readErr != nil || len(body) > 65536 || resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid engine polling response (%d)", resp.StatusCode)
	}
	// Polling may carry several Engine.IO records; decode only the OPEN record.
	var open engineOpen
	for _, record := range strings.Split(string(body), "\x1e") {
		if strings.HasPrefix(record, "0{") {
			_ = json.Unmarshal([]byte(record[1:]), &open)
			break
		}
	}
	if open.SID == "" || len(open.SID) > 1024 {
		return nil, fmt.Errorf("engine sid missing")
	}
	cookieMap := map[string]string{}
	for _, c := range req.Cookies() {
		cookieMap[c.Name] = c.Value
	}
	for _, c := range resp.Cookies() {
		cookieMap[c.Name] = c.Value
	}
	wsHeaders := headers.Clone()
	wsHeaders.Del("Cookie")
	cookieReq := &http.Request{Header: wsHeaders}
	for name, value := range cookieMap {
		cookieReq.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	ws, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid engine endpoint")
	}
	q := ws.Query()
	q.Set("sid", open.SID)
	q.Set("transport", "websocket")
	ws.RawQuery = q.Encode()
	conn, response, err := dialer.DialContext(ctx, ws.String(), wsHeaders)
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("engine upgrade failed: %w", safeAuthError(err))
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	stopCancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopCancel()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err = conn.WriteMessage(websocket.TextMessage, []byte("2probe")); err != nil {
		return nil, err
	}
	for i := 0; i < 32; i++ {
		_, p, e := conn.ReadMessage()
		if e != nil {
			return nil, e
		}
		if string(p) == "2" {
			if e = conn.WriteMessage(websocket.TextMessage, []byte("3")); e != nil {
				return nil, e
			}
			continue
		}
		if string(p) != "3probe" {
			continue
		}
		if e = conn.WriteMessage(websocket.TextMessage, []byte("5")); e != nil {
			return nil, e
		}
		// The balancer commits the polling-to-WS upgrade asynchronously. Sending
		// Socket.IO authentication immediately after UPGRADE can race that commit.
		settle := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			settle.Stop()
			return nil, ctx.Err()
		case <-settle.C:
		}
		_ = conn.SetReadDeadline(time.Time{})
		_ = conn.SetWriteDeadline(time.Time{})
		success = true
		return conn, nil
	}
	return nil, fmt.Errorf("engine probe not confirmed")
}

func EditorAuthenticated(p []byte) bool { return isSuccessfulAuth(p) }
