package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/authrelay"
	"universal-bypass-tool/transport/control"
)

import "bufio"

// Opt-in private fixture supplied in memory. No profile secret or document
// address is printed; this does not send document editing operations.
func TestLiveVerificationService(t *testing.T) {
	raw := os.Getenv("PAPERFLUX_LIVE_PROFILE")
	if raw == "" {
		t.Skip("private live profile required")
	}
	var p struct {
		ID       string `json:"id"`
		Token    string `json:"token"`
		Server   string `json:"server"`
		Document string `json:"documentUrl"`
	}
	if json.Unmarshal([]byte(raw), &p) != nil {
		t.Fatal("invalid fixture")
	}
	params := transport.PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP | control.CapabilityUDP, MaxPacketSize: 65000}
	s, err := transport.NewSession(params, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	dc := transport.DefaultDirectConfig()
	dc.DialAddr = p.Server + ":24007"
	dc.AuthSecret = p.Token
	dc.ReadTimeout = 45 * time.Second
	if err = s.AddTransport("auth-service", transport.NewDirectTransport(transport.DefaultConfig(), dc), p.Token, "paperflux-session-v1/profile/"+p.ID, 1000); err != nil {
		t.Fatal("cannot add encrypted carrier")
	}
	s.SetControlOnly("auth-service")
	relay := authrelay.New(false, s.SendControl)
	defer relay.Close()
	s.SetControlHandler(relay.Handle)
	if err = s.Start(); err != nil {
		t.Fatal("encrypted service handshake failed")
	}
	if s.HasDataPath() {
		t.Fatal("verification service incorrectly enabled VPN path")
	}
	u, err := url.Parse(p.Document)
	if err != nil || u.Hostname() != "disk.yandex.ru" {
		t.Fatal("invalid test document")
	}
	conn, err := relay.Dial("disk.yandex.ru:443")
	if err != nil {
		t.Fatal("remote HTTPS stream failed")
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "disk.yandex.ru", MinVersion: tls.VersionTLS12})
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err = tlsConn.Handshake(); err != nil {
		t.Fatal("remote TLS handshake failed")
	}
	request, _ := http.NewRequest("GET", u.String(), nil)
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("Connection", "close")
	if err = request.Write(tlsConn); err != nil {
		t.Fatal("remote HTTP request failed")
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), request)
	if err != nil {
		t.Fatal("remote HTTP response failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	t.Logf("Encrypted service verified; HTTPS response via VPS: %d; normal VPN path remains disabled", response.StatusCode)
}
