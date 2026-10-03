package authrelay

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
	"universal-bypass-tool/transport/control"
)

func TestAllowedTargets(t *testing.T) {
	for _, a := range []string{"disk.yandex.ru:443", "docs.yandex.kz:443", "passport.yandex.by:443", "docs.yandex.uz:443", "docs.yandex.com.tr:443", "smartcaptcha.yandexcloud.net:443", "yastatic.net:443"} {
		if !AllowedAddress(a) {
			t.Fatal(a)
		}
	}
	for _, a := range []string{"127.0.0.1:443", "169.254.169.254:443", "disk.yandex.ru:80", "disk.yandex.ru.evil.org:443", "docs.yandex.kz.evil.org:443", "example.com:443", "[::1]:443"} {
		if AllowedAddress(a) {
			t.Fatal(a)
		}
	}
}
func TestVerificationDNSRejectsPrivateAddresses(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "fc00::1", "2001:db8::1"} {
		if publicIP(net.ParseIP(raw)) {
			t.Fatal("private/reserved IP accepted", raw)
		}
	}
	for _, raw := range []string{"77.88.8.8", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIP(net.ParseIP(raw)) {
			t.Fatal("public IP rejected", raw)
		}
	}
}
func TestRelayStreamAndBackpressure(t *testing.T) {
	var a, b *Relay
	a = New(false, func(k control.Subtype, p []byte) error { go b.Handle(k, p); return nil })
	b = New(true, func(k control.Subtype, p []byte) error { go a.Handle(k, p); return nil })
	defer a.Close()
	defer b.Close()
	b.dial = func(string) (net.Conn, error) {
		x, y := net.Pipe()
		go func() { defer y.Close(); _, _ = io.Copy(y, y) }()
		return x, nil
	}
	c, err := a.Dial("disk.yandex.ru:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	want := bytes.Repeat([]byte("bounded verification stream"), 50000)
	done := make(chan error, 1)
	go func() { _, e := c.Write(want); done <- e }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("reordered or missing bytes")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := a.Dial("example.org:443"); err == nil {
		t.Fatal("general proxy permitted")
	}
}
