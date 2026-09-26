package yandex

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/profilesecure"
)

func TestVolgaRelayAuthorizationExpiry(t *testing.T) {
	for _, status := range []int{200, 204, 401, 403, 429, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			r := newRelayClient(&volgaAuth{Session: &http.Client{}}, DefaultVolgaConfig(), &VolgaStats{})
			defer r.Stop()
			r.httpClient.Transport = authRoundTripper(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: req}, nil
			})
			err := r.sendBatch([][]byte{[]byte("packet")})
			success := status == 200 || status == 204
			if (err == nil) != success {
				t.Fatalf("unexpected result: %v", err)
			}
			if r.authExpired.Load() != (status == 401 || status == 403) {
				t.Fatal("incorrect reauthorization signal")
			}
			if (r.stats.BytesSent.Load() > 0) != success {
				t.Fatal("failed request counted as delivered")
			}
		})
	}
}

func TestVolgaStopIdempotent(t *testing.T) {
	r := newRelayClient(&volgaAuth{Session: &http.Client{}}, DefaultVolgaConfig(), &VolgaStats{})
	r.Stop()
	r.Stop()
	if err := r.Send([]byte("packet")); err == nil {
		t.Fatal("send after stop accepted")
	}
	x := NewYandexVolgaTransport("https://disk.yandex.ru/i/test", transport.DefaultConfig())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = x.Stop() }()
	}
	wg.Wait()
	if x.IsConnected() {
		t.Fatal("stopped transport connected")
	}
	if err := x.Start(); err == nil {
		t.Fatal("stopped instance restarted")
	}
}

func TestVolgaAuthEndpoint(t *testing.T) {
	if _, err := volgaAuthRequest(context.Background(), "POST", "https://evil.invalid/", nil); err == nil {
		t.Fatal("foreign auth endpoint accepted")
	}
	if _, err := volgaAuthRequest(context.Background(), "POST", "https://volga.yandex.ru/auth/initial", nil); err != nil {
		t.Fatal(err)
	}
}

// Explicit opt-in: Volga inserts operations into a dedicated throwaway document.
func TestLiveVolgaSecureRoundTrip(t *testing.T) {
	doc := os.Getenv("PAPERFLUX_TEST_VOLGA_DOCUMENT")
	if doc == "" {
		t.Skip("requires a dedicated empty document")
	}
	var peers [2]*profilesecure.Transport
	for i := range peers {
		raw := NewYandexVolgaTransport(doc, transport.DefaultConfig())
		var err error
		peers[i], err = profilesecure.New(raw, "901", "local-test-only-token-32-characters-long", "vyandex:"+doc, i == 1)
		if err != nil {
			t.Fatal(err)
		}
		if err = peers[i].Start(); err != nil {
			t.Fatal(err)
		}
		defer peers[i].Stop()
	}
	deadline := time.Now().Add(80 * time.Second)
	for !(peers[0].IsConnected() && peers[1].IsConnected()) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !peers[0].IsConnected() || !peers[1].IsConnected() {
		t.Fatal("protected peers not ready; inspect authorization diagnostics")
	}
	got := make(chan []byte, 1)
	peers[1].Receive(func(b []byte) {
		select {
		case got <- bytes.Clone(b):
		default:
		}
	})
	want := []byte("paperflux protected Volga smoke test")
	if err := peers[0].Send(want); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, want) {
			t.Fatal("payload mismatch")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("payload timeout")
	}
}
