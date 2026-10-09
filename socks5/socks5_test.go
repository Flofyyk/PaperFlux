package socks5

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestFragmentedAndPipelinedHandshake(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		server, client := net.Pipe()
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		result := make(chan string, 1)
		go func() {
			defer server.Close()
			address, err := readConnectRequest(server)
			if err != nil {
				result <- "error: " + err.Error()
				return
			}
			result <- address
		}()
		// Long and short domain requests are equally valid. TCP fragments may
		// split the length and body independently; extra application data stays unread.
		greeting := []byte{5, 2, 2, 0}
		request := append([]byte{5, 1, 0, 3, 3}, []byte("a.b")...)
		request = append(request, 1, 187)
		go func() {
			if fragmented {
				for _, b := range greeting {
					_, _ = client.Write([]byte{b})
				}
			} else {
				_, _ = client.Write(greeting)
			}
		}()
		reply := make([]byte, 2)
		if _, err := io.ReadFull(client, reply); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reply, []byte{5, 0}) {
			t.Fatal(reply)
		}
		if fragmented {
			for _, b := range request {
				if _, err := client.Write([]byte{b}); err != nil {
					t.Fatal(err)
				}
			}
		} else {
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
		}
		if got := <-result; got != "a.b:443" {
			t.Fatal(got)
		}
		client.Close()
	}
}

func TestRejectedSocksRequestsDoNotPanicOrDial(t *testing.T) {
	for _, request := range [][]byte{
		{5, 3, 0, 1},    // UDP associate unsupported
		{5, 1, 0, 4},    // IPv6 unsupported
		{5, 1, 0, 3, 0}, // empty domain
		{4, 1, 0, 1},    // wrong version
	} {
		server, client := net.Pipe()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		done := make(chan error, 1)
		go func() { defer server.Close(); _, err := readConnectRequest(server); done <- err }()
		_, _ = client.Write([]byte{5, 1, 0})
		ack := make([]byte, 2)
		_, _ = io.ReadFull(client, ack)
		_, _ = client.Write(request)
		rejection := make([]byte, 10)
		if _, err := io.ReadFull(client, rejection); err != nil {
			t.Fatal(err)
		}
		if rejection[1] == 0 {
			t.Fatal("unsupported request was accepted")
		}
		if err := <-done; err == nil {
			t.Fatal("expected error")
		}
		client.Close()
	}
}

func TestTruncatedDomainIsSafe(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { defer server.Close(); _, err := readConnectRequest(server); done <- err }()
	_, _ = client.Write([]byte{5, 1, 0})
	ack := make([]byte, 2)
	_, _ = io.ReadFull(client, ack)
	_, _ = client.Write([]byte{5, 1, 0, 3, 255, 'x'})
	client.Close()
	if err := <-done; err == nil {
		t.Fatal("truncated request accepted")
	}
}

type testDialer func(string) (net.Conn, error)

func (f testDialer) DialTCP(addr string) (net.Conn, error) { return f(addr) }

func TestConnectRelaysPipelinedData(t *testing.T) {
	server, client := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	proxy := NewSOCKS5Server("127.0.0.1:1080", testDialer(func(addr string) (net.Conn, error) {
		if addr != "192.0.2.7:443" {
			t.Errorf("target: %s", addr)
		}
		proxySide, echoSide := net.Pipe()
		go func() {
			defer echoSide.Close()
			data := make([]byte, 4)
			if _, err := io.ReadFull(echoSide, data); err == nil {
				_, _ = echoSide.Write(data)
			}
		}()
		return proxySide, nil
	}))
	done := make(chan struct{})
	go func() { proxy.handleConnection(server); close(done) }()
	_, _ = client.Write([]byte{5, 1, 0})
	ack := make([]byte, 2)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = client.Write([]byte{5, 1, 0, 1, 192, 0, 2, 7, 1, 187, 'p', 'i', 'n', 'g'}) }()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatal(reply)
	}
	body := make([]byte, 4)
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatal(err)
	}
	if string(body) != "ping" {
		t.Fatal(string(body))
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not shut down")
	}
}

func TestUnsupportedAuthenticationIsRejected(t *testing.T) {
	server, client := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { defer server.Close(); _, err := readConnectRequest(server); done <- err }()
	_, _ = client.Write([]byte{5, 1, 2})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, []byte{5, 255}) {
		t.Fatal(reply)
	}
	if err := <-done; err == nil {
		t.Fatal("expected rejection")
	}
	client.Close()
}

func TestOccupiedPortNeverSignalsReady(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	proxy := NewSOCKS5Server(listener.Addr().String(), nil)
	if err := proxy.Start(); err == nil {
		t.Fatal("occupied port was accepted")
	}
	select {
	case <-proxy.Ready():
		t.Fatal("failed listener signaled ready")
	default:
	}
}
