package tunnel

import (
	"net"
	"testing"
	"time"
	"universal-bypass-tool/transport"
)

type silentTransport struct{ *transport.BaseTransport }

func (s *silentTransport) Send([]byte) error { return nil }

func TestDialTCPTimeoutReturnsNilConnection(t *testing.T) {
	old := dialTimeout
	dialTimeout = 150 * time.Millisecond
	defer func() { dialTimeout = old }()
	raw := &silentTransport{transport.NewBaseTransport(transport.DefaultConfig())}
	tun := NewTCPTunnel(raw, false)
	defer tun.gvisorStack.Close()
	result := make(chan net.Conn, 1)
	go func() {
		conn, err := tun.DialTCP("192.0.2.1:443")
		if err == nil {
			t.Error("expected handshake timeout")
		}
		result <- conn
	}()
	select {
	case conn := <-result:
		if conn != nil {
			conn.Close()
			t.Fatal("typed nil returned as net.Conn")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unbounded TCP dial")
	}
}
