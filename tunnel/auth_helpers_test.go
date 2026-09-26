package tunnel

import (
	"net"
	"sync"
	"testing"
	"universal-bypass-tool/transport"
)

type pairedTransport struct {
	mu   sync.RWMutex
	peer *pairedTransport
	cb   func([]byte)
}

func newTransportPair() (*pairedTransport, *pairedTransport) {
	a, b := &pairedTransport{}, &pairedTransport{}
	a.peer, b.peer = b, a
	return a, b
}

func (p *pairedTransport) Start() error { return nil }
func (p *pairedTransport) Stop() error  { return nil }
func (p *pairedTransport) Send(data []byte) error {
	p.peer.mu.RLock()
	cb := p.peer.cb
	p.peer.mu.RUnlock()
	if cb != nil {
		cb(append([]byte(nil), data...))
	}
	return nil
}
func (p *pairedTransport) Receive(cb func([]byte)) {
	p.mu.Lock()
	p.cb = cb
	p.mu.Unlock()
}
func (p *pairedTransport) IsConnected() bool               { return true }
func (p *pairedTransport) Stats() transport.TransportStats { return transport.TransportStats{} }

func testLANIPv4(t *testing.T) net.IP {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&(net.FlagUp|net.FlagLoopback|net.FlagPointToPoint) != net.FlagUp {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
				return ip.To4()
			}
		}
	}
	t.Skip("no non-loopback IPv4 interface for UDP integration test")
	return nil
}
