package tunnel

import (
	"bytes"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
	"testing"
	"time"
)

func TestProxyUDPDatagrams(t *testing.T) {
	ip := testLANIPv4(t)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := server.ReadFromUDP(b)
			if e != nil {
				return
			}
			server.WriteToUDP(b[:n], a)
		}
	}()
	a, b := newTransportPair()
	exit := NewTCPTunnelWithClientIPMode(b, true, [4]byte{10, 10, 10, 2}, ExitModeProxy)
	defer exit.Close()
	client := NewTCPTunnelWithClientIP(a, false, [4]byte{10, 10, 10, 2})
	defer client.Close()
	c, err := client.DialUDP(server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	for _, payload := range [][]byte{{1, 2, 3}, bytes.Repeat([]byte{4}, 1200), {}} {
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 1400)
		n, err := c.Read(got)
		if err != nil || !bytes.Equal(got[:n], payload) {
			t.Fatalf("datagram len=%d err=%v", n, err)
		}
	}
}

func TestProxyPublicEgressGuard(t *testing.T) {
	t.Setenv("PAPERFLUX_PUBLIC_EGRESS_ONLY", "1")
	t.Setenv("PAPERFLUX_EGRESS_DENY_IPS", "8.8.4.4")
	tun := &TCPTunnel{clientIP: [4]byte{10, 10, 10, 2}}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.168.1.1", "8.8.4.4", "198.18.0.1", "240.0.0.1"} {
		id := stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{10, 10, 10, 2}), LocalAddress: tcpip.AddrFromSlice(net.ParseIP(ip).To4()), LocalPort: 443}
		if tun.allowedProxyPeer(id) {
			t.Fatalf("allowed %s", ip)
		}
	}
	id := stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{10, 10, 10, 2}), LocalAddress: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), LocalPort: 53}
	if !tun.allowedProxyPeer(id) {
		t.Fatal("public DNS rejected")
	}
	id.RemoteAddress = tcpip.AddrFrom4([4]byte{10, 10, 10, 3})
	if tun.allowedProxyPeer(id) {
		t.Fatal("spoofed profile accepted")
	}
}
