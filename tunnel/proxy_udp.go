package tunnel

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Hardened co-located nodes must not expose localhost, metadata or the other
// VPN's control plane to authenticated clients. Ordinary deployments opt in.
func (t *TCPTunnel) allowedProxyPeer(id stack.TransportEndpointID) bool {
	if id.RemoteAddress.String() != net.IP(t.clientIP[:]).String() {
		return false
	}
	if os.Getenv("PAPERFLUX_PUBLIC_EGRESS_ONLY") != "1" {
		return true
	}
	ip, err := netip.ParseAddr(id.LocalAddress.String())
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	for _, value := range strings.Split(os.Getenv("PAPERFLUX_EGRESS_DENY_IPS"), ",") {
		if value == ip.String() {
			return false
		}
	}
	return id.LocalPort != 0 && id.LocalPort != 25
}

// One connected socket per UDP tuple preserves datagram boundaries. DNS and
// QUIC share the TCP flow budget; idle sessions release it after 30 seconds.
func (t *TCPTunnel) handleProxyUDP(request *udp.ForwarderRequest) bool {
	id := request.ID()
	if !t.allowedProxyPeer(id) {
		return false
	}
	select {
	case t.proxyFlows <- struct{}{}:
	default:
		t.proxyFlowRejected.Add(1)
		return false
	}
	var queue waiter.Queue
	ep, err := request.CreateEndpoint(&queue)
	if err != nil {
		<-t.proxyFlows
		return false
	}
	local := gonet.NewUDPConn(&queue, ep)
	if !t.trackConnection(local) {
		<-t.proxyFlows
		return false
	}
	go func() {
		defer func() { <-t.proxyFlows }()
		defer t.releaseConnection(local)
		remote, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.lifecycleContext, "udp4", net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort))))
		if err != nil {
			return
		}
		if !t.trackConnection(remote) {
			return
		}
		defer t.releaseConnection(remote)
		var group sync.WaitGroup
		var once sync.Once
		closeBoth := func() { once.Do(func() { local.Close(); remote.Close() }) }
		pump := func(dst, src net.Conn) {
			defer group.Done()
			defer closeBoth()
			buffer := make([]byte, 65535)
			for {
				src.SetReadDeadline(time.Now().Add(30 * time.Second))
				n, err := src.Read(buffer)
				if err != nil {
					return
				}
				dst.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err = dst.Write(buffer[:n]); err != nil {
					return
				}
			}
		}
		group.Add(2)
		go pump(remote, local)
		go pump(local, remote)
		group.Wait()
	}()
	return true
}
