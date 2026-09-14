package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

type TCPTunnel struct {
	gvisorStack  *stack.Stack
	tunnelEP     *TunnelLinkEndpoint
	transport    transport.Transport
	isExitNode   bool
	clientIP     [4]byte
	rawEP        *RawSocketEndpoint
	startTime    time.Time
	packetCount  atomic.Uint64
	outboundQ    chan []byte
	outboundDrop atomic.Uint64
	outboundErr  atomic.Uint64
}

func NewTCPTunnel(trans transport.Transport, isExitNode bool) *TCPTunnel {
	return NewTCPTunnelWithClientIP(trans, isExitNode, [4]byte{10, 10, 10, 2})
}

// NewTCPTunnelWithClientIP lets isolated Android workers use different
// virtual addresses. This keeps independently created five-tuples distinct.
func NewTCPTunnelWithClientIP(trans transport.Transport, isExitNode bool, clientIP [4]byte) *TCPTunnel {
	t := &TCPTunnel{
		transport:  trans,
		isExitNode: isExitNode,
		clientIP:   clientIP,
		startTime:  time.Now(),
	}

	utils.Debugf("[TUNNEL] Net stack init...")
	t.gvisorStack = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		// UDP is needed for DNS, QUIC and other datagram traffic on Android.
		// It shares the same authenticated transport as TCP; it is not a second
		// external proxy or a direct-network fallback.
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 1048576}); err != nil {
		utils.Debugf("[TUNNEL] Failed to set recv buffer: %v", err)
	}
	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPSendBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 1048576}); err != nil {
		utils.Debugf("[TUNNEL] Failed to set send buffer: %v", err)
	}

	tunnelEP := NewTunnelLinkEndpoint()
	tunnelEP.onOutgoingPacket = func(data []byte) {
		// A full transport queue is temporary congestion, not a reason to
		// discard a TCP segment. Keep backpressure on gVisor for a short bounded
		// window; the old four millisecond window caused avoidable retransmits.
		for attempt := 0; attempt < 24; attempt++ {
			if err := trans.Send(data); err == nil {
				return
			}
			delay := time.Duration(attempt+1) * 2 * time.Millisecond
			if delay > 20*time.Millisecond {
				delay = 20 * time.Millisecond
			}
			time.Sleep(delay)
		}
		utils.Debugf("[TUNNEL] transport congested; packet dropped after 24 retries")
	}
	t.tunnelEP = tunnelEP

	tunnelNIC := tcpip.NICID(1)
	if err := t.gvisorStack.CreateNIC(tunnelNIC, tunnelEP); err != nil {
		utils.Debugf("[TUNNEL] CreateNIC tunnel error: %v", err)
	}

	if isExitNode {
		t.setupExitNode(tunnelNIC)
	} else {
		t.setupClient(tunnelNIC)
	}

	trans.Receive(func(data []byte) {
		tunnelEP.InjectInbound(data)
	})

	go t.printStats()
	return t
}

func (t *TCPTunnel) setupExitNode(tunnelNIC tcpip.NICID) {
	localIP := getLocalIP()
	utils.Debugf("[TUNNEL] EXIT NODE - Local IP: %s", localIP)

	rawEP, err := NewRawSocketEndpoint(tcpip.NICID(2))
	if err != nil {
		utils.Debugf("[TUNNEL] Raw socket error: %v", err)
		return
	}

	t.rawEP = rawEP
	// Restrict this exit worker to its assigned profile address. This is
	// required when several PaperFlux workers share one VPS raw namespace.
	rawEP.SetClientIP(t.clientIP)
	// Raw socket callbacks must stay non-blocking. Sending directly from the
	// gVisor/raw reader made a full transport queue stall inbound packet reads,
	// which in turn caused TCP retransmits and low download speed. Copy into a
	// bounded queue and let a dedicated sender drain it.
	t.outboundQ = make(chan []byte, 4096)
	rawEP.SetTransportSender(func(data []byte) {
		packet := append([]byte(nil), data...)
		select {
		case t.outboundQ <- packet:
		default:
			n := t.outboundDrop.Add(1)
			if n <= 5 || n%1000 == 0 {
				utils.Debugf("[TUNNEL] outbound queue full; dropped=%d", n)
			}
		}
	})
	go t.drainOutbound()

	internetNIC := tcpip.NICID(2)
	if err := t.gvisorStack.CreateNIC(internetNIC, rawEP); err != nil {
		utils.Debugf("[TUNNEL] CreateNIC internet error: %v", err)
		return
	}

	var ipBytes [4]byte
	fmt.Sscanf(localIP, "%d.%d.%d.%d", &ipBytes[0], &ipBytes[1], &ipBytes[2], &ipBytes[3])
	internetAddr := tcpip.AddrFrom4(ipBytes)
	t.gvisorStack.AddProtocolAddress(internetNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   internetAddr,
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})

	t.gvisorStack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         internetNIC,
	})

	tunnelSubnet := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4([4]byte{10, 10, 10, 0}),
		PrefixLen: 24,
	}.Subnet()
	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: tunnelSubnet,
		NIC:         tunnelNIC,
	})
}

func (t *TCPTunnel) drainOutbound() {
	for packet := range t.outboundQ {
		if err := t.transport.Send(packet); err != nil {
			n := t.outboundErr.Add(1)
			if n <= 5 || n%1000 == 0 {
				utils.Debugf("[TUNNEL] outbound transport error=%v count=%d", err, n)
			}
		}
	}
}

func (t *TCPTunnel) setupClient(tunnelNIC tcpip.NICID) {
	clientAddr := tcpip.AddrFrom4(t.clientIP)
	t.gvisorStack.AddProtocolAddress(tunnelNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   clientAddr,
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})

	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         tunnelNIC,
	})
}

func (t *TCPTunnel) DialTCP(address string) (net.Conn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	ip := tcpAddr.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 not supported")
	}

	nic := tcpip.NICID(1)
	if t.isExitNode {
		nic = tcpip.NICID(2)
	}

	conn, err := gonet.DialTCP(t.gvisorStack, tcpip.FullAddress{
		NIC:  nic,
		Addr: tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}),
		Port: uint16(tcpAddr.Port),
	}, ipv4.ProtocolNumber)

	return conn, err
}

// DialUDP opens a connected UDP flow inside the gVisor stack.  This mirrors
// DialTCP so Android's tun2socks UDP callback can relay datagrams through the
// existing OpenFlux packet transport.
func (t *TCPTunnel) DialUDP(address string) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	ip := udpAddr.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 not supported")
	}
	nic := tcpip.NICID(1)
	if t.isExitNode {
		nic = tcpip.NICID(2)
	}
	return gonet.DialUDP(t.gvisorStack, nil, &tcpip.FullAddress{
		NIC: nic, Addr: tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}), Port: uint16(udpAddr.Port),
	}, ipv4.ProtocolNumber)
}

// Probe dialing uses the same userland stack and document transport as data.
func (t *TCPTunnel) DialProbe(ctx context.Context, address string) (net.Conn, error) {
	a, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil || a.IP.To4() == nil {
		return nil, fmt.Errorf("probe requires IPv4 address")
	}
	ip := a.IP.To4()
	return gonet.DialContextTCP(ctx, t.gvisorStack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}), Port: uint16(a.Port)}, ipv4.ProtocolNumber)
}

func (t *TCPTunnel) ListenTCP(port uint16) (net.Listener, error) {
	return gonet.ListenTCP(t.gvisorStack, tcpip.FullAddress{
		NIC:  1,
		Port: port,
	}, ipv4.ProtocolNumber)
}

func (t *TCPTunnel) printStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := t.gvisorStack.Stats()
		queueDepth := 0
		if t.outboundQ != nil {
			queueDepth = len(t.outboundQ)
		}
		utils.Debugf("[STATS] uptime=%v packets=%d connected=%d established=%d retrans=%d outbound_queue=%d/4096 outbound_drop=%d outbound_err=%d",
			time.Since(t.startTime).Round(time.Second),
			t.packetCount.Load(),
			stats.TCP.CurrentConnected.Value(),
			stats.TCP.CurrentEstablished.Value(),
			stats.TCP.Retransmits.Value(),
			queueDepth,
			t.outboundDrop.Load(),
			t.outboundErr.Load(),
		)
	}
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "192.168.1.100"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
