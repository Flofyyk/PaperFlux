package tunnel

import (
	"context"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

// ExitMode chooses how the VPS delivers TCP to the destination. Raw preserves
// the historical packet-forwarding path; proxy terminates each TCP flow in
// gVisor and opens a regular outbound socket, so it needs no raw socket or
// iptables RST rule.
type ExitMode uint8

const (
	ExitModeRaw ExitMode = iota
	ExitModeProxy
)

func (m ExitMode) String() string {
	if m == ExitModeProxy {
		return "proxy"
	}
	return "raw"
}

func ParseExitMode(value string) (ExitMode, error) {
	switch value {
	case "", "raw":
		return ExitModeRaw, nil
	case "proxy":
		return ExitModeProxy, nil
	default:
		return ExitModeRaw, fmt.Errorf("unknown exit mode %q (want raw or proxy)", value)
	}
}

type TCPTunnel struct {
	gvisorStack        *stack.Stack
	tunnelEP           *TunnelLinkEndpoint
	transport          transport.Transport
	isExitNode         bool
	exitMode           ExitMode
	clientIP           [4]byte
	rawEP              *RawSocketEndpoint
	startTime          time.Time
	packetCount        atomic.Uint64
	outboundQ          chan []byte
	outboundDrop       atomic.Uint64
	outboundErr        atomic.Uint64
	proxyFlows         chan struct{}
	downloadLimiter    *rate.Limiter
	proxyUploadLimiter *rate.Limiter
	lifecycleContext   context.Context
	cancel             context.CancelFunc
	closeOnce          sync.Once
	connectionsMu      sync.Mutex
	connections        map[net.Conn]struct{}
}

func NewTCPTunnel(trans transport.Transport, isExitNode bool) *TCPTunnel {
	return NewTCPTunnelWithClientIP(trans, isExitNode, [4]byte{10, 10, 10, 2})
}

// NewTCPTunnelWithClientIP lets isolated Android workers use different
// virtual addresses. This keeps independently created five-tuples distinct.
func NewTCPTunnelWithClientIP(trans transport.Transport, isExitNode bool, clientIP [4]byte) *TCPTunnel {
	return NewTCPTunnelWithClientIPMode(trans, isExitNode, clientIP, ExitModeRaw)
}

func NewTCPTunnelWithClientIPMode(trans transport.Transport, isExitNode bool, clientIP [4]byte, exitMode ExitMode) *TCPTunnel {
	t := &TCPTunnel{
		transport:   trans,
		isExitNode:  isExitNode,
		clientIP:    clientIP,
		exitMode:    exitMode,
		startTime:   time.Now(),
		connections: make(map[net.Conn]struct{}),
	}
	t.lifecycleContext, t.cancel = context.WithCancel(context.Background())
	if isExitNode {
		t.downloadLimiter = newExitLimiter()
		if exitMode == ExitModeProxy {
			t.proxyUploadLimiter = newExitLimiter()
		}
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
		if isExitNode && exitMode == ExitModeProxy && t.downloadLimiter != nil {
			if err := t.downloadLimiter.WaitN(t.lifecycleContext, len(data)); err != nil {
				return
			}
		}
		// A full transport queue is temporary congestion, not a reason to
		// discard a TCP segment. Keep backpressure on gVisor for a short bounded
		// window; the old four millisecond window caused avoidable retransmits.
		for attempt := 0; attempt < 24; attempt++ {
			if t.lifecycleContext.Err() != nil {
				return
			}
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
		if exitMode == ExitModeProxy {
			t.setupExitNodeProxy(tunnelNIC)
		} else {
			t.setupExitNodeRaw(tunnelNIC)
		}
	} else {
		t.setupClient(tunnelNIC)
	}

	trans.Receive(func(data []byte) {
		if t.lifecycleContext.Err() != nil {
			return
		}
		if t.proxyUploadLimiter != nil {
			if err := t.proxyUploadLimiter.WaitN(t.lifecycleContext, len(data)); err != nil {
				return
			}
		}
		tunnelEP.InjectInbound(data)
	})

	go t.printStats()
	return t
}

func (t *TCPTunnel) setupExitNodeRaw(tunnelNIC tcpip.NICID) {
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

func (t *TCPTunnel) setupExitNodeProxy(tunnelNIC tcpip.NICID) {
	maxProxyFlows := configuredFlowLimit()
	utils.Debugf("[TUNNEL] EXIT NODE - proxy mode")
	t.gvisorStack.SetPromiscuousMode(tunnelNIC, true)
	t.gvisorStack.SetSpoofing(tunnelNIC, true)
	t.gvisorStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: tunnelNIC})
	t.proxyFlows = make(chan struct{}, maxProxyFlows)
	fwd := tcp.NewForwarder(t.gvisorStack, 0, maxProxyFlows, t.handleProxyTCP)
	t.gvisorStack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	// This callback creates the endpoint synchronously. Do not clone pkt:
	// this gVisor revision's UDP Forwarder clones it without releasing it.
	t.gvisorStack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		return t.handleProxyUDP(udp.NewForwarderRequest(t.gvisorStack, id, pkt))
	})
}

func (t *TCPTunnel) handleProxyTCP(request *tcp.ForwarderRequest) {
	id := request.ID()
	if !t.allowedProxyPeer(id) {
		request.Complete(true)
		return
	}
	// JoinHostPort preserves IPv6 bracket syntax. Formatting the pair manually
	// works for IPv4 but produces an ambiguous address for IPv6 destinations.
	destination := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	select {
	case t.proxyFlows <- struct{}{}:
	default:
		utils.Debugf("[EXIT] proxy flow limit reached for %s", destination)
		request.Complete(true)
		return
	}

	var waitQueue waiter.Queue
	endpoint, tcpErr := request.CreateEndpoint(&waitQueue)
	if tcpErr != nil {
		<-t.proxyFlows
		utils.Debugf("[EXIT] CreateEndpoint %s: %v", destination, tcpErr)
		request.Complete(true)
		return
	}
	request.Complete(false)
	local := gonet.NewTCPConn(&waitQueue, endpoint)
	if !t.trackConnection(local) {
		<-t.proxyFlows
		return
	}
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				utils.Debugf("[EXIT] proxy flow panic for %s: %v", destination, recovered)
			}
		}()
		defer func() { <-t.proxyFlows }()
		defer t.releaseConnection(local)
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		remote, err := dialer.DialContext(t.lifecycleContext, "tcp", destination)
		if err != nil {
			utils.Debugf("[EXIT] proxy dial %s failed: %v", destination, err)
			return
		}
		if !t.trackConnection(remote) {
			return
		}
		defer t.releaseConnection(remote)
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
		}
		copyBothWays(local, remote)
	}()
}

type closeWriter interface{ CloseWrite() error }

func copyBothWays(left, right net.Conn) {
	var wait sync.WaitGroup
	copyDirection := func(destination, source net.Conn) {
		defer wait.Done()
		_, _ = io.CopyBuffer(destination, source, make([]byte, 64<<10))
		if closer, ok := destination.(closeWriter); ok {
			_ = closer.CloseWrite()
		}
	}
	wait.Add(2)
	go copyDirection(right, left)
	go copyDirection(left, right)
	wait.Wait()
}

func (t *TCPTunnel) drainOutbound() {
	for {
		var packet []byte
		select {
		case <-t.lifecycleContext.Done():
			return
		case packet = <-t.outboundQ:
		}
		if t.downloadLimiter != nil {
			if err := t.downloadLimiter.WaitN(t.lifecycleContext, len(packet)); err != nil {
				t.outboundDrop.Add(1)
				continue
			}
		}
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

var dialTimeout = 10 * time.Second

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

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, t.gvisorStack, tcpip.FullAddress{
		NIC:  nic,
		Addr: tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}),
		Port: uint16(tcpAddr.Port),
	}, ipv4.ProtocolNumber)

	if err != nil {
		return nil, err
	}
	return conn, nil
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

	for {
		select {
		case <-t.lifecycleContext.Done():
			return
		case <-ticker.C:
		}
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
