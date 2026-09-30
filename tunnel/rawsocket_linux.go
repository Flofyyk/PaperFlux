package tunnel

import (
	"context"
	"fmt"
	"golang.org/x/time/rate"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"universal-bypass-tool/network"
	"universal-bypass-tool/utils"
)

type RawSocketEndpoint struct {
	dispatcher      stack.NetworkDispatcher
	sendFd          int
	tcpRecvFd       int
	udpRecvFd       int
	nicID           tcpip.NICID
	egressIP        [4]byte
	packetIn        atomic.Uint64
	packetOut       atomic.Uint64
	activeFlows     sync.Map // flowKey -> flowState
	sendToTransport func([]byte)
	clientIP        [4]byte
	clientIPSet     atomic.Bool
	flowMu          sync.Mutex
	flowIndex       map[clientFlowKey]flowKey
	maxFlows        int
	flowRejected    atomic.Uint64
	closed          bool
	done            chan struct{}
	closeOnce       sync.Once
	uploadLimiter   *rate.Limiter
	limitContext    context.Context
	limitCancel     context.CancelFunc
}

type flowKey struct {
	protocol   byte
	remoteIP   [4]byte
	remotePort uint16
	localPort  uint16
}

type flowState struct {
	synSeq      uint32 // TCP only
	seenAt      time.Time
	clientIP    [4]byte
	original    clientFlowKey
	reservation int
	closingAt   time.Time
}

func NewRawSocketEndpoint(nicID tcpip.NICID) (*RawSocketEndpoint, error) {
	// The exit's source address is stable for a worker lifetime. Resolving it
	// with a UDP dial for every packet used to put a syscall-heavy network
	// operation on both raw packet paths and became a visible throughput cap.
	// Keep it once, as the upstream L3 backend does.
	var egressIP [4]byte
	if ip := net.ParseIP(getLocalIP()).To4(); ip != nil {
		copy(egressIP[:], ip)
	}
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("send socket failed: %v (need root)", err)
	}

	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("IP_HDRINCL: %v", err)
	}
	// SOCK_RAW with IP_HDRINCL does not use TCP's autotuning. Larger bounded
	// buffers absorb document-transport jitter on high-RTT paths; failures are
	// harmless when the kernel caps them below this requested ceiling.
	_ = syscall.SetsockoptInt(sendFd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 16*1024*1024)

	tcpRecvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("recv socket failed: %v (need root)", err)
	}
	_ = syscall.SetsockoptInt(tcpRecvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 16*1024*1024)
	_ = syscall.SetsockoptTimeval(tcpRecvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})

	addr := &syscall.SockaddrInet4{
		Addr: [4]byte{0, 0, 0, 0},
		Port: 0,
	}
	if err := syscall.Bind(tcpRecvFd, addr); err != nil {
		syscall.Close(sendFd)
		syscall.Close(tcpRecvFd)
		return nil, fmt.Errorf("bind failed: %v", err)
	}
	udpRecvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		syscall.Close(sendFd)
		syscall.Close(tcpRecvFd)
		return nil, fmt.Errorf("UDP recv socket failed: %v", err)
	}
	_ = syscall.SetsockoptInt(udpRecvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 16*1024*1024)
	_ = syscall.SetsockoptTimeval(udpRecvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	if err := syscall.Bind(udpRecvFd, addr); err != nil {
		syscall.Close(sendFd)
		syscall.Close(tcpRecvFd)
		syscall.Close(udpRecvFd)
		return nil, fmt.Errorf("UDP bind failed: %v", err)
	}

	ep := &RawSocketEndpoint{
		sendFd:    sendFd,
		tcpRecvFd: tcpRecvFd,
		udpRecvFd: udpRecvFd,
		nicID:     nicID,
		egressIP:  egressIP,
		maxFlows:  configuredFlowLimit(),
		done:      make(chan struct{}),
	}
	ep.uploadLimiter = newExitLimiter()
	ep.limitContext, ep.limitCancel = context.WithCancel(context.Background())

	go ep.readLoop(tcpRecvFd, 6)
	go ep.readLoop(udpRecvFd, 17)
	go ep.expireFlows()
	return ep, nil
}

func (e *RawSocketEndpoint) SetTransportSender(sendFunc func([]byte)) {
	e.sendToTransport = sendFunc
}

// SetClientIP isolates an exit worker when several profile workers share the
// host raw socket namespace. Packets from other virtual clients must never be
// accepted by this worker's gVisor stack.
func (e *RawSocketEndpoint) SetClientIP(ip [4]byte) {
	e.clientIP = ip
	e.clientIPSet.Store(true)
}

func (e *RawSocketEndpoint) readLoop(fd int, expectedProtocol byte) {
	buf := make([]byte, 65535)

	for {
		select {
		case <-e.done:
			return
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			utils.Debugf("[RAW-NIC%d] Read error: %v", e.nicID, err)
			return
		}
		if n < 28 || buf[0]>>4 != 4 {
			continue
		}

		protocol := buf[9]
		if protocol != expectedProtocol {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || n < ihl+8 {
			continue
		}
		total := int(buf[2])<<8 | int(buf[3])
		if total < ihl+8 || total > n || buf[6]&0x3f != 0 || buf[7] != 0 {
			continue
		}
		n = total
		if protocol == 6 && n < ihl+20 {
			continue
		}
		flags := byte(0)
		if protocol == 6 {
			flags = buf[ihl+13]
		}
		if buf[16] == e.egressIP[0] && buf[17] == e.egressIP[1] && buf[18] == e.egressIP[2] && buf[19] == e.egressIP[3] {
			srcPort := uint16(buf[ihl])<<8 | uint16(buf[ihl+1])
			dstPort := uint16(buf[ihl+2])<<8 | uint16(buf[ihl+3])
			var remote [4]byte
			copy(remote[:], buf[12:16])
			key := flowKey{protocol: protocol, remoteIP: remote, remotePort: srcPort, localPort: dstPort}
			ackNum := uint32(0)
			if protocol == 6 {
				ackNum = uint32(buf[ihl+8])<<24 | uint32(buf[ihl+9])<<16 | uint32(buf[ihl+10])<<8 | uint32(buf[ihl+11])
			}
			state, active := e.replyFlow(key, protocol == 6 && flags&0x12 == 0x12, ackNum)
			// Do not log flow addresses on the packet path. Apart from exposing
			// destinations in persistent server logs, formatting these lines under
			// load consumed enough CPU and I/O to affect tunnel throughput.

			// Only deliver packets for ports opened by this gVisor instance.
			// The raw socket also sees the VPS's own Yandex/SSH traffic.
			if !active {
				continue
			}

			pktCopy := make([]byte, n)
			copy(pktCopy, buf[:n])

			copy(pktCopy[16:20], state.clientIP[:])
			pktCopy[ihl+2], pktCopy[ihl+3] = byte(state.original.localPort>>8), byte(state.original.localPort)

			pktCopy[10] = 0
			pktCopy[11] = 0
			ipChecksumVal := network.IPChecksum(pktCopy[:ihl])
			pktCopy[10] = byte(ipChecksumVal >> 8)
			pktCopy[11] = byte(ipChecksumVal & 0xFF)

			ipHeaderLen := int(pktCopy[0]&0x0F) * 4
			transportHeader := pktCopy[ipHeaderLen:]
			srcIPBytes := [4]byte{pktCopy[12], pktCopy[13], pktCopy[14], pktCopy[15]}
			dstIPBytes := [4]byte{pktCopy[16], pktCopy[17], pktCopy[18], pktCopy[19]}
			if protocol == 6 {
				transportHeader[16], transportHeader[17] = 0, 0
				checksum := network.TCPChecksum(transportHeader, srcIPBytes, dstIPBytes)
				transportHeader[16], transportHeader[17] = byte(checksum>>8), byte(checksum)
			} else {
				transportHeader[6], transportHeader[7] = 0, 0
				checksum := network.TransportChecksum(transportHeader, srcIPBytes, dstIPBytes, 17)
				if checksum == 0 {
					checksum = 0xffff
				}
				transportHeader[6], transportHeader[7] = byte(checksum>>8), byte(checksum)
			}

			if e.sendToTransport != nil {
				e.sendToTransport(pktCopy)
			}
		}
	}
}

func (e *RawSocketEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		view := pkt.ToView()
		// Keep an owned packet copy before releasing gVisor's temporary View.
		ipPacket := append([]byte(nil), view.ToSlice()...)
		view.Release()
		if len(ipPacket) < 28 || ipPacket[0]>>4 != 4 {
			continue
		}
		// The exit node must only originate packets from the virtual Android
		// subnet. This is a final containment boundary for document-side noise:
		// malformed collaboration data may reach gVisor, but can never turn the
		// VPS into a scanner or consume the external uplink.
		if e.clientIPSet.Load() {
			if ipPacket[12] != e.clientIP[0] || ipPacket[13] != e.clientIP[1] || ipPacket[14] != e.clientIP[2] || ipPacket[15] != e.clientIP[3] {
				continue
			}
		} else if ipPacket[12] != 10 || ipPacket[13] != 10 || ipPacket[14] != 10 || ipPacket[15] < 2 || ipPacket[15] > 5 {
			continue
		}

		// ipPacket is our owned copy. Preserve the client address BEFORE
		// rewriting it in place for SNAT; replies must target the client,
		// never the VPS address now stored in the same backing array.
		var clientIP [4]byte
		copy(clientIP[:], ipPacket[12:16])
		pktCopy := ipPacket

		copy(pktCopy[12:16], e.egressIP[:])

		ipHeaderLen := int(pktCopy[0]&0x0F) * 4
		if ipHeaderLen < 20 || len(pktCopy) < ipHeaderLen+8 {
			continue
		}
		protocol := pktCopy[9]
		if protocol != 6 && protocol != 17 {
			continue
		}
		if protocol == 6 && len(pktCopy) < ipHeaderLen+20 {
			continue
		}
		total := int(pktCopy[2])<<8 | int(pktCopy[3])
		if total < ipHeaderLen+8 || total > len(pktCopy) || pktCopy[6]&0x3f != 0 || pktCopy[7] != 0 {
			continue
		}
		pktCopy = pktCopy[:total]
		if protocol == 6 && total < ipHeaderLen+20 {
			continue
		}
		transportHeader := pktCopy[ipHeaderLen:]
		var remote [4]byte
		copy(remote[:], pktCopy[16:20])
		original := clientFlowKey{flowKey: flowKey{protocol: protocol, remoteIP: remote,
			remotePort: uint16(transportHeader[2])<<8 | uint16(transportHeader[3]),
			localPort:  uint16(transportHeader[0])<<8 | uint16(transportHeader[1])}, clientIP: clientIP}
		flags, seq := byte(0), uint32(0)
		if protocol == 6 {
			flags = transportHeader[13]
			seq = uint32(transportHeader[4])<<24 | uint32(transportHeader[5])<<16 | uint32(transportHeader[6])<<8 | uint32(transportHeader[7])
		}
		key, _, allowed := e.claimFlow(original, seq, protocol == 17 || flags&0x02 != 0, protocol == 6 && flags&0x05 != 0)
		if !allowed {
			continue
		}
		transportHeader[0], transportHeader[1] = byte(key.localPort>>8), byte(key.localPort)
		pktCopy[10], pktCopy[11] = 0, 0
		ipChecksumVal := network.IPChecksum(pktCopy[:ipHeaderLen])
		pktCopy[10] = byte(ipChecksumVal >> 8)
		pktCopy[11] = byte(ipChecksumVal & 0xFF)

		srcIPBytes := [4]byte{pktCopy[12], pktCopy[13], pktCopy[14], pktCopy[15]}
		dstIPBytes := [4]byte{pktCopy[16], pktCopy[17], pktCopy[18], pktCopy[19]}
		if protocol == 6 {
			transportHeader[16], transportHeader[17] = 0, 0
			checksum := network.TCPChecksum(transportHeader, srcIPBytes, dstIPBytes)
			transportHeader[16], transportHeader[17] = byte(checksum>>8), byte(checksum)
		} else {
			transportHeader[6], transportHeader[7] = 0, 0
			checksum := network.TransportChecksum(transportHeader, srcIPBytes, dstIPBytes, 17)
			if checksum == 0 {
				checksum = 0xffff
			}
			transportHeader[6], transportHeader[7] = byte(checksum>>8), byte(checksum)
		}

		// Packet-path tracing is intentionally disabled in the normal build;
		// diagnostics are available through the bounded aggregate counters.

		var dst [4]byte
		copy(dst[:], pktCopy[16:20])

		addr := &syscall.SockaddrInet4{
			Addr: dst,
			Port: 0,
		}

		if e.uploadLimiter != nil {
			if err := e.uploadLimiter.WaitN(e.limitContext, len(pktCopy)); err != nil {
				continue
			}
		}
		if err := syscall.Sendto(e.sendFd, pktCopy, 0, addr); err != nil {
			utils.Debugf("[RAW-NIC%d] Sendto failed: %v", e.nicID, err)
			continue
		}

		e.packetOut.Add(1)
		n++
	}
	return n, nil
}

// expireFlows prevents idle UDP NAT entries from growing unbounded. TCP is
// retained slightly longer because a remote peer may still send a final ACK.
func (e *RawSocketEndpoint) expireFlows() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.done:
			return
		case now := <-ticker.C:
			e.pruneFlows(now, false)
			e.flowMu.Lock()
			active := len(e.flowIndex)
			e.flowMu.Unlock()
			utils.Debugf("[EXIT_LIMITS] active=%d rejected=%d", active, e.flowRejected.Load())
		}
	}
}

func (e *RawSocketEndpoint) MTU() uint32                    { return 1500 }
func (e *RawSocketEndpoint) MaxHeaderLength() uint16        { return 0 }
func (e *RawSocketEndpoint) LinkAddress() tcpip.LinkAddress { return "" }
func (e *RawSocketEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}
func (e *RawSocketEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}
func (e *RawSocketEndpoint) IsAttached() bool                        { return e.dispatcher != nil }
func (e *RawSocketEndpoint) Wait()                                   {}
func (e *RawSocketEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *RawSocketEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (e *RawSocketEndpoint) Close() {
	e.closeOnce.Do(func() {
		if e.limitCancel != nil {
			e.limitCancel()
		}
		if e.done != nil {
			close(e.done)
		}
		e.pruneFlows(time.Now(), true)
		syscall.Close(e.sendFd)
		syscall.Close(e.tcpRecvFd)
		syscall.Close(e.udpRecvFd)
	})
}
func (e *RawSocketEndpoint) SetMTU(uint32)                        {}
func (e *RawSocketEndpoint) SetLinkAddress(tcpip.LinkAddress)     {}
func (e *RawSocketEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }
func (e *RawSocketEndpoint) SetOnCloseAction(func())              {}
