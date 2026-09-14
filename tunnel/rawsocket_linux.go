package tunnel

import (
	"fmt"
	"log"
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
	packetIn        atomic.Uint64
	packetOut       atomic.Uint64
	activeFlows     sync.Map // flowKey -> flowState
	sendToTransport func([]byte)
	clientIP        [4]byte
	clientIPSet     atomic.Bool
	traceIn         atomic.Uint64
	traceOut        atomic.Uint64
}

type flowKey struct {
	protocol   byte
	remoteIP   [4]byte
	remotePort uint16
	localPort  uint16
}

type flowState struct {
	synSeq   uint32 // TCP only
	seenAt   time.Time
	clientIP [4]byte
}

func NewRawSocketEndpoint(nicID tcpip.NICID) (*RawSocketEndpoint, error) {
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("send socket failed: %v (need root)", err)
	}

	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("IP_HDRINCL: %v", err)
	}

	tcpRecvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("recv socket failed: %v (need root)", err)
	}

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
	}

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
		if protocol == 6 && n < ihl+20 {
			continue
		}
		flags := byte(0)
		if protocol == 6 {
			flags = buf[ihl+13]
		}
		dstIP := net.IP(buf[16:20])
		localIP := getLocalIP()

		if dstIP.String() == localIP {
			srcPort := uint16(buf[ihl])<<8 | uint16(buf[ihl+1])
			dstPort := uint16(buf[ihl+2])<<8 | uint16(buf[ihl+3])
			var remote [4]byte
			copy(remote[:], buf[12:16])
			key := flowKey{protocol: protocol, remoteIP: remote, remotePort: srcPort, localPort: dstPort}
			flow, active := e.activeFlows.Load(key)
			if protocol == 6 && flags&(0x02|0x04|0x01) != 0 {
				n := e.traceIn.Add(1)
				if n <= 40 || n%500 == 0 {
					log.Printf("[RAW-NIC%d] IN %s:%d -> %s:%d flags=%s active=%t", e.nicID, srcIP(buf), srcPort, dstIP, dstPort, tcpFlags(flags), active)
				}
			}

			// Only deliver packets for ports opened by this gVisor instance.
			// The raw socket also sees the VPS's own Yandex/SSH traffic.
			if !active {
				continue
			}

			if protocol == 6 && flags == 0x12 {
				ackNum := uint32(buf[ihl+8])<<24 | uint32(buf[ihl+9])<<16 | uint32(buf[ihl+10])<<8 | uint32(buf[ihl+11])
				synSeq := ackNum - 1
				if !active || flow.(flowState).synSeq != synSeq {
					continue
				}
			}
			if active {
				state := flow.(flowState)
				state.seenAt = time.Now()
				e.activeFlows.Store(key, state)
			}

			pktCopy := make([]byte, n)
			copy(pktCopy, buf[:n])

			state := flow.(flowState)
			copy(pktCopy[16:20], state.clientIP[:])

			pktCopy[10] = 0
			pktCopy[11] = 0
			ipChecksumVal := network.IPChecksum(pktCopy[:20])
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

		localIP := getLocalIP()
		var localIPBytes [4]byte
		fmt.Sscanf(localIP, "%d.%d.%d.%d", &localIPBytes[0], &localIPBytes[1], &localIPBytes[2], &localIPBytes[3])
		copy(pktCopy[12:16], localIPBytes[:])

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
		pktCopy[10], pktCopy[11] = 0, 0
		ipChecksumVal := network.IPChecksum(pktCopy[:20])
		pktCopy[10] = byte(ipChecksumVal >> 8)
		pktCopy[11] = byte(ipChecksumVal & 0xFF)

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

		srcPort := uint16(transportHeader[0])<<8 | uint16(transportHeader[1])
		var remote [4]byte
		copy(remote[:], pktCopy[16:20])
		flowKey := flowKey{protocol: protocol, remoteIP: remote, remotePort: uint16(transportHeader[2])<<8 | uint16(transportHeader[3]), localPort: srcPort}
		flags := byte(0)
		if protocol == 6 {
			flags = transportHeader[13]
		}
		if protocol == 6 && flags&(0x02|0x04|0x01) != 0 {
			nTrace := e.traceOut.Add(1)
			if nTrace <= 40 || nTrace%500 == 0 {
				log.Printf("[RAW-NIC%d] OUT %s:%d -> %s:%d flags=%s", e.nicID, net.IP(pktCopy[12:16]), srcPort, net.IP(pktCopy[16:20]), uint16(transportHeader[2])<<8|uint16(transportHeader[3]), tcpFlags(flags))
			}
		}

		if protocol == 6 && flags&0x02 != 0 {
			seqNum := uint32(transportHeader[4])<<24 | uint32(transportHeader[5])<<16 | uint32(transportHeader[6])<<8 | uint32(transportHeader[7])
			e.activeFlows.Store(flowKey, flowState{synSeq: seqNum, seenAt: time.Now(), clientIP: clientIP})
		} else if protocol == 17 {
			e.activeFlows.Store(flowKey, flowState{seenAt: time.Now(), clientIP: clientIP})
		}

		if protocol == 6 && (flags&0x01 != 0 || flags&0x04 != 0) {
			e.activeFlows.Delete(flowKey)
		}

		var dst [4]byte
		copy(dst[:], pktCopy[16:20])

		addr := &syscall.SockaddrInet4{
			Addr: dst,
			Port: 0,
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
	for range ticker.C {
		now := time.Now()
		e.activeFlows.Range(func(key, value any) bool {
			flowKey := key.(flowKey)
			state := value.(flowState)
			ttl := 90 * time.Second
			if flowKey.protocol == 6 {
				ttl = 5 * time.Minute
			}
			if now.Sub(state.seenAt) > ttl {
				e.activeFlows.Delete(key)
			}
			return true
		})
	}
}

func srcIP(packet []byte) net.IP { return net.IPv4(packet[12], packet[13], packet[14], packet[15]) }

func tcpFlags(flags byte) string {
	var s string
	if flags&0x02 != 0 {
		s += "S"
	}
	if flags&0x10 != 0 {
		s += "A"
	}
	if flags&0x01 != 0 {
		s += "F"
	}
	if flags&0x04 != 0 {
		s += "R"
	}
	return s
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
	syscall.Close(e.sendFd)
	syscall.Close(e.tcpRecvFd)
	syscall.Close(e.udpRecvFd)
}
func (e *RawSocketEndpoint) SetMTU(uint32)                        {}
func (e *RawSocketEndpoint) SetLinkAddress(tcpip.LinkAddress)     {}
func (e *RawSocketEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }
func (e *RawSocketEndpoint) SetOnCloseAction(func())              {}
