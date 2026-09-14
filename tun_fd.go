//go:build android

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dosgo/go-tun2socks/core"
	"github.com/dosgo/go-tun2socks/tun2socks"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"

	"universal-bypass-tool/network"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

var androidDialFailures atomic.Uint64

// packetBridge is a length-prefixed raw-IP packet stream used by Android's
// WorkerManager. A worker owns one Yandex session while the service owns TUN.
type packetBridge struct {
	net.Conn
	read    []byte
	writeMu sync.Mutex
}

func connectPacketBridge(address string) (io.ReadWriteCloser, error) {
	c, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return &packetBridge{Conn: c}, nil
}
func (b *packetBridge) Read(p []byte) (int, error) {
	if len(b.read) == 0 {
		var h [4]byte
		if _, err := io.ReadFull(b.Conn, h[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(h[:])
		if n == 0 || n > 65535 {
			return 0, fmt.Errorf("invalid packet length %d", n)
		}
		b.read = make([]byte, n)
		if _, err := io.ReadFull(b.Conn, b.read); err != nil {
			return 0, err
		}
	}
	n := copy(p, b.read)
	b.read = b.read[n:]
	return n, nil
}
func (b *packetBridge) Write(p []byte) (int, error) {
	if len(p) == 0 || len(p) > 65535 {
		return 0, fmt.Errorf("invalid packet length %d", len(p))
	}
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, err := b.Conn.Write(h[:]); err != nil {
		return 0, err
	}
	if _, err := b.Conn.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// runTun2Socks terminates TCP in a userspace stack and forwards each stream
// through the OpenFlux SOCKS5 listener. This is the supported custom-I/O
// integration path for Android VpnService TUN descriptors.
type udpTunnelDialer interface {
	DialUDP(string) (net.Conn, error)
}

func runTun2Socks(dev io.ReadWriteCloser, mtu int, socksAddr string, udpDialer udpTunnelDialer) error {
	err := tun2socks.ForwardTransportFromIo(dev, mtu,
		func(conn core.CommTCPConn) error {
			defer conn.Close()
			dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
			if err != nil {
				return err
			}
			// In dosgo/tun2socks the forwarded connection's LocalAddr is the
			// original destination from the intercepted IP flow; RemoteAddr is
			// the virtual TUN peer (10.0.0.2) and must not be dialed upstream.
			target := conn.LocalAddr().String()
			// A raw exit node can report a transient SOCKS host-unreachable while
			// it creates the outbound flow. Retry a couple of times before
			// failing the intercepted connection; browsers otherwise surface this
			// as a noisy per-request tunnel error.
			var upstream net.Conn
			for attempt := 0; attempt < 3; attempt++ {
				upstream, err = dialer.Dial("tcp", target)
				if err == nil {
					break
				}
				if attempt < 2 {
					time.Sleep(time.Duration(attempt+1) * 75 * time.Millisecond)
				}
			}
			if err != nil {
				if n := androidDialFailures.Add(1); n <= 20 || n%100 == 0 {
					log.Printf("[ANDROID-TCP] SOCKS dial failed target=%s count=%d err=%v", target, n, err)
				}
				return err
			}
			defer upstream.Close()
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(conn, upstream)
				close(done)
			}()
			_, _ = io.Copy(upstream, conn)
			<-done
			return nil
		},
		func(conn core.CommUDPConn, _ core.CommEndpoint) error {
			defer conn.Close()
			// LocalAddr is the intercepted destination, just as it is for TCP.
			// Relay every UDP flow (including DNS and QUIC) through gVisor so a
			// VPN session never silently leaks datagrams to the physical network.
			upstream, err := udpDialer.DialUDP(conn.LocalAddr().String())
			if err != nil {
				log.Printf("[ANDROID-UDP] tunnel dial failed target=%s err=%v", conn.LocalAddr(), err)
				return nil // keep the TUN engine alive on a single-flow failure
			}
			defer upstream.Close()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(conn, upstream); close(done) }()
			_, _ = io.Copy(upstream, conn)
			<-done
			return nil
		},
	)
	if err != nil {
		return err
	}
	select {}
}

// Android's libc advertises a localhost DNS stub to native processes, but the
// stub is unavailable to a separately executed binary. Use a resolver that
// talks directly to the same DNS endpoint exposed through the VPN service.
func configureAndroidResolver() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 2 * time.Second}
			var last error
			for _, server := range androidDNSServers() {
				conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		},
	}
}

// Android's VPN process cannot use the libc DNS stub.  Prefer the gateway
// advertised by the active physical interface (read from procfs), then fall
// back to public resolvers.  Some mobile/Wi-Fi networks drop UDP/53 to 1.1.1.1.
func androidDNSServers() []string {
	// Do not put a remembered Wi‑Fi gateway first: on LTE that address (often
	// 192.168.1.1) is unreachable and causes a multi-second resolver stall
	// before the fallback list is tried. Yandex DNS is reachable on the mobile
	// path used by the document transport.
	servers := []string{"77.88.8.8", "77.88.8.1"}
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[1] != "00000000" || fields[0] == "tun0" {
				continue
			}
			gateway, err := strconv.ParseUint(fields[2], 16, 32)
			if err != nil || gateway == 0 {
				continue
			}
			servers = append(servers, net.IPv4(byte(gateway), byte(gateway>>8), byte(gateway>>16), byte(gateway>>24)).String())
			break
		}
	}
	for _, fallback := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		seen := false
		for _, server := range servers {
			if server == fallback {
				seen = true
				break
			}
		}
		if !seen {
			servers = append(servers, fallback)
		}
	}
	return servers
}

// recvTunFD accepts the Android VpnService file descriptor over an abstract
// Unix socket. LocalSocket.setFileDescriptorsForSend uses SCM_RIGHTS, so the
// native OpenFlux client can read and write the system TUN directly.
func recvTunFD(sockPath string) (*os.File, error) {
	// Android LocalSocket's ABSTRACT namespace is represented by a leading
	// NUL in the Linux sockaddr_un, while the command-line spelling uses @.
	if len(sockPath) > 0 && sockPath[0] == '@' {
		sockPath = "\x00" + sockPath[1:]
	}
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("resolve TUN socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen TUN socket: %w", err)
	}
	defer listener.Close()
	conn, err := listener.AcceptUnix()
	if err != nil {
		return nil, fmt.Errorf("accept TUN socket: %w", err)
	}
	defer conn.Close()

	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := conn.ReadMsgUnix(data, oob)
	if err != nil {
		return nil, fmt.Errorf("receive TUN descriptor: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return nil, fmt.Errorf("parse TUN descriptor: %w", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return nil, fmt.Errorf("extract TUN descriptor: %w", err)
	}
	return os.NewFile(uintptr(fds[0]), "openflux-tun"), nil
}

// runTUNBridge deliberately does not create a second TCP stack on the Android
// side: packets from VpnService are already complete IP packets. OpenFlux
// carries them to the exit node, whose gVisor/raw-socket stack handles TCP and
// returns response packets over the same transport.
func runTUNBridge(t transport.Transport, tun *os.File) {
	// The VPN interface can receive the first SYN before the document
	// handshake finishes. Keep a bounded FIFO and retry briefly instead of
	// silently dropping those packets.
	pending := make(chan []byte, 256)
	go func() {
		for packet := range pending {
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				if !t.IsConnected() {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				if err := t.Send(packet); err == nil {
					utils.Debugf("[ANDROID-TUN] sent bytes=%d %s", len(packet), network.ParsePacketInfo(packet))
					break
				} else {
					utils.Debugf("[ANDROID-TUN] transport send retry: %v", err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()
	t.Receive(func(packet []byte) {
		// Raw-socket forwarding rewrites the destination address at the exit
		// node. Rebuild both checksums once more at the Android boundary so the
		// kernel TCP stack never sees an offload/stale-checksum packet.
		if len(packet) >= 40 && packet[0]>>4 == 4 && packet[9] == 6 {
			packet = append([]byte(nil), packet...)
			ihl := int(packet[0]&0x0f) * 4
			if ihl >= 20 && len(packet) >= ihl+20 {
				packet[10], packet[11] = 0, 0
				ipSum := ipv4Checksum(packet[:ihl])
				packet[10], packet[11] = byte(ipSum>>8), byte(ipSum)
				tcp := packet[ihl:]
				tcp[16], tcp[17] = 0, 0
				src := [4]byte{packet[12], packet[13], packet[14], packet[15]}
				dst := [4]byte{packet[16], packet[17], packet[18], packet[19]}
				tcpSum := network.TCPChecksum(tcp, src, dst)
				tcp[16], tcp[17] = byte(tcpSum>>8), byte(tcpSum)
			}
		}
		valid := "n/a"
		if len(packet) >= 40 && packet[9] == 6 {
			ihl := int(packet[0]&0x0f) * 4
			if ihl >= 20 && len(packet) >= ihl+20 {
				src := [4]byte{packet[12], packet[13], packet[14], packet[15]}
				dst := [4]byte{packet[16], packet[17], packet[18], packet[19]}
				valid = fmt.Sprintf("ip=%04x tcp=%04x", ipv4Checksum(packet[:ihl]), network.TCPChecksum(packet[ihl:], src, dst))
			}
		}
		if _, err := tun.Write(packet); err != nil {
			utils.Debugf("[ANDROID-TUN] write failed: %v", err)
		} else {
			utils.Debugf("[ANDROID-TUN] received response bytes=%d %s %s", len(packet), valid, network.ParsePacketInfo(packet))
		}
	})
	buf := make([]byte, 65535)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			packet := append([]byte(nil), buf[:n]...)
			if len(packet) < 20 || packet[0]>>4 != 4 {
				continue
			}
			ihl := int(packet[0]&0x0f) * 4
			if ihl < 20 || len(packet) < ihl {
				continue
			}
			// OpenFlux's exit implementation currently carries TCP.  Resolve
			// Android's UDP DNS requests locally instead of sending them into a
			// TCP-only exit stack. The Android service excludes its own UID from
			// the VPN, so this resolver uses the underlying network and does not
			// loop back into this TUN.
			if response, ok := resolveDNS(packet); ok {
				if len(response) == 0 {
					utils.Debugf("[ANDROID-DNS] query could not be resolved upstream")
					continue
				}
				if _, err := tun.Write(response); err != nil {
					utils.Debugf("[ANDROID-DNS] response write failed: %v", err)
				} else {
					utils.Debugf("[ANDROID-DNS] response delivered bytes=%d", len(response))
				}
				continue
			}
			// The OpenFlux exit stack is intentionally TCP-only. Android also
			// emits ICMP connectivity probes and UDP/QUIC traffic; forwarding
			// those into gVisor's TCP-only stack can crash the exit process.
			if packet[9] != 6 {
				utils.Debugf("[ANDROID-TUN] dropped unsupported IPv4 protocol=%d", packet[9])
				continue
			}
			select {
			case pending <- packet:
			default:
				utils.Debugf("[ANDROID-TUN] send queue full, dropping bytes=%d", len(packet))
			}
		}
	}
}

// resolveDNS handles an IPv4 UDP/53 query from Android and returns an IPv4
// response addressed back to the original app. A zero UDP checksum is valid
// for IPv4 and avoids changing the DNS payload.
func resolveDNS(packet []byte) ([]byte, bool) {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 {
		return nil, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 {
		return nil, false
	}
	total := int(packet[2])<<8 | int(packet[3])
	if total < ihl+8 || total > len(packet) || packet[ihl+2] != 0 || packet[ihl+3] != 53 {
		return nil, false
	}
	utils.Debugf("[ANDROID-DNS] query bytes=%d", total-ihl-8)
	query := packet[ihl+8 : total]
	var answer []byte
	var lastErr error
	for _, server := range androidDNSServers() {
		conn, err := net.DialTimeout("udp", net.JoinHostPort(server, "53"), 2*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = conn.Write(query); err != nil {
			lastErr = err
			conn.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, readErr := conn.Read(buf)
		conn.Close()
		if readErr == nil {
			answer = buf[:n]
			break
		}
		lastErr = readErr
	}
	if len(answer) == 0 {
		utils.Debugf("[ANDROID-DNS] all upstream resolvers failed: %v", lastErr)
		return nil, true
	}
	response := make([]byte, ihl+8+len(answer))
	copy(response, packet[:ihl])
	copy(response[ihl+8:], answer)
	response[2] = byte(len(response) >> 8)
	response[3] = byte(len(response))
	response[8] = 64
	copy(response[12:16], packet[16:20])
	copy(response[16:20], packet[12:16])
	response[10], response[11] = 0, 0
	sum := ipv4Checksum(response[:ihl])
	response[10], response[11] = byte(sum>>8), byte(sum)
	response[ihl], response[ihl+1] = 0, 53
	response[ihl+2], response[ihl+3] = packet[ihl], packet[ihl+1]
	udpLen := len(response) - ihl
	response[ihl+4], response[ihl+5] = byte(udpLen>>8), byte(udpLen)
	response[ihl+6], response[ihl+7] = 0, 0
	return response, true
}

func ipv4Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
