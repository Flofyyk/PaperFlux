package tunnel

import (
	"bytes"
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Root-only local end-to-end probe: two independent raw workers originate
// the exact same virtual TCP tuple. A local kernel TCP server must complete
// both handshakes and return payload to the correct original virtual IP/port.
// No external destination, provider document, or production profile is used.
func TestRawNATTwoWorkersLocalTCP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw sockets require root")
	}
	globalRule := exec.Command("iptables", "-C", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP").Run()
	scopedRule := exec.Command("iptables", "-C", "OUTPUT", "-s", getLocalIP(), "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP").Run()
	if globalRule != nil && scopedRule != nil {
		t.Skip("existing raw-mode RST suppression required; test does not change firewall")
	}
	t.Setenv("PAPERFLUX_MAX_MBIT", "0")
	address := net.ParseIP(getLocalIP()).To4()
	if address == nil {
		t.Fatal("local egress address unavailable")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for i := 0; i < 2; i++ {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write([]byte("isolated-payload"))
			}()
		}
	}()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	remote := [4]byte(address)
	for index := 0; index < 2; index++ {
		ep, err := NewRawSocketEndpoint(2)
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Close()
		client := [4]byte{10, 10, 10, byte(index + 2)}
		ep.SetClientIP(client)
		replies := make(chan []byte, 64)
		ep.SetTransportSender(func(p []byte) {
			select {
			case replies <- p:
			default:
			}
		})
		seq := uint32(10000 + index*1000)
		send := func(flags byte, sequence, ack uint32) {
			data := make([]byte, 40)
			data[0], data[3], data[8], data[9] = 0x45, 40, 64, 6
			copy(data[12:16], client[:])
			copy(data[16:20], remote[:])
			binary.BigEndian.PutUint16(data[20:22], 42000)
			binary.BigEndian.PutUint16(data[22:24], port)
			binary.BigEndian.PutUint32(data[24:28], sequence)
			binary.BigEndian.PutUint32(data[28:32], ack)
			data[32], data[33], data[34], data[35] = 0x50, flags, 0xff, 0xff
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			var packets stack.PacketBufferList
			packets.PushBack(packet)
			n, err := ep.WritePackets(packets)
			packet.DecRef()
			if err != nil || n != 1 {
				t.Fatalf("raw send failed: %d %v", n, err)
			}
		}
		waitFor := func(payload bool) []byte {
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			for {
				select {
				case p := <-replies:
					if !bytes.Equal(p[16:20], client[:]) || binary.BigEndian.Uint16(p[22:24]) != 42000 {
						t.Fatal("reply crossed worker boundary")
					}
					ihl := int(p[0]&15) * 4
					headerLen := int(p[ihl+12]>>4) * 4
					if payload && bytes.Contains(p[ihl+headerLen:], []byte("isolated-payload")) {
						return p
					}
					if !payload && p[ihl+13]&0x12 == 0x12 {
						return p
					}
				case <-deadline.C:
					t.Fatal("local TCP reply timed out")
					return nil
				}
			}
		}
		send(2, seq, 0)
		synACK := waitFor(false)
		send(0x10, seq+1, binary.BigEndian.Uint32(synACK[24:28])+1)
		waitFor(true)
	}
}

// The invalid send FD ensures this regression test never sends a real packet.
// Flow registration happens before sendto, so SNAT ownership is still tested.
func TestNATRetainsOriginalClientAddress(t *testing.T) {
	for _, proto := range []byte{6, 17} {
		original := [4]byte{10, 10, 10, 42}
		data := make([]byte, 40)
		data[0], data[3], data[8], data[9] = 0x45, 40, 64, proto
		copy(data[12:16], original[:])
		copy(data[16:20], []byte{77, 88, 8, 8})
		data[20], data[21], data[23], data[32], data[33] = 0x80, 1, 53, 0x50, 2
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		var packets stack.PacketBufferList
		packets.PushBack(pkt)
		ep := &RawSocketEndpoint{sendFd: -1}
		defer ep.pruneFlows(time.Now(), true)
		ep.SetClientIP(original)
		ep.WritePackets(packets)
		pkt.DecRef()
		var flow flowState
		found := false
		ep.activeFlows.Range(func(_, value any) bool { flow = value.(flowState); found = true; return false })
		if !found {
			t.Fatalf("protocol %d: missing flow", proto)
		}
		if got := flow.clientIP; got != original {
			t.Fatalf("protocol %d: NAT reply address %v, want %v", proto, got, original)
		}
	}
}

func TestIndependentWorkersReserveDistinctPorts(t *testing.T) {
	for _, protocol := range []byte{6, 17} {
		a, b := &RawSocketEndpoint{}, &RawSocketEndpoint{}
		defer a.pruneFlows(time.Now(), true)
		defer b.pruneFlows(time.Now(), true)
		input := clientFlowKey{flowKey: flowKey{protocol: protocol, remoteIP: [4]byte{8, 8, 8, 8}, remotePort: 53, localPort: 42000}, clientIP: [4]byte{10, 10, 10, 2}}
		first, _, ok := a.claimFlow(input, 10, true, false)
		if !ok {
			t.Fatal("first reservation failed")
		}
		input.clientIP[3] = 3
		second, _, ok := b.claimFlow(input, 10, true, false)
		if !ok || first.localPort == second.localPort {
			t.Fatal("workers share an external source port")
		}
		if _, ok := a.replyFlow(second, false, 0); ok {
			t.Fatal("cross-worker reply accepted")
		}
		state, ok := b.replyFlow(second, false, 0)
		if !ok || state.clientIP != input.clientIP || state.original.localPort != 42000 {
			t.Fatal("reply lost its client identity")
		}
		again, _, _ := b.claimFlow(input, 10, true, false)
		if again != second {
			t.Fatal("retransmission allocated a second port")
		}
	}
}

func TestNATQuotaAndHalfClose(t *testing.T) {
	ep := &RawSocketEndpoint{maxFlows: 1}
	defer ep.pruneFlows(time.Now(), true)
	input := clientFlowKey{flowKey: flowKey{protocol: 6, remoteIP: [4]byte{8, 8, 8, 8}, remotePort: 443, localPort: 42000}, clientIP: [4]byte{10, 10, 10, 2}}
	key, _, ok := ep.claimFlow(input, 123, true, false)
	if !ok {
		t.Fatal("claim failed")
	}
	other := input
	other.localPort++
	if _, _, ok := ep.claimFlow(other, 0, true, false); ok {
		t.Fatal("quota exceeded")
	}
	if _, _, ok := ep.claimFlow(input, 0, false, true); !ok {
		t.Fatal("FIN dropped")
	}
	if _, ok := ep.replyFlow(key, false, 0); !ok {
		t.Fatal("half-close deleted mapping")
	}
	if _, ok := ep.replyFlow(key, true, 999); ok {
		t.Fatal("wrong SYN ACK accepted")
	}
	ep.pruneFlows(time.Now().Add(31*time.Second), false)
	if _, ok := ep.replyFlow(key, false, 0); ok {
		t.Fatal("expired reply accepted")
	}
	if _, _, ok := ep.claimFlow(other, 0, true, false); !ok {
		t.Fatal("quota not released")
	}
	ep.pruneFlows(time.Now(), true)
	if _, _, ok := ep.claimFlow(input, 0, true, false); ok {
		t.Fatal("closed NAT accepted packet")
	}
}

func TestConcurrentNATQuota(t *testing.T) {
	ep := &RawSocketEndpoint{maxFlows: 16}
	defer ep.pruneFlows(time.Now(), true)
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			ep.claimFlow(clientFlowKey{flowKey: flowKey{protocol: 17, localPort: uint16(port + 30000)}, clientIP: [4]byte{10, 10, 10, 2}}, 0, true, false)
		}(i)
	}
	wg.Wait()
	if len(ep.flowIndex) != 16 || ep.flowRejected.Load() != 112 {
		t.Fatal("concurrent quota is not bounded")
	}
}
