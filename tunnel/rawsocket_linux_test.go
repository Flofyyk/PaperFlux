package tunnel

import (
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"testing"
)

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
		ep.SetClientIP(original)
		ep.WritePackets(packets)
		pkt.DecRef()
		key := flowKey{protocol: proto, remoteIP: [4]byte{77, 88, 8, 8}, remotePort: 53, localPort: 32769}
		flow, ok := ep.activeFlows.Load(key)
		if !ok {
			t.Fatalf("protocol %d: missing flow", proto)
		}
		if got := flow.(flowState).clientIP; got != original {
			t.Fatalf("protocol %d: NAT reply address %v, want %v", proto, got, original)
		}
	}
}
