package tunnel

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestTCPRecoveryModes(t *testing.T) {
	for _, mode := range []string{"", "default", "rack", "classic", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			s := stack.New(stack.Options{TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
			defer s.Destroy()
			var before, after tcpip.TCPRecovery
			if err := s.TransportProtocolOption(tcp.ProtocolNumber, &before); err != nil {
				t.Fatal(err)
			}
			err := configureTCPRecovery(s, mode)
			if (err != nil) != (mode == "invalid") {
				t.Fatalf("configuration error = %v", err)
			}
			if err := s.TransportProtocolOption(tcp.ProtocolNumber, &after); err != nil {
				t.Fatal(err)
			}
			if mode == "classic" {
				if after != 0 {
					t.Fatalf("classic recovery = %v", after)
				}
			} else if after != before {
				t.Fatal("non-opt-in changed the stack default")
			}
		})
	}
}
