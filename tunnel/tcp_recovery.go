package tunnel

import (
	"fmt"
	"os"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Experimental per-process opt-in. Unset/default retains gVisor's recovery;
// classic disables RACK/TLP but retains duplicate-ACK/SACK and RTO recovery.
// CLI rejects classic on non-document transports. No production default flip.
func ParseTCPRecoveryMode(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default", "rack":
		return "default", nil
	case "classic":
		return "classic", nil
	default:
		return "", fmt.Errorf("invalid TCP recovery mode (want default or classic)")
	}
}

func configureTCPRecovery(s *stack.Stack, mode string) error {
	parsed, err := ParseTCPRecoveryMode(mode)
	if err != nil {
		return err
	}
	if parsed == "classic" {
		recovery := tcpip.TCPRecovery(0)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
			return fmt.Errorf("set TCP recovery: %s", err)
		}
	}
	return nil
}

func tcpRecoveryEnvironment() string { return os.Getenv("PAPERFLUX_TCP_RECOVERY") }
