package tunnel

import (
	"fmt"
	"os"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// classic disables RACK/TLP but retains duplicate-ACK/SACK and RTO recovery.
// Explicit default/rack retains gVisor's recovery. The CLI resolves auto to
// classic only for document transports, leaving unrelated transports unchanged.
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

func ResolveTCPRecoveryMode(value, provider string) (string, error) {
	if normalized := strings.ToLower(strings.TrimSpace(value)); normalized == "" || normalized == "auto" {
		switch provider {
		case "yandex", "vyandex", "mailru":
			return "classic", nil
		default:
			return "default", nil
		}
	}
	return ParseTCPRecoveryMode(value)
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
