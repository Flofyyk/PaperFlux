package tunnel

import (
	"os"
	"strconv"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Per-process tuning; unset keeps the small multi-profile defaults. The exit
// deployment must budget both directions against its flow and memory limits.
func configuredTCPBuffers() (int, int) {
	def, maxSize := 256<<10, 1<<20
	if value, err := strconv.Atoi(os.Getenv("PAPERFLUX_TCP_BUFFER_KIB")); err == nil && value >= 256 && value <= 2048 {
		def = value << 10
	}
	if value, err := strconv.Atoi(os.Getenv("PAPERFLUX_TCP_BUFFER_MAX_KIB")); err == nil && value >= 256 && value <= 2048 {
		maxSize = value << 10
	}
	if maxSize < def {
		maxSize = def
	}
	return def, maxSize
}

func configureTCPBuffers(s *stack.Stack) tcpip.Error {
	def, maxSize := configuredTCPBuffers()
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 65536, Default: def, Max: maxSize}); err != nil {
		return err
	}
	return s.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPSendBufferSizeRangeOption{Min: 65536, Default: def, Max: maxSize})
}
