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
func configuredTCPBufferRange() (int, int, int) {
	// Exact current upstream values, explicit per-process only. The shared
	// multi-profile deployment keeps its bounded defaults unless opted in.
	if os.Getenv("PAPERFLUX_TCP_BUFFER_PRESET") == "upstream" {
		return 4 << 20, 16 << 20, 64 << 20
	}
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
	return 65536, def, maxSize
}

func configureTCPBuffers(s *stack.Stack) tcpip.Error {
	minSize, def, maxSize := configuredTCPBufferRange()
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: minSize, Default: def, Max: maxSize}); err != nil {
		return err
	}
	return s.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPSendBufferSizeRangeOption{Min: minSize, Default: def, Max: maxSize})
}
