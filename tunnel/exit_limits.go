package tunnel

import (
	"encoding/binary"
	"os"
	"strconv"

	"golang.org/x/time/rate"
)

// Pure TCP acknowledgements and connection lifecycle packets must not wait
// for bulk-data reservations. Otherwise a capped upload can stall downloads
// (ACKs), and a capped download can stall new connections (SYN/FIN/RST).
// Count every data-bearing, fragmented or malformed packet at full wire size.
// Traffic accounting is unchanged: this only selects the pacing budget.
func pacedPacketBytes(packet []byte) int {
	n := len(packet)
	if n < 40 || packet[0]>>4 != 4 || packet[9] != 6 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != n ||
		binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return n
	}
	ipHeader := int(packet[0]&15) * 4
	if ipHeader < 20 || ipHeader+20 > n {
		return n
	}
	tcpHeader := int(packet[ipHeader+12]>>4) * 4
	if tcpHeader < 20 || ipHeader+tcpHeader != n || packet[ipHeader+13]&0x17 == 0 {
		return n
	}
	return 0
}

func configuredFlowLimit() int {
	value, err := strconv.Atoi(os.Getenv("PAPERFLUX_MAX_FLOWS"))
	if err != nil || value < 16 || value > 4096 {
		return 256
	}
	return value
}

// Independent upload/download buckets per profile worker. Session hellos,
// keepalives and authentication are outside the IP data path and are not
// throttled. Zero keeps the historical unlimited setting for private exits.
func newExitLimiter() *rate.Limiter {
	mbit, err := strconv.ParseFloat(os.Getenv("PAPERFLUX_MAX_MBIT"), 64)
	if err != nil || !(mbit >= 0.25 && mbit <= 10000) {
		return nil
	}
	return rate.NewLimiter(rate.Limit(mbit*1_000_000/8), 128*1024)
}
