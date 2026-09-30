package tunnel

import (
	"os"
	"strconv"

	"golang.org/x/time/rate"
)

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
