package tunnel

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"time"
)

// Probe DNS over TCP through the actual tunneled stack. A valid DNS response
// verifies both TCP directions and DNS; no direct-network fallback is used.
func (t *TCPTunnel) Probe(ctx context.Context) error {
	var last error
	for _, target := range []string{"77.88.8.8:53", "77.88.8.1:53"} {
		conn, err := t.DialProbe(ctx, target)
		if err != nil {
			last = err
			continue
		}
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		dc := &dns.Conn{Conn: conn}
		q := new(dns.Msg).SetQuestion("yandex.ru.", dns.TypeA)
		err = dc.WriteMsg(q)
		if err == nil {
			var answer *dns.Msg
			answer, err = dc.ReadMsg()
			if err == nil && (answer.Id != q.Id || !answer.Response || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) == 0) {
				err = fmt.Errorf("invalid DNS probe response")
			}
		}
		_ = conn.Close()
		if err == nil {
			return nil
		}
		last = err
	}
	return last
}
func (t *TCPTunnel) RunHealthChecks() {
	healthy := false
	failures := 0
	const probeInterval = 45 * time.Second
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		err := t.Probe(ctx)
		cancel()
		if err == nil {
			failures = 0
			if !healthy {
				log.Printf("[PAPERFLUX] TUNNEL_READY: DNS/TCP via exit verified")
				healthy = true
			} else {
				// A quiet heartbeat refreshes Android's persisted connection state
				// without publishing another visible CONNECTED journal event.
				log.Printf("[PAPERFLUX] TUNNEL_HEALTHY")
			}
		} else {
			failures++
			if failures <= 2 || failures%6 == 0 {
				log.Printf("[PAPERFLUX] TUNNEL_PROBE_FAILED: %v", err)
			}
			if healthy && failures >= 3 {
				log.Printf("[PAPERFLUX] TUNNEL_LOST: DNS/TCP via exit failed")
				healthy = false
			}
		}
		time.Sleep(probeInterval)
	}
}
