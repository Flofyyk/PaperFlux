package tunnel

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// Probe DNS over TCP through the actual tunneled stack. A valid DNS response
// verifies both TCP directions and DNS; no direct-network fallback is used.
func (t *TCPTunnel) Probe(ctx context.Context) error {
	return probeDNS(ctx, t.DialProbe, probeResolvers(), 6*time.Second)
}

func probeResolvers() []string {
	values := []string{os.Getenv("PAPERFLUX_DNS_PRIMARY"), os.Getenv("PAPERFLUX_DNS_SECONDARY")}
	defaults := []string{"77.88.8.8", "77.88.8.1"}
	var targets []string
	for i, value := range values {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			ip = net.ParseIP(defaults[i])
		}
		target := net.JoinHostPort(ip.String(), "53")
		if len(targets) == 0 || targets[0] != target {
			targets = append(targets, target)
		}
	}
	return targets
}

// Each resolver receives a fresh budget. The parent is the session lifetime,
// not the first resolver's deadline. Cancellation still stops every attempt.
func probeDNS(ctx context.Context, dial func(context.Context, string) (net.Conn, error), targets []string, timeout time.Duration) error {
	var failures []string
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt, cancel := context.WithTimeout(ctx, timeout)
		conn, err := dial(attempt, target)
		if err != nil {
			failures = append(failures, probeFailure(target, "tcp", err))
			cancel()
			continue
		}
		stop := context.AfterFunc(attempt, func() { _ = conn.Close() })
		deadline, _ := attempt.Deadline()
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
		if attempt.Err() != nil {
			err = attempt.Err()
		}
		stop()
		_ = conn.Close()
		cancel()
		if err == nil {
			return nil
		}
		failures = append(failures, probeFailure(target, "dns", err))
	}
	return fmt.Errorf("%s", strings.Join(failures, "; "))
}

// Stable, bounded public diagnostics; never include arbitrary network payloads.
func probeFailure(target, stage string, err error) string {
	kind := "failed"
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		kind = "timeout"
	}
	return fmt.Sprintf("resolver=%s stage=%s reason=%s", target, stage, kind)
}
func (t *TCPTunnel) RunHealthChecks() {
	healthy := false
	failures := 0
	schedule := healthSchedule{}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-t.lifecycleContext.Done():
			return
		case <-tick.C:
		}
		carrierReady := t.transport.IsConnected()
		if !schedule.due(time.Now(), carrierReady) {
			continue
		}
		err := t.Probe(t.lifecycleContext)
		schedule.completed(time.Now(), err == nil)
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
	}
}

// A carrier recovery makes the end-to-end probe due immediately, even if a
// previous successful probe scheduled the next idle check 45 seconds later.
// The inexpensive ticker sends no traffic while carriers are unavailable.
type healthSchedule struct {
	carrier bool
	next    time.Time
}

func (s *healthSchedule) due(now time.Time, carrier bool) bool {
	if !carrier {
		s.carrier = false
		return false
	}
	if !s.carrier {
		s.carrier = true
		s.next = time.Time{}
	}
	return !now.Before(s.next)
}

func (s *healthSchedule) completed(now time.Time, success bool) {
	s.next = now.Add(healthProbeDelay(success))
}

func healthProbeDelay(success bool) time.Duration {
	if success {
		return 45 * time.Second
	}
	return 3 * time.Second
}
