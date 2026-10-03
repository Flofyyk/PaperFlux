package transport

import (
	"hash/fnv"
	"math"
	"sync"
	"time"
)

type laneCandidate struct {
	name     string
	health   LaneHealth
	stats    TransportStats
	flows    uint64
	priority int
}
type laneSample struct {
	rtt, rate, failure            float64
	bytes, failures, reconnects   uint64
	last, badSince, recoverySince time.Time
	connected, demoted            bool
}
type laneSelector struct {
	mu          sync.Mutex
	samples     map[string]*laneSample
	pins        map[string]selectorPin
	lastCleanup time.Time
}
type selectorPin struct {
	name string
	seen time.Time
}

// Rate-limit observation: do not repeatedly smooth the same ping on every
// packet, and do not confuse an idle channel with a zero-capacity channel.
func (s *laneSelector) costs(candidates []laneCandidate, now time.Time, costs []float64, eligible []bool) {
	if s.samples == nil {
		s.samples = make(map[string]*laneSample)
	}
	bestRTT, maxRate := 0.0, 0.0
	for name, p := range s.samples {
		present := false
		for _, c := range candidates {
			if c.name == name {
				present = true
				break
			}
		}
		if !present {
			p.connected, p.demoted, p.recoverySince = false, true, time.Time{}
		}
	}
	for _, c := range candidates {
		p := s.samples[c.name]
		if p == nil {
			p = &laneSample{rtt: float64(c.health.RTT.Milliseconds()), bytes: c.stats.BytesSent + c.stats.BytesReceived, failures: c.health.WriteFailures, reconnects: c.stats.Reconnects, last: now, connected: c.health.Connected}
			s.samples[c.name] = p
		}
		if !c.health.Connected {
			p.connected, p.demoted, p.recoverySince = false, true, time.Time{}
			continue
		}
		if !p.connected {
			p.connected, p.recoverySince = true, now
		}
		if dt := now.Sub(p.last); dt >= time.Second {
			if c.health.RTT > 0 {
				rtt := float64(c.health.RTT.Milliseconds())
				if p.rtt <= 0 {
					p.rtt = rtt
				} else {
					p.rtt += .2 * (rtt - p.rtt)
				}
			}
			bytes := c.stats.BytesSent + c.stats.BytesReceived
			if bytes > p.bytes {
				rate := float64(bytes-p.bytes) / dt.Seconds()
				if p.rate == 0 {
					p.rate = rate
				} else {
					p.rate += .2 * (rate - p.rate)
				}
			}
			failed := 0.0
			if c.health.WriteFailures > p.failures {
				failed = 1
			}
			p.failure += .2 * (failed - p.failure)
			p.bytes, p.failures, p.reconnects, p.last = bytes, c.health.WriteFailures, c.stats.Reconnects, now
		}
		if p.rtt > 0 && (bestRTT == 0 || p.rtt < bestRTT) {
			bestRTT = p.rtt
		}
		maxRate = max(maxRate, p.rate)
	}
	for i, c := range candidates {
		p := s.samples[c.name]
		if !c.health.Connected {
			continue
		}
		// Relative RTT policy: a fixed 150ms cutoff rejects working Docs links.
		bad := c.health.QueueLoad >= .9 || p.failure >= .4 || (bestRTT > 0 && p.rtt > max(1000, bestRTT*3))
		if bad {
			p.recoverySince = time.Time{}
			if p.badSince.IsZero() {
				p.badSince = now
			}
			if now.Sub(p.badSince) >= 3*time.Second {
				p.demoted = true
			}
		} else {
			p.badSince = time.Time{}
			if p.demoted {
				if p.recoverySince.IsZero() {
					p.recoverySince = now
				}
				if now.Sub(p.recoverySince) >= 2*time.Second {
					p.demoted, p.recoverySince = false, time.Time{}
				}
			}
		}
		cost := c.health.QueueLoad*10000 + p.rtt + p.failure*2000 + float64(min(p.reconnects, 20))*20 + float64(c.flows)*5
		if maxRate > 0 {
			cost += 100 * (1 - math.Sqrt(p.rate/maxRate))
		}
		costs[i], eligible[i] = cost, !p.demoted
	}
}

// Whole flows stay pinned while healthy. Weighted rendezvous chooses new
// Session flows; empty keys choose the least-loaded control/new-flow route.
func (s *laneSelector) pick(candidates []laneCandidate, key string, rotation int, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var localCosts [8]float64
	var localEligible [8]bool
	costs, eligible := localCosts[:], localEligible[:]
	if len(candidates) > len(localCosts) {
		costs, eligible = make([]float64, len(candidates)), make([]bool, len(candidates))
	}
	s.costs(candidates, now, costs, eligible)
	if s.pins == nil {
		s.pins = make(map[string]selectorPin)
	}
	if now.Sub(s.lastCleanup) >= time.Minute {
		for k, p := range s.pins {
			if now.Sub(p.seen) > 5*time.Minute {
				delete(s.pins, k)
			}
		}
		s.lastCleanup = now
	}
	if key != "" {
		if pin, ok := s.pins[key]; ok {
			for i, c := range candidates {
				if c.name == pin.name && c.health.Connected && eligible[i] {
					s.pins[key] = selectorPin{c.name, now}
					return i
				}
			}
			delete(s.pins, key)
		}
	}
	best, rank := -1, math.Inf(1)
	for pass := 0; pass < 2 && best < 0; pass++ {
		bestPriority, havePriority := 0, false
		for i, c := range candidates {
			if c.health.Connected && (pass != 0 || eligible[i]) && (!havePriority || c.priority > bestPriority) {
				bestPriority, havePriority = c.priority, true
			}
		}
		for offset := range candidates {
			i := (offset + rotation) % len(candidates)
			c := candidates[i]
			if !c.health.Connected || c.priority != bestPriority || (pass == 0 && !eligible[i]) {
				continue
			}
			r := costs[i]
			if key != "" {
				hash := fnv.New64a()
				_, _ = hash.Write([]byte(key))
				_, _ = hash.Write([]byte("\x00" + c.name))
				h := hash.Sum64()
				u := (float64(h>>11) + 1) / (float64(uint64(1)<<53) + 1)
				r = -math.Log(u) * (1 + costs[i]/100)
			}
			if r < rank {
				best, rank = i, r
			}
		}
	}
	if best >= 0 && key != "" && len(s.pins) < 4096 {
		s.pins[key] = selectorPin{candidates[best].name, now}
	}
	return best
}

func (s *laneSelector) noteResult(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.samples[name]; p != nil {
		if err != nil {
			p.failure += .2 * (1 - p.failure)
		} else {
			p.failure *= .98
		}
	}
}
func (s *laneSelector) forgetFlow(key string) { s.mu.Lock(); delete(s.pins, key); s.mu.Unlock() }

func (s *laneSelector) isDemoted(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.samples[name]
	return p != nil && p.demoted
}

func (s *laneSelector) rememberFlow(key, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pins == nil {
		s.pins = make(map[string]selectorPin)
	}
	if key != "" && len(s.pins) < 4096 {
		s.pins[key] = selectorPin{name, time.Now()}
	}
}
