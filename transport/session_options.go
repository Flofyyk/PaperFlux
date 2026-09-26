package transport

import "time"

// Configure bounded recovery detection before Start. A shorter ping interval
// detects a restarted peer without reducing the tolerance for transient gaps.
func (s *Session) SetRecoveryTiming(interval, timeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started && interval >= time.Second && timeout >= 3*interval && timeout <= 2*time.Minute {
		s.keepaliveInterval, s.linkTimeout = interval, timeout
	}
}

// Interactive verification consumes no network-handshake budget. Stop still
// interrupts immediately, and waitReady keeps an absolute 30 minute limit.
func (s *Session) SetHandshakePause(fn func() bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		s.handshakePaused = fn
	}
}

func (s *Session) SetControlOnly(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		if l := s.links[name]; l != nil {
			l.controlOnly = true
		}
	}
}

func (s *Session) dataLinksLocked() []*transportLink {
	all := s.liveLinksLocked()
	out := all[:0]
	for _, l := range all {
		// A service-channel handshake proves the peer identity, not that any
		// document reaches it. Require a proof received on this physical lane.
		if !l.controlOnly && !l.lastHeard.IsZero() && time.Since(l.lastHeard) < s.linkTimeout {
			out = append(out, l)
		}
	}
	return out
}

func (s *Session) HasDataPath() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready && !s.stopped && len(s.dataLinksLocked()) > 0
}

func (s *Session) DataRTT() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best time.Duration
	for _, l := range s.dataLinksLocked() {
		if l.rtt > 0 && (best == 0 || l.rtt < best) {
			best = l.rtt
		}
	}
	return best
}

// SetHandshakeTimeout lets the app keep IPC alive while a person completes
// an interactive verification; it must be configured before Start.
func (s *Session) SetHandshakeTimeout(timeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started && timeout > 0 && timeout <= 10*time.Minute {
		s.handshakeTimeout = timeout
	}
}
