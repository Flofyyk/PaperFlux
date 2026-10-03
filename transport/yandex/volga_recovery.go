package yandex

func isVolgaKeepalive(data []byte) bool { return len(data) == 1 && data[0] == 0 }

// Observe is called once per five-second interval. Only an unanswered user
// request starts the timer; keepalives and idle periods alone never do.
type stalledTraffic struct {
	unanswered int
	pending    bool
}

func (s *stalledTraffic) Observe(sent, received uint64) bool {
	if received > 0 {
		s.unanswered, s.pending = 0, false
		return false
	}
	if sent > 0 {
		s.pending = true
	}
	if !s.pending {
		return false
	}
	s.unanswered++
	if s.unanswered < 12 {
		return false
	}
	s.unanswered, s.pending = 0, false
	return true
}
