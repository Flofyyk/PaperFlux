package transport

import "errors"

// SetBatchByteLimit changes only local queue admission, not the wire format.
// Configure before attaching any lane; all lanes of a Session get this cap.
func (s *Session) SetBatchByteLimit(bytes int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || len(s.links) > 0 || bytes < 65536 || bytes > 16<<20 {
		return errors.New("invalid batch budget or lifecycle")
	}
	s.batchByteLimit = bytes
	return nil
}
func (s *Session) newBatched(inner Transport) *BatchedTransport {
	s.mu.Lock()
	budget := s.batchByteLimit
	s.mu.Unlock()
	return newBatchedTransportWithBudget(inner, budget)
}
func (s *Session) QueuedBatchBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int64
	for _, link := range s.links {
		total += link.batched.queueBytes.Load()
	}
	return total
}
