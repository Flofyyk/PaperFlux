package transport

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// ReliableTransport is a negotiated reliability layer for parallel document
// lanes. It stays transparent until both endpoints advertise support, so a
// new client can still exchange normal IP packets with an older endpoint.
// The enclosing Yandex/PFS2 transport authenticates every control and data
// frame; this layer supplies delivery identity and bounded retry semantics.
const (
	reliableMagic                 = "PFR1"
	reliableHeaderSize            = 4 + 1 + 8 + 8
	reliableHello            byte = 1
	reliableAck              byte = 2
	reliableData             byte = 3
	reliableMaxPending            = 384
	reliableMaxBytes              = 3 << 20
	reliableSoftPending           = 288
	reliableSoftBytes             = 1536 << 10
	reliableBackpressureWait      = 120 * time.Millisecond
)

type ReliableTransport struct {
	Transport
	BaseTransport

	mu        sync.Mutex
	sessionID uint64
	peerID    uint64
	sequence  uint64
	ready     bool
	pending   map[uint64]*reliablePending
	seen      map[reliableKey]time.Time
	pendingN  uint64
	pendingB  uint64
	srtt      time.Duration
	rttvar    time.Duration
	rto       time.Duration
	retrans   atomic.Uint64
	drops     atomic.Uint64
	stop      chan struct{}
	stopOnce  sync.Once
	spaceCh   chan struct{}
}

type reliablePending struct {
	frame   []byte
	sentAt  time.Time
	attempt int
}

type reliableKey struct{ session, sequence uint64 }

func NewReliableTransport(inner Transport, config TransportConfig) (*ReliableTransport, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("reliable session id: %w", err)
	}
	return &ReliableTransport{
		Transport:     inner,
		BaseTransport: *NewBaseTransport(config),
		sessionID:     binary.BigEndian.Uint64(random[:]),
		pending:       make(map[uint64]*reliablePending),
		seen:          make(map[reliableKey]time.Time),
		stop:          make(chan struct{}),
		spaceCh:       make(chan struct{}),
		rto:           time.Second,
	}, nil
}

func (t *ReliableTransport) Start() error {
	if err := t.Transport.Start(); err != nil {
		return err
	}
	if err := t.BaseTransport.Start(); err != nil {
		_ = t.Transport.Stop()
		return err
	}
	t.Transport.Receive(t.handleReceive)
	go t.controlLoop()
	return nil
}

func (t *ReliableTransport) Stop() error {
	t.stopOnce.Do(func() { close(t.stop) })
	_ = t.BaseTransport.Stop()
	t.mu.Lock()
	clear(t.pending)
	clear(t.seen)
	t.pendingN, t.pendingB = 0, 0
	t.signalSpaceLocked()
	t.mu.Unlock()
	return t.Transport.Stop()
}

func (t *ReliableTransport) Send(packet []byte) error {
	deadline := time.Now().Add(reliableBackpressureWait)
	for {
		t.mu.Lock()
		ready := t.ready
		full := t.pendingN >= reliableMaxPending || t.pendingB+uint64(len(packet)) > reliableMaxBytes
		softFull := t.pendingN >= reliableSoftPending || t.pendingB+uint64(len(packet)) > reliableSoftBytes
		if !ready {
			t.mu.Unlock()
			return t.Transport.Send(packet)
		}
		if !full && !softFull {
			break
		}
		waitCh := t.spaceCh
		t.mu.Unlock()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.drops.Add(1)
			return fmt.Errorf("reliable pending window backpressure")
		}
		timer := time.NewTimer(min(remaining, 10*time.Millisecond))
		select {
		case <-waitCh:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
	t.sequence++
	seq := t.sequence
	frame := reliableFrame(reliableData, t.sessionID, seq, packet)
	t.pending[seq] = &reliablePending{frame: frame, sentAt: time.Now()}
	t.pendingN++
	t.pendingB += uint64(len(packet))
	t.mu.Unlock()
	if err := t.Transport.Send(frame); err != nil {
		t.mu.Lock()
		if entry, exists := t.pending[seq]; exists {
			delete(t.pending, seq)
			t.pendingN--
			t.pendingB -= uint64(len(entry.frame) - reliableHeaderSize)
			t.signalSpaceLocked()
		}
		t.mu.Unlock()
		return err
	}
	t.RecordSend(len(packet))
	return nil
}

func (t *ReliableTransport) IsConnected() bool { return t.Transport.IsConnected() }

func (t *ReliableTransport) Receive(callback func([]byte)) { t.BaseTransport.Receive(callback) }

func (t *ReliableTransport) Stats() TransportStats {
	s := t.Transport.Stats()
	t.mu.Lock()
	s.QueuePackets = t.pendingN
	s.QueueBytes = t.pendingB
	t.mu.Unlock()
	s.RetryQueued = t.retrans.Load()
	s.ExpiredDrops += t.drops.Load()
	s.Connected = t.IsConnected()
	return s
}

func (t *ReliableTransport) handleReceive(frame []byte) {
	kind, session, sequence, payload, ok := parseReliableFrame(frame)
	if !ok {
		t.RecordReceive(len(frame))
		t.CallReceive(frame)
		return
	}
	switch kind {
	case reliableHello:
		t.mu.Lock()
		t.peerID = session
		t.ready = true
		t.mu.Unlock()
		_ = t.Transport.Send(reliableFrame(reliableAck, session, 0, nil))
	case reliableAck:
		t.mu.Lock()
		if session == t.sessionID {
			if sequence == 0 {
				t.ready = true
			} else if entry, exists := t.pending[sequence]; exists {
				// Retransmitted packets have ambiguous ACK timing (Karn's rule).
				if entry.attempt == 0 {
					t.observeRTTLocked(time.Since(entry.sentAt))
				}
				delete(t.pending, sequence)
				t.pendingN--
				t.pendingB -= uint64(len(entry.frame) - reliableHeaderSize)
				t.signalSpaceLocked()
			}
		}
		t.mu.Unlock()
	case reliableData:
		key := reliableKey{session: session, sequence: sequence}
		now := time.Now()
		t.mu.Lock()
		_, duplicate := t.seen[key]
		t.seen[key] = now
		t.ready = true
		t.mu.Unlock()
		_ = t.Transport.Send(reliableFrame(reliableAck, session, sequence, nil))
		if !duplicate {
			t.RecordReceive(len(payload))
			t.CallReceive(payload)
		}
	}
}

func (t *ReliableTransport) observeRTTLocked(sample time.Duration) {
	if t.srtt == 0 {
		t.srtt, t.rttvar = sample, sample/2
	} else {
		delta := t.srtt - sample
		if delta < 0 {
			delta = -delta
		}
		t.rttvar = (3*t.rttvar + delta) / 4
		t.srtt = (7*t.srtt + sample) / 8
	}
	t.rto = max(time.Second, min(8*time.Second, t.srtt+4*t.rttvar))
}

func (t *ReliableTransport) controlLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	nextHello := time.Time{}
	nextStats := time.Now().Add(5 * time.Second)
	for {
		select {
		case <-t.stop:
			return
		case now := <-ticker.C:
			var outbound [][]byte
			t.mu.Lock()
			ready := t.ready
			if !ready && (nextHello.IsZero() || !now.Before(nextHello)) {
				nextHello = now.Add(2 * time.Second)
				outbound = append(outbound, reliableFrame(reliableHello, t.sessionID, 0, nil))
			}
			for seq, entry := range t.pending {
				rto := min(8*time.Second, t.rto*time.Duration(1<<min(entry.attempt, 3)))
				if now.Sub(entry.sentAt) < rto {
					continue
				}
				if entry.attempt >= 4 {
					delete(t.pending, seq)
					t.pendingN--
					t.pendingB -= uint64(len(entry.frame) - reliableHeaderSize)
					t.drops.Add(1)
					t.signalSpaceLocked()
					continue
				}
				entry.attempt++
				entry.sentAt = now
				outbound = append(outbound, entry.frame)
				t.retrans.Add(1)
			}
			for key, seenAt := range t.seen {
				if now.Sub(seenAt) > 2*time.Minute {
					delete(t.seen, key)
				}
			}
			if !now.Before(nextStats) {
				nextStats = now.Add(5 * time.Second)
				log.Printf("[PAPERFLUX_RELIABLE] pending=%d bytes=%d retry=%d dropped=%d rtt_ms=%d rto_ms=%d", t.pendingN, t.pendingB, t.retrans.Load(), t.drops.Load(), t.srtt.Milliseconds(), t.rto.Milliseconds())
			}
			t.mu.Unlock()
			for _, frame := range outbound {
				_ = t.Transport.Send(frame)
			}
		}
	}
}

// signalSpaceLocked wakes producers waiting for ACK window capacity. The
// channel is replaced under the same mutex so a wakeup cannot be lost.
func (t *ReliableTransport) signalSpaceLocked() {
	close(t.spaceCh)
	t.spaceCh = make(chan struct{})
}

func reliableFrame(kind byte, session, sequence uint64, payload []byte) []byte {
	frame := make([]byte, reliableHeaderSize+len(payload))
	copy(frame, reliableMagic)
	frame[4] = kind
	binary.BigEndian.PutUint64(frame[5:13], session)
	binary.BigEndian.PutUint64(frame[13:21], sequence)
	copy(frame[21:], payload)
	return frame
}

func parseReliableFrame(frame []byte) (byte, uint64, uint64, []byte, bool) {
	if len(frame) < reliableHeaderSize || string(frame[:4]) != reliableMagic {
		return 0, 0, 0, nil, false
	}
	kind := frame[4]
	if kind != reliableHello && kind != reliableAck && kind != reliableData {
		return 0, 0, 0, nil, false
	}
	return kind, binary.BigEndian.Uint64(frame[5:13]), binary.BigEndian.Uint64(frame[13:21]), frame[21:], true
}
