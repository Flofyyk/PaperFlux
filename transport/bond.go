package transport

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sync"
	"time"
)

// BondTransport is an experimental per-flow multipath layer. It stripes only
// sizeable TCP payloads; DNS, TCP setup/teardown and small packets retain the
// normal flow pinning in MultiTransport.
const (
	bondMagic            = "PFM3"
	bondHeaderSize       = 28
	bondMinPayload       = 384
	bondMaxBufferedFlow  = 128
	bondMaxBufferedTotal = 1024
	bondMinGapAge        = 12 * time.Millisecond
	bondMaxGapAge        = 80 * time.Millisecond
)

type bondPacket struct {
	payload  []byte
	received time.Time
}
type bondReorder struct {
	next     uint64
	pending  map[uint64]bondPacket
	gapSince time.Time
}
type bondStreamKey struct{ peer, flow uint64 }

type BondTransport struct {
	Transport
	BaseTransport
	mu       sync.Mutex
	session  uint64
	sequence map[uint64]uint64
	streams  map[bondStreamKey]*bondReorder
	pending  int
	stop     chan struct{}
	stopOnce sync.Once
}

func NewBondTransport(inner Transport, config TransportConfig) (*BondTransport, error) {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("bond session id: %w", err)
	}
	return &BondTransport{Transport: inner, BaseTransport: *NewBaseTransport(config), session: binary.BigEndian.Uint64(id[:]), sequence: make(map[uint64]uint64), streams: make(map[bondStreamKey]*bondReorder), stop: make(chan struct{})}, nil
}
func (t *BondTransport) Start() error {
	if err := t.Transport.Start(); err != nil {
		return err
	}
	if err := t.BaseTransport.Start(); err != nil {
		_ = t.Transport.Stop()
		return err
	}
	t.Transport.Receive(t.handleReceive)
	go t.reorderLoop()
	return nil
}
func (t *BondTransport) Stop() error {
	t.stopOnce.Do(func() { close(t.stop) })
	_ = t.BaseTransport.Stop()
	t.mu.Lock()
	clear(t.sequence)
	clear(t.streams)
	t.pending = 0
	t.mu.Unlock()
	return t.Transport.Stop()
}
func (t *BondTransport) Send(packet []byte) error {
	flow, eligible := bondEligibleFlow(packet)
	if gate, ok := t.Transport.(interface{ BondEligible() bool }); ok && !gate.BondEligible() {
		eligible = false
	}
	if !eligible {
		if err := t.Transport.Send(packet); err != nil {
			return err
		}
		t.RecordSend(len(packet))
		return nil
	}
	t.mu.Lock()
	t.sequence[flow]++
	seq, session := t.sequence[flow], t.session
	t.mu.Unlock()
	if err := t.Transport.Send(bondFrame(session, flow, seq, packet)); err != nil {
		return err
	}
	t.RecordSend(len(packet))
	return nil
}
func (t *BondTransport) IsConnected() bool             { return t.Transport.IsConnected() }
func (t *BondTransport) Receive(callback func([]byte)) { t.BaseTransport.Receive(callback) }
func (t *BondTransport) Stats() TransportStats {
	s := t.Transport.Stats()
	s.Connected = t.IsConnected()
	return s
}

func (t *BondTransport) handleReceive(frame []byte) {
	peer, flow, seq, payload, ok := parseBondFrame(frame)
	if !ok {
		t.RecordReceive(len(frame))
		t.CallReceive(frame)
		return
	}
	now := time.Now()
	key := bondStreamKey{peer, flow}
	t.mu.Lock()
	stream := t.streams[key]
	if stream == nil {
		stream = &bondReorder{next: 1, pending: make(map[uint64]bondPacket)}
		t.streams[key] = stream
	}
	if seq >= stream.next && len(stream.pending) < bondMaxBufferedFlow && t.pending < bondMaxBufferedTotal {
		if _, exists := stream.pending[seq]; !exists {
			stream.pending[seq] = bondPacket{payload, now}
			t.pending++
		}
	}
	deliver := t.collectLocked(stream, now, false)
	t.mu.Unlock()
	t.deliver(deliver)
}
func (t *BondTransport) reorderLoop() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case now := <-ticker.C:
			t.mu.Lock()
			var deliver [][]byte
			for _, s := range t.streams {
				deliver = append(deliver, t.collectLocked(s, now, true)...)
			}
			t.mu.Unlock()
			t.deliver(deliver)
		}
	}
}
func (t *BondTransport) collectLocked(s *bondReorder, now time.Time, expire bool) [][]byte {
	var deliver [][]byte
	for {
		entry, ok := s.pending[s.next]
		if !ok {
			break
		}
		delete(s.pending, s.next)
		t.pending--
		s.next++
		s.gapSince = time.Time{}
		deliver = append(deliver, entry.payload)
	}
	if len(s.pending) == 0 {
		s.gapSince = time.Time{}
		return deliver
	}
	if s.gapSince.IsZero() {
		s.gapSince = now
		return deliver
	}
	if !expire || now.Sub(s.gapSince) < t.reorderDeadline() {
		return deliver
	}
	lowest := uint64(0)
	for seq := range s.pending {
		if lowest == 0 || seq < lowest {
			lowest = seq
		}
	}
	if lowest > 0 {
		s.next = lowest
		s.gapSince = time.Time{}
		return append(deliver, t.collectLocked(s, now, false)...)
	}
	return deliver
}
func (t *BondTransport) reorderDeadline() time.Duration {
	if reporter, ok := t.Transport.(interface{ ReorderDeadline() time.Duration }); ok {
		if d := reporter.ReorderDeadline(); d > 0 {
			return d
		}
	}
	return bondMaxGapAge
}
func (t *BondTransport) deliver(packets [][]byte) {
	for _, p := range packets {
		t.RecordReceive(len(p))
		t.CallReceive(p)
	}
}

func bondEligibleFlow(packet []byte) (uint64, bool) {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+20 {
		return 0, false
	}
	tcp := int(packet[ihl+12]>>4) * 4
	if tcp < 20 || len(packet) < ihl+tcp+bondMinPayload || packet[ihl+13]&0x07 != 0 {
		return 0, false
	}
	key := flowKey(packet)
	if key == "" {
		return 0, false
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return h.Sum64(), true
}
func bondFrame(session, flow, seq uint64, payload []byte) []byte {
	frame := make([]byte, bondHeaderSize+len(payload))
	copy(frame, bondMagic)
	binary.BigEndian.PutUint64(frame[4:12], session)
	binary.BigEndian.PutUint64(frame[12:20], flow)
	binary.BigEndian.PutUint64(frame[20:28], seq)
	copy(frame[28:], payload)
	return frame
}
func parseBondFrame(frame []byte) (uint64, uint64, uint64, []byte, bool) {
	if len(frame) < bondHeaderSize || string(frame[:4]) != bondMagic {
		return 0, 0, 0, nil, false
	}
	return binary.BigEndian.Uint64(frame[4:12]), binary.BigEndian.Uint64(frame[12:20]), binary.BigEndian.Uint64(frame[20:28]), frame[28:], true
}
