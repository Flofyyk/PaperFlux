package transport

import (
	"encoding/binary"
	"hash/fnv"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// MultiTransport stripes independent IP flows across document transports.
// A five-tuple hash keeps every TCP flow on one lane, preserving packet order.
type MultiTransport struct {
	*BaseTransport
	lanes []Transport
	mu    sync.RWMutex
	// flowLanes is learned in both directions.  This is important on the exit
	// node: a reply packet must leave through the same Yandex document lane as
	// the packet that opened the flow, otherwise it can reach a different
	// Android worker/TCP stack and the connection stalls.
	flowLanes    map[string]flowBinding
	activeFlows  []uint64
	rr           atomic.Uint32
	receiveQueue chan []byte
	receiveStop  chan struct{}
	lastCleanup  time.Time
	lastReady    atomic.Int32
}

type flowBinding struct {
	lane   int
	seenAt time.Time
}

type queueLoadReporter interface {
	QueueLoad() float64
}

func NewMultiTransport(lanes []Transport, config TransportConfig) *MultiTransport {
	return &MultiTransport{BaseTransport: NewBaseTransport(config), lanes: lanes, flowLanes: make(map[string]flowBinding), activeFlows: make([]uint64, len(lanes))}
}

func (m *MultiTransport) Start() error {
	if err := m.BaseTransport.Start(); err != nil {
		return err
	}
	m.receiveQueue = make(chan []byte, m.GetConfig().MaxQueueSize)
	m.receiveStop = make(chan struct{})
	go m.receiveLoop()
	started := make([]Transport, 0, len(m.lanes))
	for laneIndex, lane := range m.lanes {
		// Keep document sessions out of the same Yandex balancer time bucket.
		// Starting both lanes on the same scheduler tick made their remote idle
		// rotations line up and caused a brief full outage on every rotation.
		if laneIndex > 0 {
			time.Sleep(4 * time.Second)
		}
		if err := lane.Start(); err != nil {
			for _, ready := range started {
				_ = ready.Stop()
			}
			close(m.receiveStop)
			_ = m.BaseTransport.Stop()
			return err
		}
		started = append(started, lane)
		idx := laneIndex
		lane.Receive(func(packet []byte) {
			// Learn the physical lane on which this flow arrived.  The binding is
			// consulted by Send for the reverse direction.
			m.bindFlow(packet, idx)
			// All lanes feed one dispatcher. TUN/gVisor consumers are not
			// guaranteed to support concurrent injection from several readers.
			select {
			case m.receiveQueue <- packet:
			case <-m.receiveStop:
			}
		})
	}
	go m.monitorLanes()
	go m.statsLoop()
	return nil
}

// LaneStatus reports authenticated document lines without exposing their URLs.
// It lets a UI distinguish a partial outage from a failed tunnel.
func (m *MultiTransport) LaneStatus() (ready, total int) {
	for _, lane := range m.lanes {
		if lane.IsConnected() {
			ready++
		}
	}
	return ready, len(m.lanes)
}

func (m *MultiTransport) monitorLanes() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for m.IsRunning() {
		ready, total := m.LaneStatus()
		if int32(ready) != m.lastReady.Swap(int32(ready)) {
			log.Printf("[PAPERFLUX_LANES] ready=%d/%d", ready, total)
		}
		<-ticker.C
	}
}

// statsLoop is deliberately owned by the aggregate transport.  Per-document
// counters are not comparable: they reset independently after a reconnect and
// made Android add one lane's total to another lane's total.
func (m *MultiTransport) statsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	previous := make([]TransportStats, len(m.lanes))
	for m.IsRunning() {
		<-ticker.C
		s := m.Stats()
		// A tunnel may have several independent document lanes. The UI needs one
		// meaningful control-plane RTT, not a fabricated average over routes with
		// different queues. Report the lowest current RTT among authenticated
		// lanes; it is the route selected for new flows under normal pressure.
		ping := time.Duration(0)
		for index, lane := range m.lanes {
			health := laneHealth(lane)
			if health.Connected && health.RTT > 0 && (ping == 0 || health.RTT < ping) {
				ping = health.RTT
			}
			laneStats := lane.Stats()
			txRate := (laneStats.BytesSent - previous[index].BytesSent) / 5
			rxRate := (laneStats.BytesReceived - previous[index].BytesReceived) / 5
			previous[index] = laneStats
			log.Printf("[PAPERFLUX_LANE] lane=%d connected=%t queue_ppm=%d rtt_ms=%d tx_bps=%d rx_bps=%d tx=%d rx=%d write_failures=%d", index+1, health.Connected, int(health.QueueLoad*1_000_000), health.RTT.Milliseconds(), txRate, rxRate, laneStats.BytesSent, laneStats.BytesReceived, health.WriteFailures)
		}
		log.Printf("[PAPERFLUX_STATS] rx=%d tx=%d ping=%d", s.BytesReceived, s.BytesSent, ping.Milliseconds())
	}
}

func (m *MultiTransport) Stop() error {
	if m.receiveStop != nil {
		select {
		case <-m.receiveStop:
		default:
			close(m.receiveStop)
		}
	}
	for _, lane := range m.lanes {
		_ = lane.Stop()
	}
	m.mu.Lock()
	m.flowLanes = make(map[string]flowBinding)
	m.activeFlows = make([]uint64, len(m.lanes))
	m.mu.Unlock()
	return m.BaseTransport.Stop()
}

func (m *MultiTransport) receiveLoop() {
	for {
		select {
		case packet := <-m.receiveQueue:
			if packet != nil {
				m.RecordReceive(len(packet))
				m.CallReceive(packet)
			}
		case <-m.receiveStop:
			return
		}
	}
}

func (m *MultiTransport) IsConnected() bool {
	for _, lane := range m.lanes {
		if lane.IsConnected() {
			return true
		}
	}
	return false
}

func (m *MultiTransport) Send(packet []byte) error {
	if len(m.lanes) == 0 {
		return ErrNoLane
	}
	key := flowKey(packet)
	// ACK/hello frames are not IP connections. Keeping every ACK sequence as
	// a binding made flow counts grow with traffic and skewed lane selection.
	if key == "" {
		start := m.pickAdaptiveLane()
		for offset := range m.lanes {
			lane := m.lanes[(start+offset)%len(m.lanes)]
			if lane.IsConnected() {
				if err := lane.Send(packet); err == nil {
					m.RecordSend(len(packet))
					return nil
				}
			}
		}
		return ErrNoLane
	}
	m.mu.RLock()
	binding, ok := m.flowLanes[key]
	m.mu.RUnlock()
	start := -1
	if ok && time.Since(binding.seenAt) < 10*time.Minute && binding.lane >= 0 && binding.lane < len(m.lanes) {
		start = binding.lane
	}
	if !ok {
		start = m.pickLane()
		m.mu.Lock()
		m.cleanupLocked(time.Now())
		if existing, exists := m.flowLanes[key]; exists {
			if time.Since(existing.seenAt) < 10*time.Minute {
				start = existing.lane
			} else {
				m.replaceBindingLocked(key, start, time.Now())
			}
		} else {
			m.replaceBindingLocked(key, start, time.Now())
		}
		m.mu.Unlock()
	}
	if start < 0 {
		start = m.pickLane()
	}
	for offset := 0; offset < len(m.lanes); offset++ {
		lane := m.lanes[(start+offset)%len(m.lanes)]
		if !lane.IsConnected() {
			continue
		}
		// Keep headroom on each lane. If another document is ready, a new flow
		// should use it instead of waiting for a nearly full writer queue.
		if load, ok := lane.(queueLoadReporter); ok && load.QueueLoad() >= 0.75 {
			continue
		}
		if err := lane.Send(packet); err == nil {
			m.bindFlowLane(key, (start+offset)%len(m.lanes))
			m.RecordSend(len(packet))
			return nil
		}
	}
	return ErrNoLane
}

func (m *MultiTransport) bindFlow(packet []byte, lane int) {
	key := flowKey(packet)
	m.bindFlowLane(key, lane)
}

func (m *MultiTransport) bindFlowLane(key string, lane int) {
	if key == "" || lane < 0 || lane >= len(m.lanes) {
		return
	}
	m.mu.Lock()
	m.replaceBindingLocked(key, lane, time.Now())
	m.mu.Unlock()
}

func (m *MultiTransport) replaceBindingLocked(key string, lane int, now time.Time) {
	previous, exists := m.flowLanes[key]
	if exists && previous.lane != lane && previous.lane >= 0 && previous.lane < len(m.activeFlows) && m.activeFlows[previous.lane] > 0 {
		m.activeFlows[previous.lane]--
	}
	if (!exists || previous.lane != lane) && lane >= 0 && lane < len(m.activeFlows) {
		m.activeFlows[lane]++
	}
	m.flowLanes[key] = flowBinding{lane: lane, seenAt: now}
}

func (m *MultiTransport) cleanupLocked(now time.Time) {
	if now.Sub(m.lastCleanup) < time.Minute {
		return
	}
	m.lastCleanup = now
	for key, binding := range m.flowLanes {
		if now.Sub(binding.seenAt) < 10*time.Minute {
			continue
		}
		if binding.lane >= 0 && binding.lane < len(m.activeFlows) && m.activeFlows[binding.lane] > 0 {
			m.activeFlows[binding.lane]--
		}
		delete(m.flowLanes, key)
	}
}

func (m *MultiTransport) pickLane() int {
	if len(m.lanes) == 0 {
		return 0
	}
	best := -1
	bestScore := 0.0
	start := int(m.rr.Add(1)-1) % len(m.lanes)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i, lane := range m.lanes {
		if !lane.IsConnected() {
			continue
		}
		health := laneHealth(lane)
		// The writer queue is the earliest congestion signal. RTT is useful once
		// queues are similarly empty, while active flow count keeps an otherwise
		// equal pair evenly spread.  A flow is selected only once and is pinned
		// afterwards, so this cannot reorder an established TCP connection.
		score := health.QueueLoad*10_000 + float64(health.RTT.Milliseconds()) + float64(m.activeFlows[i])*5
		rotation := (i - start + len(m.lanes)) % len(m.lanes)
		bestRotation := (best - start + len(m.lanes)) % len(m.lanes)
		if best < 0 || score < bestScore || (score == bestScore && rotation < bestRotation) {
			best, bestScore = i, score
		}
	}
	if best >= 0 {
		return best
	}
	return int(m.rr.Add(1)-1) % len(m.lanes)
}

// pickAdaptiveLane is used for bond envelopes and control frames, which do
// not have a stable five-tuple. It selects the line with the smallest current
// queue and then lower observed RTT; active-flow count is only a final tie
// breaker. Existing non-bonded flows stay pinned in Send above.
func (m *MultiTransport) pickAdaptiveLane() int {
	if len(m.lanes) == 0 {
		return 0
	}
	best := -1
	bestScore := 0.0
	m.mu.RLock()
	defer m.mu.RUnlock()
	for index, lane := range m.lanes {
		health := laneHealth(lane)
		if !health.Connected {
			continue
		}
		score := health.QueueLoad*10_000 + float64(health.RTT.Milliseconds()) + float64(m.activeFlows[index])*5
		if best < 0 || score < bestScore {
			best, bestScore = index, score
		}
	}
	if best >= 0 {
		return best
	}
	return int(m.rr.Add(1)-1) % len(m.lanes)
}

// BondEligible prevents a fast flow from being striped onto a document that
// is currently much slower than its peer. A second line helps only while its
// control-plane delay is comparable; otherwise it creates avoidable packet
// reordering and lowers goodput. The threshold is intentionally conservative
// and evaluated continuously, not stored as a user-visible tunnel state.
func (m *MultiTransport) BondEligible() bool {
	if len(m.lanes) < 2 {
		return false
	}
	fastest := time.Duration(0)
	slowest := time.Duration(0)
	for _, lane := range m.lanes {
		health := laneHealth(lane)
		if !health.Connected || health.QueueLoad >= 0.5 || health.RTT <= 0 {
			return false
		}
		if fastest == 0 || health.RTT < fastest {
			fastest = health.RTT
		}
		if health.RTT > slowest {
			slowest = health.RTT
		}
	}
	return slowest <= fastest*3/2
}

// ReorderDeadline follows the observed line skew. It is never lower than a
// normal scheduler turn and never high enough to turn a missing packet into a
// perceptible pause for another flow.
func (m *MultiTransport) ReorderDeadline() time.Duration {
	var fastest, slowest time.Duration
	for _, lane := range m.lanes {
		rtt := laneHealth(lane).RTT
		if rtt <= 0 {
			continue
		}
		if fastest == 0 || rtt < fastest {
			fastest = rtt
		}
		if rtt > slowest {
			slowest = rtt
		}
	}
	if fastest == 0 || slowest <= fastest {
		return bondMinGapAge
	}
	return min(bondMaxGapAge, max(bondMinGapAge, (slowest-fastest)/2))
}

func laneHealth(lane Transport) LaneHealth {
	if reporter, ok := lane.(LaneHealthReporter); ok {
		return reporter.LaneHealth()
	}
	return LaneHealth{Connected: lane.IsConnected()}
}

func (m *MultiTransport) Stats() TransportStats {
	s := m.BaseTransport.Stats()
	for _, lane := range m.lanes {
		ls := lane.Stats()
		s.QueuePackets += ls.QueuePackets
		s.QueueBytes += ls.QueueBytes
		s.RetryQueued += ls.RetryQueued
		s.ExpiredDrops += ls.ExpiredDrops
		s.WriteFailures += ls.WriteFailures
	}
	s.Connected = m.IsConnected()
	return s
}

var ErrNoLane = &multiError{"no connected document lane"}

type multiError struct{ text string }

func (e *multiError) Error() string { return e.text }

func flowKey(packet []byte) string {
	if kind, _, _, payload, reliable := parseReliableFrame(packet); reliable {
		if kind == reliableData {
			return flowKey(payload)
		}
		return ""
	}
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		ihl := int(packet[0]&0x0f) * 4
		if ihl >= 20 && len(packet) >= ihl+4 && (packet[9] == 6 || packet[9] == 17) {
			// Canonicalise the endpoints so client->server and server->client map
			// to the same lane.  The previous direction-sensitive hash was the
			// source of cross-worker SYN/ACK loss with Android multi-worker mode.
			var endpointA, endpointB [6]byte
			copy(endpointA[:4], packet[12:16])
			copy(endpointB[:4], packet[16:20])
			binary.BigEndian.PutUint16(endpointA[4:], binary.BigEndian.Uint16(packet[ihl:ihl+2]))
			binary.BigEndian.PutUint16(endpointB[4:], binary.BigEndian.Uint16(packet[ihl+2:ihl+4]))
			if string(endpointB[:]) < string(endpointA[:]) {
				endpointA, endpointB = endpointB, endpointA
			}
			return string(append(append(endpointA[:], endpointB[:]...), packet[9]))
		}
	}
	h := fnv.New64a()
	_, _ = h.Write(packet)
	return string(binary.BigEndian.AppendUint64(nil, h.Sum64()))
}
