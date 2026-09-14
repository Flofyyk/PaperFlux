package transport

import (
	"encoding/binary"
	"hash/fnv"
	"os"
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
	flowLanes    map[uint32]flowBinding
	scores       []int64
	rr           atomic.Uint32
	receiveQueue chan []byte
	receiveStop  chan struct{}
}

type flowBinding struct {
	lane   int
	seenAt time.Time
}

func NewMultiTransport(lanes []Transport, config TransportConfig) *MultiTransport {
	return &MultiTransport{BaseTransport: NewBaseTransport(config), lanes: lanes, flowLanes: make(map[uint32]flowBinding), scores: make([]int64, len(lanes))}
}

func (m *MultiTransport) Start() error {
	if err := m.BaseTransport.Start(); err != nil {
		return err
	}
	m.receiveQueue = make(chan []byte, m.GetConfig().MaxQueueSize)
	m.receiveStop = make(chan struct{})
	go m.receiveLoop()
	for laneIndex, lane := range m.lanes {
		if err := lane.Start(); err != nil {
			return err
		}
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
	if os.Getenv("OPENFLUX_ADAPTIVE_LANES") == "1" {
		go m.measureLanes()
	}
	return nil
}

// measureLanes keeps a short-lived throughput score. It is only used when a
// new flow is assigned; packets of an existing flow remain pinned to one lane.
func (m *MultiTransport) measureLanes() {
	prev := make([]uint64, len(m.lanes))
	for m.IsRunning() {
		time.Sleep(time.Second)
		for i, lane := range m.lanes {
			bytes := lane.Stats().BytesSent
			if bytes >= prev[i] {
				m.mu.Lock()
				m.scores[i] = int64(bytes - prev[i])
				m.mu.Unlock()
			}
			prev[i] = bytes
		}
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
	m.flowLanes = make(map[uint32]flowBinding)
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
	key := flowHash(packet)
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
		if existing, exists := m.flowLanes[key]; exists {
			if time.Since(existing.seenAt) < 10*time.Minute {
				start = existing.lane
			} else {
				m.flowLanes[key] = flowBinding{lane: start, seenAt: time.Now()}
			}
		} else {
			m.flowLanes[key] = flowBinding{lane: start, seenAt: time.Now()}
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
		if err := lane.Send(packet); err == nil {
			m.bindFlowLane(key, (start+offset)%len(m.lanes))
			m.RecordSend(len(packet))
			return nil
		}
	}
	return ErrNoLane
}

func (m *MultiTransport) bindFlow(packet []byte, lane int) {
	key := flowHash(packet)
	m.bindFlowLane(key, lane)
}

func (m *MultiTransport) bindFlowLane(key uint32, lane int) {
	if key == 0 || lane < 0 || lane >= len(m.lanes) {
		return
	}
	m.mu.Lock()
	m.flowLanes[key] = flowBinding{lane: lane, seenAt: time.Now()}
	m.mu.Unlock()
}

func (m *MultiTransport) pickLane() int {
	if len(m.lanes) == 0 {
		return 0
	}
	best := -1
	var score int64 = -1
	for i, lane := range m.lanes {
		if !lane.IsConnected() {
			continue
		}
		m.mu.RLock()
		s := m.scores[i]
		m.mu.RUnlock()
		if s > score {
			best, score = i, s
		}
	}
	if best >= 0 {
		return best
	}
	return int(m.rr.Add(1)-1) % len(m.lanes)
}

func (m *MultiTransport) Stats() TransportStats {
	s := m.BaseTransport.Stats()
	s.Connected = m.IsConnected()
	return s
}

var ErrNoLane = &multiError{"no connected document lane"}

type multiError struct{ text string }

func (e *multiError) Error() string { return e.text }

func flowHash(packet []byte) uint32 {
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		ihl := int(packet[0]&0x0f) * 4
		if ihl >= 20 && len(packet) >= ihl+4 && (packet[9] == 6 || packet[9] == 17) {
			h := fnv.New32a()
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
			_, _ = h.Write(endpointA[:])
			_, _ = h.Write(endpointB[:])
			_, _ = h.Write([]byte{packet[9]})
			return h.Sum32()
		}
	}
	h := fnv.New32a()
	_, _ = h.Write(packet)
	return h.Sum32()
}
