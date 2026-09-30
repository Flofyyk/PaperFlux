package tunnel

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"universal-bypass-tool/transport"
)

// LazyProxy keeps the authenticated carrier alive without allocating a gVisor
// stack until real IPv4 data arrives. Each instance owns a separate stack even
// when different users have identical virtual addresses and TCP tuples.
type LazyProxy struct {
	upstream      transport.Transport
	sessions      transport.SessionPackets
	ip            [4]byte
	gate          sync.Mutex
	stackMu       sync.Mutex
	stack         *TCPTunnel
	receiver      func([]byte)
	queue         chan sessionPacket
	latestEpoch   atomic.Uint64
	stackEpoch    uint64
	done          chan struct{}
	stopped       chan struct{}
	closed        bool
	queuedBytes   int
	dropped       atomic.Uint64
	invalidDrops  atomic.Uint64
	queueDrops    atomic.Uint64
	lastActive    atomic.Int64
	creates       atomic.Uint64
	sessionResets atomic.Uint64
	staleDrops    atomic.Uint64
}

type sessionPacket struct {
	epoch uint64
	data  []byte
}

// Responses from an old stack must never be re-stamped as the new session,
// including FIN/RST generated while closing that obsolete stack.
type lazyStackTransport struct {
	*LazyProxy
	epoch uint64
}

func (t *lazyStackTransport) Send(data []byte) error {
	if t.latestEpoch.Load() != t.epoch || (t.sessions != nil && t.sessions.DataEpoch() != t.epoch) {
		return errors.New("obsolete proxy session")
	}
	if t.sessions != nil {
		select {
		case <-t.done:
			return errors.New("profile closed")
		default:
		}
		t.lastActive.Store(time.Now().UnixNano())
		return t.sessions.SendSessionPacket(t.epoch, data)
	}
	return t.LazyProxy.Send(data)
}

const lazyQueueBytes = 256 << 10

func NewLazyProxy(upstream transport.Transport, ip [4]byte) *LazyProxy {
	p := &LazyProxy{upstream: upstream, ip: ip, queue: make(chan sessionPacket, 128), done: make(chan struct{}), stopped: make(chan struct{})}
	p.lastActive.Store(time.Now().UnixNano())
	if sessions, ok := upstream.(transport.SessionPackets); ok {
		p.sessions = sessions
		sessions.ReceiveSessionPackets(p.enqueueSession)
	} else {
		upstream.Receive(p.enqueue)
	}
	go p.run()
	return p
}

func (p *LazyProxy) enqueue(data []byte) {
	p.enqueueSession(0, data)
}
func (p *LazyProxy) enqueueSession(epoch uint64, data []byte) {
	// Reject malformed/spoofed packets before allocating queues or a stack.
	if len(data) < 20 || len(data) > 65000 || data[0]>>4 != 4 || int(data[0]&15)*4 < 20 || int(data[0]&15)*4 > len(data) || int(binary.BigEndian.Uint16(data[2:4])) != len(data) ||
		data[12] != p.ip[0] || data[13] != p.ip[1] || data[14] != p.ip[2] || data[15] != p.ip[3] {
		p.dropped.Add(1)
		p.invalidDrops.Add(1)
		return
	}
	p.gate.Lock()
	defer p.gate.Unlock()
	if p.closed {
		return
	}
	if epoch < p.latestEpoch.Load() {
		p.dropped.Add(1)
		p.staleDrops.Add(1)
		return
	}
	p.latestEpoch.Store(epoch)
	if p.queuedBytes+len(data) > lazyQueueBytes || len(p.queue) == cap(p.queue) {
		p.dropped.Add(1)
		p.queueDrops.Add(1)
		return
	}
	packet := append([]byte(nil), data...)
	p.queuedBytes += len(packet)
	p.queue <- sessionPacket{epoch: epoch, data: packet}
}

func (p *LazyProxy) run() {
	defer close(p.stopped)
	for {
		select {
		case <-p.done:
			return
		case packet := <-p.queue:
			data := packet.data
			p.gate.Lock()
			p.queuedBytes -= len(data)
			closed := p.closed
			p.gate.Unlock()
			if closed {
				return
			}
			p.stackMu.Lock()
			if packet.epoch < p.latestEpoch.Load() {
				p.dropped.Add(1)
				p.staleDrops.Add(1)
				p.stackMu.Unlock()
				continue
			}
			if p.stack != nil && packet.epoch != p.stackEpoch {
				p.stack.Close()
				p.stack = nil
				p.receiver = nil
				p.sessionResets.Add(1)
			}
			if p.stack == nil {
				p.stackEpoch = packet.epoch
				p.stack = NewTCPTunnelWithClientIPMode(&lazyStackTransport{LazyProxy: p, epoch: packet.epoch}, true, p.ip, ExitModeProxy)
				p.creates.Add(1)
			}
			cb := p.receiver
			p.lastActive.Store(time.Now().UnixNano())
			if cb != nil {
				cb(data)
			}
			p.stackMu.Unlock()
		}
	}
}

// Reap is driven by the group's single maintenance ticker. Established TCP
// and UDP flows prevent reaping; a quiet long-lived TCP connection survives.
func (p *LazyProxy) Reap(now time.Time, idle time.Duration) {
	p.stackMu.Lock()
	defer p.stackMu.Unlock()
	if p.stack != nil && p.stack.ActiveFlows() == 0 && now.Sub(time.Unix(0, p.lastActive.Load())) >= idle {
		p.stack.Close()
		p.stack = nil
		p.receiver = nil
	}
}

func (p *LazyProxy) Close() {
	p.gate.Lock()
	if !p.closed {
		p.closed = true
		close(p.done)
	}
	p.gate.Unlock()
	// The current packet's limiter wait is bounded by burst/rate. The reader
	// checks closed before the next packet and cannot create another stack.
	<-p.stopped
	p.stackMu.Lock()
	if p.stack != nil {
		p.stack.Close()
		p.stack = nil
	}
	p.receiver = nil
	p.stackMu.Unlock()
	p.gate.Lock()
	for len(p.queue) > 0 {
		<-p.queue
	}
	p.queuedBytes = 0
	p.gate.Unlock()
}

type LazyProxyStats struct {
	Active        bool   `json:"active"`
	Flows         int    `json:"flows"`
	QueueBytes    int    `json:"queueBytes"`
	Dropped       uint64 `json:"dropped"`
	InvalidDrops  uint64 `json:"invalidDrops,omitempty"`
	QueueDrops    uint64 `json:"queueDrops,omitempty"`
	StackCreates  uint64 `json:"stackCreates"`
	SessionResets uint64 `json:"sessionResets"`
	StaleDrops    uint64 `json:"staleDrops"`
}

func (p *LazyProxy) Snapshot() LazyProxyStats {
	p.stackMu.Lock()
	defer p.stackMu.Unlock()
	result := LazyProxyStats{Active: p.stack != nil, Dropped: p.dropped.Load(), InvalidDrops: p.invalidDrops.Load(), QueueDrops: p.queueDrops.Load(), StackCreates: p.creates.Load()}
	result.SessionResets, result.StaleDrops = p.sessionResets.Load(), p.staleDrops.Load()
	if p.stack != nil {
		result.Flows = p.stack.ActiveFlows()
	}
	p.gate.Lock()
	result.QueueBytes = p.queuedBytes
	p.gate.Unlock()
	return result
}

func (p *LazyProxy) Send(data []byte) error {
	select {
	case <-p.done:
		return errors.New("profile closed")
	default:
	}
	p.lastActive.Store(time.Now().UnixNano())
	return p.upstream.Send(data)
}
func (p *LazyProxy) Receive(cb func([]byte))         { p.receiver = cb } // stackMu held during creation
func (p *LazyProxy) Start() error                    { return nil }
func (p *LazyProxy) Stop() error                     { return nil }
func (p *LazyProxy) IsConnected() bool               { return p.upstream.IsConnected() }
func (p *LazyProxy) Stats() transport.TransportStats { return p.upstream.Stats() }
