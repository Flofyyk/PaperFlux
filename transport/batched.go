package transport

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"universal-bypass-tool/utils"
)

// Defaults for the coalescing layer. Tunable at runtime via env vars so the
// batch size can be matched to the channel's per-message limits without a
// rebuild (OPENFLUX_BATCH_BYTES / OPENFLUX_BATCH_COUNT / OPENFLUX_BATCH_LINGER_MS).
const (
	defaultMaxBatchBytes = 8192
	defaultMaxBatchCount = 64
	defaultLingerMs      = 5
	batchQueueDepth      = 256 // At most 16 MiB of queued packet data.
)

// BatchedTransport replaces the old per-packet CompressedTransport. It queues
// outgoing tunnel packets, coalesces bursts into a single framed+zstd batch per
// inner transport message, and splits batches back into packets on receive.
//
// This is the symmetric layer: client and exit node must both use it (they do,
// because main.go wraps both the same way).
//
// BatchedTransport speaks wire-format v2 only. Capability negotiation lives
// in NegotiatedTransport (transport/negotiated.go); the retired wire-v3
// prototype is no longer supported and fails startup if forced.
type BatchedTransport struct {
	Transport

	queue          chan []byte
	queueByteLimit int64
	queueBytes     atomic.Int64
	lingerMs       int
	maxBatchBytes  int
	maxBatchCount  int

	running    atomic.Bool
	lifecycle  sync.Mutex
	stopOnce   sync.Once
	stopCh     chan struct{}
	sendErrors atomic.Uint64
	retries    atomic.Uint64
	expired    atomic.Uint64

	mu     sync.RWMutex
	userCb func([]byte)
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func NewBatchedTransport(inner Transport) *BatchedTransport {
	return newBatchedTransportWithBudget(inner, 16<<20)
}

func newBatchedTransportWithBudget(inner Transport, budget int64) *BatchedTransport {
	if budget <= 0 {
		budget = 16 << 20
	}
	return &BatchedTransport{
		Transport:      inner,
		queue:          make(chan []byte, batchQueueDepth),
		queueByteLimit: budget,
		lingerMs:       envInt("OPENFLUX_BATCH_LINGER_MS", defaultLingerMs),
		maxBatchBytes:  min(envInt("OPENFLUX_BATCH_BYTES", defaultMaxBatchBytes), maxFrameBytes-65537),
		maxBatchCount:  min(envInt("OPENFLUX_BATCH_COUNT", defaultMaxBatchCount), maxFrameRecords-1),
		stopCh:         make(chan struct{}),
	}
}

func (b *BatchedTransport) Start() error {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	if os.Getenv("OPENFLUX_EXPERIMENTAL_WIRE_V3") == "1" {
		return fmt.Errorf("unauthenticated wire-v3 negotiation has been retired; unset OPENFLUX_EXPERIMENTAL_WIRE_V3 and use --negotiate with encryption on both peers")
	}
	select {
	case <-b.stopCh:
		return fmt.Errorf("batched transport is stopped")
	default:
	}
	if b.running.Load() {
		return nil
	}
	if err := b.Transport.Start(); err != nil {
		return err
	}
	b.running.Store(true)
	go b.flushLoop()
	return nil
}

func (b *BatchedTransport) Stop() error {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	select {
	case <-b.stopCh:
		return nil
	default:
	}
	b.running.Store(false)
	b.stopOnce.Do(func() { close(b.stopCh) })
	for {
		select {
		case p := <-b.queue:
			b.queueBytes.Add(-int64(len(p)))
		default:
			return b.Transport.Stop()
		}
	}
}

// Send copies the packet (the caller's buffer may be reused) and enqueues it
// for batching. A full queue returns an explicit error; TCP may retransmit,
// while UDP callers must treat it as datagram loss.
func (b *BatchedTransport) Send(data []byte) error {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	if !b.running.Load() {
		return fmt.Errorf("batched transport is not running")
	}
	if len(data) > 65535 {
		return fmt.Errorf("packet too large for batch record: %d bytes", len(data))
	}
	if b.queueBytes.Load()+int64(len(data)) > b.queueByteLimit {
		return fmt.Errorf("batch byte budget full")
	}
	p := make([]byte, len(data))
	copy(p, data)
	b.queueBytes.Add(int64(len(p)))
	select {
	case b.queue <- p:
		return nil
	default:
		b.queueBytes.Add(-int64(len(p)))
		return fmt.Errorf("batch queue full")
	}
}

func (b *BatchedTransport) Receive(callback func([]byte)) {
	b.mu.Lock()
	b.userCb = callback
	b.mu.Unlock()

	b.Transport.Receive(func(data []byte) {
		pkts, err := decodeBatch(data)
		if err != nil {
			utils.Debugf("[BATCH] decode error (%d bytes): %v", len(data), err)
			return
		}
		b.mu.RLock()
		cb := b.userCb
		b.mu.RUnlock()
		if cb == nil {
			return
		}
		for _, p := range pkts {
			cb(p)
		}
	})
}

// SendErrors counts Transport.Send failures observed by the batching layer.
func (b *BatchedTransport) SendErrors() uint64 { return b.sendErrors.Load() }

func (b *BatchedTransport) Stats() TransportStats {
	st := b.Transport.Stats()
	st.RetryQueued += b.retries.Load()
	st.ExpiredDrops += b.expired.Load()
	st.QueuePackets += uint64(len(b.queue))
	st.WriteFailures += b.sendErrors.Load()
	return st
}

func (b *BatchedTransport) recordSendError(err error) {
	b.sendErrors.Add(1)
	utils.Debugf("[BATCH] send error: %v", err)
}

func (b *BatchedTransport) flushLoop() {
	for b.running.Load() {
		var first []byte
		select {
		case <-b.stopCh:
			return
		case first = <-b.queue:
			b.queueBytes.Add(-int64(len(first)))
		}
		batch := [][]byte{first}
		size := 2 + len(first)

		// Phase 1: absorb everything already queued (burst coalescing). This
		// alone collapses a window's worth of segments into one message.
	drainNow:
		for size < b.maxBatchBytes && len(batch) < b.maxBatchCount {
			select {
			case p := <-b.queue:
				b.queueBytes.Add(-int64(len(p)))
				batch = append(batch, p)
				size += 2 + len(p)
			default:
				break drainNow
			}
		}

		// Phase 2: brief linger to catch stragglers arriving just after the
		// burst. Negligible next to the channel RTT, but it fills batches
		// during steady bulk transfer.
		if b.lingerMs > 0 && size < b.maxBatchBytes && len(batch) < b.maxBatchCount {
			timer := time.NewTimer(time.Duration(b.lingerMs) * time.Millisecond)
		linger:
			for size < b.maxBatchBytes && len(batch) < b.maxBatchCount {
				select {
				case <-b.stopCh:
					timer.Stop()
					return
				case p := <-b.queue:
					b.queueBytes.Add(-int64(len(p)))
					batch = append(batch, p)
					size += 2 + len(p)
				case <-timer.C:
					break linger
				}
			}
			timer.Stop()
		}

		encoded := encodeBatch(batch)
		deadline := time.Now().Add(10 * time.Second)
		backoff := 25 * time.Millisecond
		for b.running.Load() {
			err := b.Transport.Send(encoded)
			if err == nil {
				break
			}
			b.recordSendError(err)
			if time.Now().After(deadline) {
				b.expired.Add(uint64(len(batch)))
				break
			}
			b.retries.Add(1)
			timer := time.NewTimer(backoff)
			select {
			case <-b.stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff = min(backoff*2, 500*time.Millisecond)
		}
	}
}
