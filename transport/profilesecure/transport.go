package profilesecure

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"universal-bypass-tool/transport"
)

// Transport protects every packet before it reaches an untrusted document or
// room provider. A connection is usable only after the peer proves possession
// of the profile key on the current physical transport session.
type Transport struct {
	raw             transport.Transport
	crypto          *secureChannel
	mu              sync.Mutex
	callback        func([]byte)
	done            chan struct{}
	running         atomic.Bool
	ready           atomic.Bool
	lastProof       atomic.Int64
	lastPing        atomic.Int64
	pingSentAt      atomic.Int64
	rttMs           atomic.Int64
	sent            atomic.Uint64
	received        atomic.Uint64
	sentPackets     atomic.Uint64
	receivedPackets atomic.Uint64
	started         time.Time
}

// The profile ID and random token are provisioned on both endpoints. The
// provider label isolates transports while keeping Cups room creation on the
// exit node independent of the client's later room-list import.
func New(raw transport.Transport, profileID, token, provider string, exit bool) (*Transport, error) {
	c, err := newSecureChannel(profileID, token, provider, exit)
	if err != nil {
		return nil, err
	}
	return &Transport{raw: raw, crypto: c, done: make(chan struct{})}, nil
}

func (t *Transport) Start() error {
	t.raw.Receive(t.handle)
	if err := t.raw.Start(); err != nil {
		return err
	}
	t.started = time.Now()
	t.running.Store(true)
	go t.monitor()
	go t.statsLoop()
	return nil
}

func (t *Transport) Stop() error {
	if t.running.Swap(false) {
		close(t.done)
	}
	t.ready.Store(false)
	return t.raw.Stop()
}

func (t *Transport) Receive(callback func([]byte)) {
	t.mu.Lock()
	t.callback = callback
	t.mu.Unlock()
}

func (t *Transport) IsConnected() bool {
	return t.running.Load() && t.raw.IsConnected() && t.ready.Load()
}

func (t *Transport) Stats() transport.TransportStats {
	s := t.raw.Stats()
	s.BytesSent = t.sent.Load()
	s.BytesReceived = t.received.Load()
	s.PacketsSent = t.sentPackets.Load()
	s.PacketsRecv = t.receivedPackets.Load()
	s.Connected = t.IsConnected()
	s.Uptime = time.Since(t.started)
	return s
}

func (t *Transport) Send(data []byte) error {
	if !t.IsConnected() {
		return fmt.Errorf("secure peer not ready")
	}
	frame := make([]byte, 1+len(data))
	copy(frame[1:], data)
	sealed, err := t.crypto.seal(frame)
	if err != nil {
		return err
	}
	// Room scheduling must use the original IP packet. Hashing the encrypted
	// envelope would collapse all flows onto a single Cups room.
	if keyed, ok := t.raw.(interface{ SendWithFlowKey([]byte, []byte) error }); ok {
		err = keyed.SendWithFlowKey(sealed, data)
	} else {
		err = t.raw.Send(sealed)
	}
	if err == nil {
		t.sent.Add(uint64(len(data)))
		t.sentPackets.Add(1)
	}
	return err
}

func (t *Transport) sendControl(kind byte, id uint64) {
	var payload [9]byte
	payload[0] = kind
	binary.BigEndian.PutUint64(payload[1:], id)
	if sealed, err := t.crypto.seal(payload[:]); err == nil {
		_ = t.rawSendControl(sealed)
	}
}

func (t *Transport) rawSendControl(frame []byte) error {
	if control, ok := t.raw.(interface{ SendControl([]byte) error }); ok {
		return control.SendControl(frame)
	}
	return t.raw.Send(frame)
}

func (t *Transport) handle(frame []byte) {
	if len(frame) < len(secureMagic) || string(frame[:len(secureMagic)]) != string(secureMagic) {
		return
	}
	if len(frame) < secureHeader {
		return
	}
	if frame[4] != 0 {
		ack, err := t.crypto.receiveHandshake(frame)
		if err != nil {
			return
		}
		if frame[4] == 1 {
			t.ready.Store(false)
		}
		if ack != nil {
			_ = t.rawSendControl(ack)
		}
		return
	}
	plain, err := t.crypto.open(frame)
	if err != nil || len(plain) == 0 {
		return
	}
	switch plain[0] {
	case 0:
		if !t.ready.Load() {
			return
		}
		t.received.Add(uint64(len(plain) - 1))
		t.receivedPackets.Add(1)
		t.mu.Lock()
		callback := t.callback
		t.mu.Unlock()
		if callback != nil {
			callback(plain[1:])
		}
	case 1:
		if len(plain) == 9 {
			t.sendControl(2, binary.BigEndian.Uint64(plain[1:]))
		}
	case 2:
		if len(plain) == 9 && binary.BigEndian.Uint64(plain[1:]) != 0 && t.lastPing.CompareAndSwap(int64(binary.BigEndian.Uint64(plain[1:])), 0) {
			t.lastProof.Store(time.Now().UnixNano())
			if sentAt := t.pingSentAt.Load(); sentAt > 0 {
				t.rttMs.Store(time.Since(time.Unix(0, sentAt)).Milliseconds())
			}
			t.ready.Store(true)
		}
	}
}

func (t *Transport) monitor() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var connected bool
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
		}
		if !t.raw.IsConnected() {
			if connected {
				_ = t.crypto.rotateEpoch()
			}
			connected = false
			t.ready.Store(false)
			continue
		}
		connected = true
		if proof := t.lastProof.Load(); proof > 0 && time.Since(time.Unix(0, proof)) > 20*time.Second {
			_ = t.crypto.rotateEpoch()
			t.ready.Store(false)
			t.lastProof.Store(0)
		}
		if !t.crypto.ready() {
			_ = t.rawSendControl(t.crypto.hello())
			continue
		}
		if !t.ready.Load() || time.Since(time.Unix(0, t.lastProof.Load())) > 4*time.Second {
			// Do not replace an outstanding nonce every second: a slow document
			// can legitimately take longer, and every reply would then be stale.
			if t.lastPing.Load() != 0 && time.Since(time.Unix(0, t.pingSentAt.Load())) < 10*time.Second {
				continue
			}
			var idBytes [8]byte
			if _, err := rand.Read(idBytes[:]); err != nil {
				continue
			}
			id := binary.BigEndian.Uint64(idBytes[:])
			if id == 0 {
				continue
			}
			t.lastPing.Store(int64(id))
			t.pingSentAt.Store(time.Now().UnixNano())
			t.sendControl(1, id)
		}
	}
}

func (t *Transport) statsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			s := t.Stats()
			log.Printf("[PAPERFLUX_STATS] rx=%d tx=%d ping=%d", s.BytesReceived, s.BytesSent, t.rttMs.Load())
		}
	}
}
