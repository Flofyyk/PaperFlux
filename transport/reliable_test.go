package transport

import (
	"sync"
	"testing"
	"time"
)

type memoryTransport struct {
	mu       sync.RWMutex
	callback func([]byte)
	peer     *memoryTransport
	running  bool
	dropData bool
}

func memoryPair() (*memoryTransport, *memoryTransport) {
	a, b := &memoryTransport{}, &memoryTransport{}
	a.peer, b.peer = b, a
	return a, b
}
func (m *memoryTransport) Start() error { m.mu.Lock(); m.running = true; m.mu.Unlock(); return nil }
func (m *memoryTransport) Stop() error  { m.mu.Lock(); m.running = false; m.mu.Unlock(); return nil }
func (m *memoryTransport) Send(packet []byte) error {
	m.mu.Lock()
	if m.dropData {
		kind, _, _, _, reliable := parseReliableFrame(packet)
		if reliable && kind == reliableData {
			m.dropData = false
			m.mu.Unlock()
			return nil
		}
	}
	peer := m.peer
	m.mu.Unlock()
	peer.mu.RLock()
	callback := peer.callback
	running := peer.running
	peer.mu.RUnlock()
	if running && callback != nil {
		callback(append([]byte(nil), packet...))
	}
	return nil
}
func (m *memoryTransport) Receive(callback func([]byte)) {
	m.mu.Lock()
	m.callback = callback
	m.mu.Unlock()
}
func (m *memoryTransport) IsConnected() bool     { return true }
func (m *memoryTransport) Stats() TransportStats { return TransportStats{Connected: true} }

func TestReliableTransportRecoversDroppedData(t *testing.T) {
	leftInner, rightInner := memoryPair()
	config := DefaultConfig()
	left, err := NewReliableTransport(leftInner, config)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewReliableTransport(rightInner, config)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	right.Receive(func(packet []byte) { received <- packet })
	if err := left.Start(); err != nil {
		t.Fatal(err)
	}
	defer left.Stop()
	if err := right.Start(); err != nil {
		t.Fatal(err)
	}
	defer right.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		left.mu.Lock()
		ready := left.ready
		left.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	left.mu.Lock()
	ready := left.ready
	left.mu.Unlock()
	if !ready {
		t.Fatal("peers did not negotiate reliability")
	}
	leftInner.mu.Lock()
	leftInner.dropData = true
	leftInner.mu.Unlock()
	if err := left.Send([]byte{0x45, 0, 0, 20}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if string(got) != string([]byte{0x45, 0, 0, 20}) {
			t.Fatalf("received %x", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retransmitted packet was not received")
	}
	if left.Stats().RetryQueued == 0 {
		t.Fatal("retransmit counter was not incremented")
	}
}
