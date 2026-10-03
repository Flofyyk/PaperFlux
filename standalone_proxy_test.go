package main

import (
	"encoding/binary"
	"testing"
	"time"
	"universal-bypass-tool/transport"
)

type proxyReadProbe struct{ *transport.BaseTransport }

func (p *proxyReadProbe) Send([]byte) error { return nil }

func TestStandaloneUploadLimiterDoesNotBlockCarrierReader(t *testing.T) {
	t.Setenv("PAPERFLUX_MAX_MBIT", "0.25")
	raw := &proxyReadProbe{transport.NewBaseTransport(transport.DefaultConfig())}
	closeProxy := startStandaloneProxy(raw, [4]byte{10, 10, 10, 250})
	defer closeProxy()
	packet := make([]byte, 60000)
	packet[0], packet[9] = 0x45, 253 // Valid IPv4, unhandled protocol: no real network traffic.
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 10, 10, 250})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 4; i++ {
			raw.CallReceive(packet)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("upload pacing blocked the carrier reader, preventing later control/pong frames")
	}
}
