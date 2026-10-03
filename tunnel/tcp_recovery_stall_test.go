package tunnel

import (
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"universal-bypass-tool/transport"
)

type recoveryPacket struct {
	data []byte
	at   time.Time
}

// An ordered, lossless in-process document stand-in. Inspired by the ACK-stall
// reproduction in meepo161/OpenFlux PR #115; sends and timers are cancelable.
type recoveryPipe struct {
	ctx     context.Context
	queue   chan recoveryPacket
	start   time.Time
	stall   bool
	deliver func([]byte)
}

func newRecoveryPipe(ctx context.Context, stall bool, deliver func([]byte)) *recoveryPipe {
	p := &recoveryPipe{ctx: ctx, queue: make(chan recoveryPacket, 8192), start: time.Now(), stall: stall, deliver: deliver}
	go func() {
		for {
			var packet recoveryPacket
			select {
			case <-ctx.Done():
				return
			case packet = <-p.queue:
			}
			if !p.wait(time.Until(packet.at)) {
				return
			}
			if p.stall {
				if phase := time.Since(p.start) % (300 * time.Millisecond); phase < 120*time.Millisecond {
					if !p.wait(120*time.Millisecond - phase) {
						return
					}
				}
			}
			p.deliver(packet.data)
		}
	}()
	return p
}

func (p *recoveryPipe) wait(delay time.Duration) bool {
	if delay <= 0 {
		return p.ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-p.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (p *recoveryPipe) send(data []byte) error {
	packet := recoveryPacket{append([]byte(nil), data...), time.Now().Add(5 * time.Millisecond)}
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case p.queue <- packet:
		return nil
	}
}

type recoveryWire struct {
	up   *recoveryPipe
	mu   sync.Mutex
	recv func([]byte)
}

func (w *recoveryWire) Start() error                    { return nil }
func (w *recoveryWire) Stop() error                     { return nil }
func (w *recoveryWire) IsConnected() bool               { return true }
func (w *recoveryWire) Stats() transport.TransportStats { return transport.TransportStats{} }
func (w *recoveryWire) Send(data []byte) error          { return w.up.send(data) }
func (w *recoveryWire) Receive(cb func([]byte))         { w.mu.Lock(); w.recv = cb; w.mu.Unlock() }
func (w *recoveryWire) deliver(data []byte) {
	w.mu.Lock()
	cb := w.recv
	w.mu.Unlock()
	if cb != nil {
		cb(data)
	}
}

// Opt-in timing experiment, not a Yandex/Mail.ru speed promise. Every TCP
// packet is delivered in order; ACKs pause for 120ms every 300ms.
func TestTCPRecoveryACKStallAB(t *testing.T) {
	if os.Getenv("PAPERFLUX_TEST_TCP_STALL") != "1" {
		t.Skip("opt-in local ACK-stall experiment")
	}
	for _, mode := range []string{"default", "classic"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("PAPERFLUX_TCP_RECOVERY", mode)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			peer := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
			defer peer.Destroy()
			link := channel.New(4096, 1500, "")
			addr := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
			if err := peer.CreateNIC(1, link); err != nil {
				t.Fatal(err)
			}
			if err := peer.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
				t.Fatal(err)
			}
			peer.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
			wire := &recoveryWire{}
			wire.up = newRecoveryPipe(ctx, false, func(data []byte) {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
				link.InjectInbound(ipv4.ProtocolNumber, pkt)
				pkt.DecRef()
			})
			down := newRecoveryPipe(ctx, true, wire.deliver)
			go func() {
				for {
					pkt := link.ReadContext(ctx)
					if pkt == nil {
						return
					}
					view := pkt.ToView()
					_ = down.send(view.AsSlice())
					view.Release()
					pkt.DecRef()
				}
			}()
			tun := NewTCPTunnel(wire, false)
			defer tun.Close()
			ln, err := gonet.ListenTCP(peer, tcpip.FullAddress{NIC: 1, Addr: addr, Port: 9000}, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			received := make(chan int64, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					received <- -1
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				n, _ := io.Copy(io.Discard, conn)
				received <- n
			}()
			conn, err := tun.DialTCP("10.0.0.1:9000")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			const chunk, writes = 64 * 1024, 40
			payload := make([]byte, chunk)
			started := time.Now()
			for i := 0; i < writes; i++ {
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err := conn.(*gonet.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case n := <-received:
				if n != chunk*writes {
					t.Fatalf("received %d, want %d", n, chunk*writes)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("upload stalled")
			}
			elapsed := time.Since(started)
			stats := tun.gvisorStack.Stats().TCP
			t.Logf("%s: %.2f Mbit/s, %s, SACKRecovery=%d FastRecovery=%d TLPRecovery=%d Timeouts=%d SpuriousRecovery=%d Retransmits=%d", mode, float64(chunk*writes)*8/elapsed.Seconds()/1e6, elapsed.Round(time.Millisecond), stats.SACKRecovery.Value(), stats.FastRecovery.Value(), stats.TLPRecovery.Value(), stats.Timeouts.Value(), stats.SpuriousRecovery.Value(), stats.Retransmits.Value())
		})
	}
}
