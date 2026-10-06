package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLazyRejectDoesNotAllocateStack(t *testing.T) {
	a, b := newTransportPair()
	p := NewLazyProxy(b, [4]byte{10, 10, 10, 2})
	defer p.Close()
	a.Send(make([]byte, 1400))
	if s := p.Snapshot(); s.Active || s.Dropped != 1 || s.InvalidDrops != 1 || s.QueueDrops != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestLazyQueueDropIsReportedSeparately(t *testing.T) {
	_, b := newTransportPair()
	p := NewLazyProxy(b, [4]byte{10, 10, 10, 2})
	defer p.Close()
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 10, 10, 2})
	p.gate.Lock()
	p.queuedBytes = lazyQueueBytes
	p.gate.Unlock()
	p.enqueue(packet)
	if s := p.Snapshot(); s.Dropped != 1 || s.InvalidDrops != 0 || s.QueueDrops != 1 {
		t.Fatalf("%+v", s)
	}
}
func TestLazySeparateProfilesSameIP(t *testing.T) {
	ip := testLANIPv4(t)
	listener, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	const count = 8
	proxies := make([]*LazyProxy, count)
	clients := make([]*TCPTunnel, count)
	conns := make([]net.Conn, count)
	defer func() {
		for i := 0; i < count; i++ {
			if conns[i] != nil {
				conns[i].Close()
			}
			if proxies[i] != nil {
				proxies[i].Close()
			}
			if clients[i] != nil {
				clients[i].Close()
			}
		}
	}()
	for i := 0; i < count; i++ {
		a, b := newTransportPair()
		proxies[i] = NewLazyProxy(b, [4]byte{10, 10, 10, 2})
		clients[i] = NewTCPTunnel(a, false)
		if proxies[i].Snapshot().Active {
			t.Fatal("idle profile allocated stack")
		}
		conns[i], err = clients[i].DialTCP(listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conns[i].SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte(fmt.Sprintf("profile-%d", i))
			conns[i].Write(payload)
			out := make([]byte, len(payload))
			if _, err := io.ReadFull(conns[i], out); err != nil || string(out) != string(payload) {
				t.Errorf("cross-profile/corrupt traffic %d: %q %v", i, out, err)
			}
		}(i)
	}
	wg.Wait()
	proxies[0].Close()
	conns[1].SetDeadline(time.Now().Add(3 * time.Second))
	conns[1].Write([]byte("still-alive"))
	out := make([]byte, 11)
	if _, err = io.ReadFull(conns[1], out); err != nil || string(out) != "still-alive" {
		t.Fatal("one profile closed another", err)
	}
	if s := proxies[0].Snapshot(); s.Active {
		t.Fatal("closed stack retained")
	}
	proxies[1].Reap(time.Now().Add(time.Hour), time.Minute)
	if !proxies[1].Snapshot().Active {
		t.Fatal("quiet established connection reaped")
	}
}
func TestLazyIdleReapAndWake(t *testing.T) {
	a, b := newTransportPair()
	p := NewLazyProxy(b, [4]byte{10, 10, 10, 2})
	defer p.Close()
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 20)
	copy(packet[12:16], []byte{10, 10, 10, 2})
	wait := func(n uint64) {
		t.Helper()
		end := time.Now().Add(time.Second)
		for p.Snapshot().StackCreates < n {
			if time.Now().After(end) {
				t.Fatal("no wake")
			}
			time.Sleep(time.Millisecond)
		}
	}
	a.Send(packet)
	wait(1)
	p.Reap(time.Now().Add(time.Hour), time.Minute)
	if p.Snapshot().Active {
		t.Fatal("idle stack not reaped")
	}
	a.Send(packet)
	wait(2)
}
func TestTunnelCloseReleasesTrackedSockets(t *testing.T) {
	_, b := newTransportPair()
	tun := NewTCPTunnelWithClientIPMode(b, true, [4]byte{10, 10, 10, 2}, ExitModeProxy)
	a, c := net.Pipe()
	defer c.Close()
	if !tun.trackConnection(a) {
		t.Fatal("track failed")
	}
	tun.Close()
	tun.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("socket not closed", err)
	}
	a, c2 := net.Pipe()
	defer c2.Close()
	if tun.trackConnection(a) {
		t.Fatal("connection admitted after close")
	}
}

// This measures only idle IP-stack overhead, not provider sessions, OS RSS,
// throughput, process savings or the capacity of a production VPS.
func TestIdleStackMemoryMeasurement(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}
	for _, lazy := range []bool{false, true} {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		var closeFns []func()
		for i := 0; i < 16; i++ {
			_, b := newTransportPair()
			if lazy {
				p := NewLazyProxy(b, [4]byte{10, 10, 10, 2})
				closeFns = append(closeFns, p.Close)
			} else {
				p := NewTCPTunnelWithClientIPMode(b, true, [4]byte{10, 10, 10, 2}, ExitModeProxy)
				closeFns = append(closeFns, p.Close)
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		t.Logf("idle mode_lazy=%t profiles=16 heap_delta_bytes=%d goroutines=%d", lazy, int64(after.HeapAlloc)-int64(before.HeapAlloc), runtime.NumGoroutine())
		for _, close := range closeFns {
			close()
		}
	}
}

func TestGroupedSyntheticLoad(t *testing.T) {
	if os.Getenv("PAPERFLUX_LOAD_TEST") != "1" {
		t.Skip("explicit local load test only")
	}
	t.Setenv("PAPERFLUX_MAX_MBIT", "8")
	listener, err := net.Listen("tcp4", net.JoinHostPort(testLANIPv4(t).String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	profiles := 16
	chunks := 128
	if value := os.Getenv("PAPERFLUX_LOAD_PROFILES"); value != "" {
		profiles, err = strconv.Atoi(value)
		if err != nil || profiles < 1 || profiles > 1000 {
			t.Fatal("invalid load profile count")
		}
	}
	if value := os.Getenv("PAPERFLUX_LOAD_CHUNKS"); value != "" {
		chunks, err = strconv.Atoi(value)
		if err != nil || chunks < 1 || chunks > 128 {
			t.Fatal("invalid load chunk count")
		}
	}
	const chunkSize = 16384
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(profiles)
	transfer := make(chan struct{})
	var completed atomic.Int32
	go func() {
		ready.Wait()
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		t.Logf("simultaneous_stacks=%d heap_bytes=%d heap_sys_bytes=%d goroutines=%d", profiles*2, memory.HeapAlloc, memory.HeapSys, runtime.NumGoroutine())
		close(transfer)
	}()
	start := time.Now()
	for i := 0; i < profiles; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			announced := false
			defer func() {
				if !announced {
					ready.Done()
				}
			}()
			a, b := newTransportPair()
			proxy := NewLazyProxy(b, [4]byte{10, 10, 10, 2})
			defer proxy.Close()
			client := NewTCPTunnel(a, false)
			defer client.Close()
			conn, e := client.DialTCP(listener.Addr().String())
			if e != nil {
				t.Error(e)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(45 * time.Second))
			announced = true
			ready.Done()
			<-transfer // All connections overlap, rather than sequential churn.
			payload := make([]byte, chunkSize)
			for n := range payload {
				payload[n] = byte((n + id) % 251)
			}
			writer := make(chan error, 1)
			go func() {
				for j := 0; j < chunks; j++ {
					if _, e := conn.Write(payload); e != nil {
						writer <- e
						return
					}
				}
				writer <- nil
			}()
			buffer := make([]byte, chunkSize)
			for j := 0; j < chunks; j++ {
				if _, e = io.ReadFull(conn, buffer); e != nil {
					t.Error(e)
					return
				}
				for n, v := range buffer {
					if v != payload[n] {
						t.Error("cross-profile payload corruption")
						return
					}
				}
			}
			if e = <-writer; e != nil {
				t.Error(e)
				return
			}
			completed.Add(1)
		}(i)
	}
	wg.Wait()
	t.Logf("synthetic_profiles=%d completed=%d checked_bytes_per_direction=%d seconds=%.3f aggregate_payload_mbit_s=%.2f; no provider/session encryption", profiles, completed.Load(), int(completed.Load())*chunks*chunkSize, time.Since(start).Seconds(), float64(int(completed.Load())*chunks*chunkSize*8)/time.Since(start).Seconds()/1e6)
}
