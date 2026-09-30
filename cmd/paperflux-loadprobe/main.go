// Explicit, isolated load harness. Never uses the bot DB or production keys.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/control"
	"universal-bypass-tool/tunnel"
)

var role = flag.String("role", "", "exit, client or echo")
var first = flag.Int("first", 1, "first synthetic profile")
var count = flag.Int("count", 1, "synthetic profiles, at most 100")
var seedFile = flag.String("seed-file", "", "private random run seed")
var output = flag.String("output", "", "private metrics JSON")
var seconds = flag.Int("seconds", 30, "traffic measurement duration")
var rate = flag.Int("rate-kbit", 500, "offered useful rate per direction per profile")
var basePort = flag.Int("base-port", 29000, "loopback-only profile port base")
var target = flag.String("target", "127.0.0.1:29999", "controlled echo endpoint")

type profile struct {
	id int
	s  *transport.Session
	p  *tunnel.LazyProxy
	t  *tunnel.TCPTunnel
	c  net.Conn
}

func (p *profile) close() {
	if p.c != nil {
		p.c.Close()
	}
	if p.t != nil {
		p.t.Close()
	}
	if p.p != nil {
		p.p.Close()
	}
	p.s.Stop()
}
func save(v any) {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	f, e := os.CreateTemp(filepath.Dir(*output), ".load-")
	if e != nil {
		panic(e)
	}
	name := f.Name()
	defer os.Remove(name)
	f.Chmod(0600)
	if _, e = f.Write(b); e != nil {
		panic(e)
	}
	f.Close()
	if e = os.Rename(name, *output); e != nil {
		panic(e)
	}
}
func makeProfile(id int, seed []byte, exit bool) (*profile, error) {
	s, e := transport.NewSession(transport.PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP | control.CapabilityUDP, MaxPacketSize: 65000}, exit)
	if e != nil {
		return nil, e
	}
	p := &profile{id: id, s: s}
	ok := false
	defer func() {
		if !ok {
			p.close()
		}
	}()
	s.SetHandshakeTimeout(90 * time.Second)
	if e = s.SetBatchByteLimit(256 << 10); e != nil {
		return nil, e
	}
	secret := sha256.Sum256(append(append([]byte{}, seed...), []byte(fmt.Sprint(id))...))
	cfg := transport.DefaultConfig()
	cfg.MaxQueueSize = 16
	d := transport.DefaultDirectConfig()
	d.IsExit = exit
	d.AuthSecret = hex.EncodeToString(secret[:])
	d.ReadTimeout = 45 * time.Second
	addr := fmt.Sprintf("127.0.0.1:%d", *basePort+id)
	if exit {
		d.ListenAddr = addr
	} else {
		d.DialAddr = addr
	}
	if e = s.AddTransport("isolated-test", transport.NewDirectTransport(cfg, d), d.AuthSecret, fmt.Sprintf("paperflux-load/profile/%d", id), 100); e != nil {
		return nil, e
	}
	if exit {
		p.p = tunnel.NewLazyProxy(s, [4]byte{10, 10, 10, 2})
	} else {
		p.t = tunnel.NewTCPTunnel(s, false)
	}
	if e = s.Start(); e != nil {
		return nil, e
	}
	ok = true
	return p, nil
}
func main() {
	flag.Parse()
	if *count < 1 || *count > 100 || *first < 1 || *first+*count > 101 || *seconds < 1 || *seconds > 60 || *rate < 1 || *rate > 2000 {
		panic("invalid bounded test parameters")
	}
	if *role == "echo" {
		echo()
		return
	}
	seed, e := os.ReadFile(*seedFile)
	if e != nil || len(seed) != 64 {
		panic("private 64-byte seed required")
	}
	if *role != "exit" && *role != "client" {
		panic("explicit test role required")
	}
	profiles := make([]*profile, 0, *count)
	defer func() {
		for _, p := range profiles {
			p.close()
		}
	}()
	for id := *first; id < *first+*count; id++ {
		p, e := makeProfile(id, seed, *role == "exit")
		if e != nil {
			panic(e)
		}
		profiles = append(profiles, p)
	}
	if *role == "exit" {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			rows := []map[string]any{}
			for _, p := range profiles {
				st := p.p.Snapshot()
				rows = append(rows, map[string]any{"id": p.id, "connected": p.s.HasDataPath(), "active": st.Active, "flows": st.Flows, "dropped": st.Dropped, "queueBytes": st.QueueBytes + int(p.s.QueuedBatchBytes())})
			}
			save(map[string]any{"phase": "ready", "at": time.Now().Unix(), "profiles": rows})
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}
	deadline := time.Now().Add(100 * time.Second)
	for _, p := range profiles {
		for !p.s.HasDataPath() {
			if time.Now().After(deadline) {
				panic(fmt.Sprintf("profile %d handshake timeout", p.id))
			}
			time.Sleep(50 * time.Millisecond)
		}
		p.c, e = p.t.DialTCP(*target)
		if e != nil {
			panic(e)
		}
	}
	save(map[string]any{"phase": "connected", "profiles": len(profiles)})
	fmt.Printf("All %d independent encrypted profiles connected; starting %ds traffic\n", len(profiles), *seconds)
	type result struct {
		ID     int     `json:"id"`
		Bytes  int64   `json:"checkedBytes"`
		Chunks int     `json:"chunks"`
		P95MS  float64 `json:"p95Ms"`
		Error  string  `json:"error,omitempty"`
	}
	results := make([]result, len(profiles))
	var wg sync.WaitGroup
	start := time.Now()
	end := start.Add(time.Duration(*seconds) * time.Second)
	for i, p := range profiles {
		wg.Add(1)
		go func(i int, p *profile) {
			defer wg.Done()
			r := result{ID: p.id}
			defer func() { results[i] = r }()
			payload := make([]byte, 16384)
			if _, e := rand.Read(payload); e != nil {
				r.Error = e.Error()
				return
			}
			buf := make([]byte, len(payload))
			latencies := []float64{}
			interval := time.Duration(float64(len(payload)*8) * float64(time.Second) / float64(*rate*1000))
			next := start
			for time.Now().Before(end) {
				p.c.SetDeadline(time.Now().Add(10 * time.Second))
				sent := time.Now()
				if _, e := io.CopyN(p.c, bytes.NewReader(payload), int64(len(payload))); e != nil {
					r.Error = e.Error()
					break
				}
				if _, e := io.ReadFull(p.c, buf); e != nil {
					r.Error = e.Error()
					break
				}
				if !bytes.Equal(buf, payload) {
					r.Error = "payload mismatch / cross-profile corruption"
					break
				}
				r.Bytes += int64(len(payload))
				r.Chunks++
				latencies = append(latencies, time.Since(sent).Seconds()*1000)
				next = next.Add(interval)
				if wait := time.Until(next); wait > 0 {
					time.Sleep(wait)
				}
			}
			if len(latencies) > 0 {
				sort.Float64s(latencies)
				r.P95MS = latencies[(len(latencies)-1)*95/100]
			}
		}(i, p)
	}
	wg.Wait()
	var total int64
	failed := 0
	for _, r := range results {
		total += r.Bytes
		if r.Error != "" {
			failed++
		}
	}
	save(map[string]any{"phase": "complete", "profiles": len(profiles), "seconds": time.Since(start).Seconds(), "offeredKbitPerProfile": *rate, "checkedBytesPerDirection": total, "failed": failed, "results": results})
	fmt.Printf("Completed profiles=%d errors=%d checked_bytes_each_direction=%d\n", len(profiles), failed, total)
	if failed > 0 {
		os.Exit(2)
	}
}
func echo() {
	l, e := net.Listen("tcp4", *target)
	if e != nil {
		panic(e)
	}
	defer l.Close()
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go func() { defer c.Close(); c.SetDeadline(time.Now().Add(3 * time.Minute)); io.Copy(c, c) }()
	}
}
