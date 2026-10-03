// Package authrelay carries only browser verification streams over encrypted
// Session control messages. It is not a VPN data path or a general SOCKS proxy.
package authrelay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"universal-bypass-tool/transport/control"
	"universal-bypass-tool/transport/yandexhosts"
)

const Subtype control.Subtype = 0x70
const (
	openStream  byte = 1
	readyStream byte = 2
	dataStream  byte = 3
	closeStream byte = 4
	ackStream   byte = 5
)
const chunkSize = 8192

type Send func(control.Subtype, []byte) error
type packet struct {
	kind byte
	seq  uint32
	body []byte
}
type stream struct {
	id          uint64
	conn        net.Conn
	incoming    chan packet
	ready       chan error
	done        chan struct{}
	once        sync.Once
	credits     chan struct{}
	sent, acked atomic.Uint32
}
type Relay struct {
	mu      sync.Mutex
	streams map[uint64]*stream
	exit    bool
	send    Send
	closed  bool
	dial    func(string) (net.Conn, error)
}

func New(exit bool, send Send) *Relay {
	return &Relay{exit: exit, send: send, streams: make(map[uint64]*stream), dial: dialPublicHTTPS}
}

func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, blocked, _ := net.ParseCIDR(cidr)
		if blocked.Contains(ip) {
			return false
		}
	}
	return true
}

// Resolve once, reject any non-public answer, then dial pinned IPs: no DNS
// rebinding can route the verification service into a private/metadata network.
func dialPublicHTTPS(address string) (net.Conn, error) {
	if !AllowedAddress(address) {
		return nil, errors.New("verification target rejected")
	}
	host, port, _ := net.SplitHostPort(address)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("verification DNS unavailable")
	}
	for _, a := range addresses {
		if !publicIP(a.IP) {
			return nil, errors.New("verification DNS not public")
		}
	}
	var last error
	for _, a := range addresses {
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(a.IP.String(), port))
		if e == nil {
			return c, nil
		}
		last = e
	}
	return nil, last
}

// AllowedAddress is deliberately independent of peer-supplied URLs. Only
// public HTTPS Yandex/check assets are reachable; IP literals and other ports
// cannot turn the service into a LAN/metadata proxy.
func AllowedAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || net.ParseIP(host) != nil {
		return false
	}
	host = strings.ToLower(host)
	if _, ok := yandexhosts.Root(host); ok {
		return true
	}
	for _, domain := range []string{"yandex.ru", "yandex.com", "yandex.net", "yastatic.net", "smartcaptcha.yandexcloud.net"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
func (r *Relay) add(id uint64, conn net.Conn) (*stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || len(r.streams) >= 16 || r.streams[id] != nil {
		return nil, errors.New("authentication stream unavailable")
	}
	s := &stream{id: id, conn: conn, incoming: make(chan packet, 64), ready: make(chan error, 1), done: make(chan struct{}), credits: make(chan struct{}, 16)}
	for i := 0; i < 16; i++ {
		s.credits <- struct{}{}
	}
	r.streams[id] = s
	return s, nil
}
func (r *Relay) emit(id uint64, kind byte, seq uint32, body []byte) error {
	if len(body) > chunkSize {
		return errors.New("authentication chunk too large")
	}
	p := make([]byte, 13+len(body))
	p[0] = kind
	binary.BigEndian.PutUint64(p[1:9], id)
	binary.BigEndian.PutUint32(p[9:13], seq)
	copy(p[13:], body)
	return r.send(Subtype, p)
}
func (r *Relay) end(s *stream) {
	s.once.Do(func() {
		close(s.done)
		r.mu.Lock()
		conn := s.conn
		if r.streams[s.id] == s {
			delete(r.streams, s.id)
		}
		r.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
	})
}
func (r *Relay) Dial(address string) (net.Conn, error) {
	if r.exit || !AllowedAddress(address) {
		return nil, errors.New("verification proxy permits only Yandex HTTPS")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint64(nonce[:])
	local, pipe := net.Pipe()
	s, err := r.add(id, pipe)
	if err != nil {
		local.Close()
		pipe.Close()
		return nil, err
	}
	if err = r.emit(id, openStream, 0, []byte(address)); err != nil {
		r.end(s)
		local.Close()
		return nil, err
	}
	select {
	case err = <-s.ready:
	case <-s.done:
		err = errors.New("verification channel closed")
	case <-time.After(15 * time.Second):
		err = errors.New("verification channel timeout")
	}
	if err != nil {
		_ = r.emit(id, closeStream, 1, nil)
		r.end(s)
		local.Close()
		return nil, err
	}
	r.run(s)
	return local, nil
}
func (r *Relay) Handle(sub control.Subtype, body []byte) {
	if sub != Subtype || len(body) < 13 || len(body) > chunkSize+13 {
		return
	}
	kind, id, seq := body[0], binary.BigEndian.Uint64(body[1:9]), binary.BigEndian.Uint32(body[9:13])
	payload := append([]byte(nil), body[13:]...)
	if kind == openStream {
		if !r.exit || seq != 0 || !AllowedAddress(string(payload)) {
			return
		}
		// Reserve capacity before dialing; an authenticated peer still has limits.
		s, err := r.add(id, nil)
		if err != nil {
			_ = r.emit(id, closeStream, 1, nil)
			return
		}
		go func() {
			conn, err := r.dial(string(payload))
			if err != nil {
				_ = r.emit(id, closeStream, 1, nil)
				r.end(s)
				return
			}
			r.mu.Lock()
			if r.closed || r.streams[id] != s {
				r.mu.Unlock()
				conn.Close()
				return
			}
			s.conn = conn
			r.mu.Unlock()
			if r.emit(id, readyStream, 0, nil) != nil {
				r.end(s)
				return
			}
			r.run(s)
		}()
		return
	}
	r.mu.Lock()
	s := r.streams[id]
	r.mu.Unlock()
	if s == nil {
		return
	}
	if kind == ackStream {
		for {
			previous := s.acked.Load()
			if seq <= previous || seq > s.sent.Load() {
				return
			}
			if s.acked.CompareAndSwap(previous, seq) {
				for n := previous; n < seq; n++ {
					select {
					case s.credits <- struct{}{}:
					default:
					}
				}
				return
			}
		}
	}
	if kind == readyStream && !r.exit && seq == 0 {
		select {
		case s.ready <- nil:
		default:
		}
		return
	}
	if kind != dataStream && kind != closeStream {
		return
	}
	if kind == closeStream {
		select {
		case s.ready <- errors.New("verification endpoint closed"):
		default:
		}
	}
	select {
	case s.incoming <- packet{kind, seq, payload}:
	case <-s.done:
	default:
		r.end(s)
	}
}
func (r *Relay) run(s *stream) {
	go func() {
		defer r.end(s)
		next := uint32(1)
		pending := make(map[uint32]packet)
		timer := time.NewTimer(90 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-timer.C:
				return
			case p := <-s.incoming:
				if p.seq < next {
					continue
				}
				if p.seq-next > 63 {
					return
				}
				pending[p.seq] = p
				for {
					p, ok := pending[next]
					if !ok {
						break
					}
					delete(pending, next)
					next++
					if p.kind == closeStream {
						return
					}
					_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
					if _, err := s.conn.Write(p.body); err != nil {
						return
					}
					if r.emit(s.id, ackStream, p.seq, nil) != nil {
						return
					}
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(90 * time.Second)
			}
		}
	}()
	go func() {
		defer r.end(s)
		buf := make([]byte, chunkSize)
		seq := uint32(1)
		for {
			_ = s.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			n, err := s.conn.Read(buf)
			if n > 0 {
				select {
				case <-s.credits:
				case <-s.done:
					return
				case <-time.After(30 * time.Second):
					return
				}
				s.sent.Store(seq)
				if e := r.emit(s.id, dataStream, seq, buf[:n]); e != nil {
					return
				}
				seq++
			}
			if err != nil {
				_ = r.emit(s.id, closeStream, seq, nil)
				return
			}
		}
	}()
}
func (r *Relay) Close() {
	r.mu.Lock()
	r.closed = true
	all := make([]*stream, 0, len(r.streams))
	for _, s := range r.streams {
		all = append(all, s)
	}
	r.mu.Unlock()
	for _, s := range all {
		r.end(s)
	}
}
func (r *Relay) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("verification streams: %d", len(r.streams))
}
