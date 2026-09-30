// Package provision provides authenticated profile discovery, not a VPN proxy.
package provision

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const Magic = "PFPC1"
const MaxPayload = 8192

type Profile struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Token        string   `json:"token,omitempty"`
	ClientIP     string   `json:"clientIp"`
	Transport    string   `json:"transport"`
	DocumentURL  string   `json:"documentUrl,omitempty"`
	DocumentURLs []string `json:"documentUrls,omitempty"`
	VolgaURL     string   `json:"volgaUrl,omitempty"`
}

var volgaDocumentRE = regexp.MustCompile(`^https://disk\.yandex\.ru/i/[A-Za-z0-9_-]+$`)

func Sign(secret, label string, data []byte) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(label))
	h.Write(data)
	return h.Sum(nil)
}

func LoadFile(path string) ([]Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("profile source unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("profile source must be a private regular file")
	}
	var rows []Profile
	decoder := json.NewDecoder(io.LimitReader(f, 1024*1024+1))
	if decoder.Decode(&rows) != nil || len(rows) > 1024 {
		return nil, errors.New("invalid profile source")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("invalid profile source")
	}
	seen := map[string]bool{}
	for _, p := range rows {
		id, err := strconv.Atoi(p.ID)
		if err != nil || id < 1 || id > 41535 || len(p.Token) < 32 || len(p.Token) > 128 || seen[p.Token] || net.ParseIP(p.ClientIP).To4() == nil {
			return nil, errors.New("invalid profile identity")
		}
		if p.Transport != "yandex" && p.Transport != "vyandex" && p.Transport != "cupsonline" && p.Transport != "mailru" {
			return nil, errors.New("unsupported profile transport")
		}
		if len(p.DocumentURLs) == 0 && p.DocumentURL == "" {
			return nil, errors.New("profile resource is missing")
		}
		if p.VolgaURL != "" {
			if p.Transport != "yandex" || !volgaDocumentRE.MatchString(p.VolgaURL) || p.VolgaURL == p.DocumentURL {
				return nil, errors.New("invalid Volga resource")
			}
			for _, document := range p.DocumentURLs {
				if p.VolgaURL == document {
					return nil, errors.New("Volga document must be separate")
				}
			}
		}
		body, _ := json.Marshal(p)
		if len(body) > MaxPayload {
			return nil, errors.New("profile is too large")
		}
		seen[p.Token] = true
	}
	return rows, nil
}

type Source func() ([]Profile, error)
type hit struct {
	count int
	since time.Time
}
type Service struct {
	Source Source
	mu     sync.Mutex
	hits   map[string]hit
}

func (s *Service) allow(address string) bool {
	host, _, _ := net.SplitHostPort(address)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hits == nil {
		s.hits = map[string]hit{}
	}
	now := time.Now()
	for key, value := range s.hits {
		if now.Sub(value.since) >= time.Minute {
			delete(s.hits, key)
		}
	}
	h := s.hits[host]
	if h.count >= 12 || (h.count == 0 && len(s.hits) >= 2048) {
		return false
	}
	if h.count == 0 {
		h.since = now
	}
	h.count++
	s.hits[host] = h
	return true
}

func (s *Service) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	slots := make(chan struct{}, 32)
	var running sync.WaitGroup
	defer running.Wait()
	for {
		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !s.allow(c.RemoteAddr().String()) {
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		running.Add(1)
		go func() { defer running.Done(); defer func() { <-slots }(); defer c.Close(); _ = s.Handle(c) }()
	}
}

func (s *Service) Handle(c net.Conn) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	server := make([]byte, 32)
	if _, err := rand.Read(server); err != nil {
		return err
	}
	if _, err := c.Write(append([]byte(Magic), server...)); err != nil {
		return err
	}
	request := make([]byte, 96)
	if _, err := io.ReadFull(c, request); err != nil {
		return err
	}
	pair := append(append([]byte{}, server...), request[:32]...)
	rows, err := s.Source()
	if err != nil {
		_, _ = c.Write([]byte{0})
		return err
	}
	var matched *Profile
	for i := range rows {
		lookup := Sign(rows[i].Token, "paperflux-profile-lookup-v1", nil)
		proof := Sign(rows[i].Token, "paperflux-profile-client-v1", append(append([]byte{}, pair...), request[32:64]...))
		if hmac.Equal(lookup, request[32:64]) && hmac.Equal(proof, request[64:]) {
			matched = &rows[i]
		}
	}
	if matched == nil {
		_, _ = c.Write([]byte{0})
		return errors.New("profile admission rejected")
	}
	public := *matched
	public.Token = ""
	body, err := json.Marshal(public)
	if err != nil || len(body) > MaxPayload {
		return errors.New("profile response exceeds limit")
	}
	block, err := aes.NewCipher(Sign(matched.Token, "paperflux-profile-response-v1", pair))
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, body, append([]byte(Magic), pair...))
	packet := append([]byte{1}, nonce...)
	packet = binary.BigEndian.AppendUint32(packet, uint32(len(sealed)))
	packet = append(packet, sealed...)
	_, err = c.Write(packet)
	return err
}
