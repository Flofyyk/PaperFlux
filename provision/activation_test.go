package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnauthenticatedConcurrencyRemainsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Source: func() ([]Profile, error) { t.Error("incomplete proof reached catalog"); return nil, nil }}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
		cancel()
		<-done
	}()
	for i := 0; i < 32; i++ {
		c, e := net.Dial("tcp", l.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, c)
		c.SetReadDeadline(time.Now().Add(time.Second))
		hello := make([]byte, 37)
		if _, e = io.ReadFull(c, hello); e != nil {
			t.Fatal(e)
		}
	}
	if _, err = Fetch(ctx, l.Addr().String(), strings.Repeat("a", 43)); err == nil {
		t.Fatal("unbounded unauthenticated sockets admitted")
	}
}

func TestActivationOnlyAfterFreshValidProof(t *testing.T) {
	profile := Profile{ID: "1", Token: strings.Repeat("a", 43), ClientIP: "10.10.10.2", Transport: "mailru", DocumentURL: "https://cloud.mail.ru/public/Test/Doc", ActivationRequired: true}
	var wakes atomic.Int32
	service := &Service{Source: func() ([]Profile, error) { return []Profile{profile}, nil }, Activate: func(p Profile) (string, error) {
		if p.ID != "1" || p.Token != profile.Token {
			t.Error("untrusted activation identity")
		}
		wakes.Add(1)
		return "accepted", nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, listener) }()
	if _, err = Fetch(ctx, listener.Addr().String(), strings.Repeat("b", 43)); err == nil {
		t.Fatal("wrong key accepted")
	}
	if wakes.Load() != 0 {
		t.Fatal("unauthenticated request activated worker")
	}
	p, err := Fetch(ctx, listener.Addr().String(), profile.Token)
	if err != nil || p.Activation != "accepted" || p.Token != "" {
		t.Fatal("valid activation failed", err)
	}
	if wakes.Load() != 1 {
		t.Fatal("activation not performed exactly once")
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestActivationUnavailableIsEncryptedBusyNotReady(t *testing.T) {
	p := Profile{ID: "1", Token: strings.Repeat("x", 43), ClientIP: "10.10.10.2", Transport: "mailru", DocumentURL: "https://cloud.mail.ru/public/Test/Doc", ActivationRequired: true}
	s := &Service{Source: func() ([]Profile, error) { return []Profile{p}, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	result, err := Fetch(ctx, l.Addr().String(), p.Token)
	if err != nil || result.Activation != "busy" || !result.ActivationRequired {
		t.Fatal("missing manager falsely ready", err)
	}
	cancel()
	<-done
}

func TestThousandAuthenticatedBootstrapsSameNAT(t *testing.T) {
	rows := make([]Profile, 2000)
	for i := range rows {
		rows[i] = Profile{ID: fmt.Sprint(i + 1), Token: fmt.Sprintf("fixture-%032d", i+1), ClientIP: fmt.Sprintf("10.10.%d.%d", 10+i/253, 2+i%253), Transport: "mailru", DocumentURL: fmt.Sprintf("https://cloud.mail.ru/public/Test/Doc%d", i), ActivationRequired: true}
	}
	path := filepath.Join(t.TempDir(), "profiles.json")
	body, _ := json.Marshal(rows)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	var wakes atomic.Int32
	s := &Service{Source: FileSource(path), Activate: func(p Profile) (string, error) { wakes.Add(1); return "accepted", nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	started := time.Now()
	var workers sync.WaitGroup
	var failures atomic.Int32
	for n := 0; n < 16; n++ {
		workers.Add(1)
		go func(offset int) {
			defer workers.Done()
			for i := offset; i < 1000; i += 16 {
				p, err := Fetch(ctx, l.Addr().String(), rows[i].Token)
				if err != nil || p.ID != rows[i].ID || p.Activation != "accepted" {
					failures.Add(1)
				}
			}
		}(n)
	}
	workers.Wait()
	cancel()
	<-done
	if failures.Load() != 0 || wakes.Load() != 1000 {
		t.Fatalf("failed=%d wake=%d", failures.Load(), wakes.Load())
	}
	t.Logf("1000 authenticated bootstraps / 2000 catalog rows / 16 parallel / same NAT: %s; this is NOT 1000 VPN transports", time.Since(started))
}
