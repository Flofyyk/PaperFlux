package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"universal-bypass-tool/exitgroup"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/tunnel"
)

type groupedProfile struct {
	session *sessionRuntime
	proxy   *tunnel.LazyProxy
}

func (p *groupedProfile) Start() error       { return p.session.Start() }
func (p *groupedProfile) Close()             { p.proxy.Close(); _ = p.session.Stop() }
func (p *groupedProfile) Reap(now time.Time) { p.proxy.Reap(now, 5*time.Minute) }
func (p *groupedProfile) Metrics() exitgroup.Metrics {
	st := p.session.Stats()
	proxy := p.proxy.Snapshot()
	return exitgroup.Metrics{Connected: st.Connected, RX: st.BytesReceived, TX: st.BytesSent, QueueBytes: proxy.QueueBytes + int(p.session.session.QueuedBatchBytes()), Dropped: proxy.Dropped, InvalidDrops: proxy.InvalidDrops, QueueDrops: proxy.QueueDrops, ActiveStack: proxy.Active, Flows: proxy.Flows, SessionResets: proxy.SessionResets, StaleDrops: proxy.StaleDrops}
}

func runExitGroup(manifestPath, statsPath, cookieDir string) error {
	if manifestPath == "" || statsPath == "" || cookieDir == "" {
		return fmt.Errorf("group requires private manifest, stats and cookie paths")
	}
	manifestPath, _ = filepath.Abs(manifestPath)
	statsPath, _ = filepath.Abs(statsPath)
	cookieDir, _ = filepath.Abs(cookieDir)
	if manifestPath == statsPath {
		return fmt.Errorf("manifest and stats paths must differ")
	}
	m, err := exitgroup.ReadManifest(manifestPath, time.Now())
	if err != nil {
		return err
	}
	if err = os.MkdirAll(cookieDir, 0700); err != nil {
		return fmt.Errorf("private cookie directory unavailable")
	}
	if runtime.GOOS != "windows" {
		info, e := os.Stat(cookieDir)
		if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("cookie directory must be private")
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	group := exitgroup.New(func(p exitgroup.Profile) (exitgroup.Runtime, error) {
		id, _ := strconv.Atoi(p.ID)
		config := transport.DefaultConfig()
		// Providers queue encrypted batches, not single IP packets. The old
		// 8192-entry default multiplies queued memory across all profiles.
		config.MaxQueueSize = 16
		session, err := newProfileSessionRuntime(p.Transport, p.Documents, p.VolgaURL, config, true, "", fmt.Sprintf("0.0.0.0:%d", 24000+id), sessionIdentity{
			ID: p.ID, Token: p.Token, CookiePath: filepath.Join(cookieDir, "profile-"+p.ID+".json"), Quiet: true,
		})
		if err != nil {
			return nil, err
		}
		ip := netip.MustParseAddr(p.ClientIP).As4()
		return &groupedProfile{session: session, proxy: tunnel.NewLazyProxy(session, ip)}, nil
	})
	defer group.Close()
	if err = group.Apply(m, time.Now()); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastReload, lastStats := time.Now(), time.Time{}
	bad := false
	for {
		select {
		case <-ctx.Done():
			group.Close()
			return exitgroup.WriteSnapshot(statsPath, group.Snapshot(time.Now()))
		case now := <-ticker.C:
			if now.Sub(lastReload) >= 5*time.Second {
				next, e := exitgroup.ReadManifest(manifestPath, now)
				if e == nil {
					e = group.Apply(next, now)
				}
				if e != nil && !bad {
					log.Print("[EXIT_GROUP] manifest rejected; previous profiles retained only until their lease expires")
				}
				bad = e != nil
				lastReload = now
			}
			group.Tick(now)
			if now.Sub(lastStats) >= 5*time.Second {
				if e := exitgroup.WriteSnapshot(statsPath, group.Snapshot(now)); e != nil {
					return fmt.Errorf("cannot persist private group metrics")
				}
				lastStats = now
			}
		}
	}
}
