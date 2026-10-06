package exitgroup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRuntime struct {
	starts  atomic.Int32
	closes  atomic.Int32
	metrics Metrics
	block   <-chan struct{}
}

func (f *fakeRuntime) Start() error {
	f.starts.Add(1)
	if f.block != nil {
		<-f.block
	}
	return nil
}
func (f *fakeRuntime) Close()           { f.closes.Add(1) }
func (f *fakeRuntime) Metrics() Metrics { return f.metrics }
func (f *fakeRuntime) Reap(time.Time)   {}
func profile(id string) Profile {
	return Profile{ID: id, Token: strings.Repeat("x", 32) + id, ClientIP: "10.10.10.2", Transport: "yandex", Documents: []string{"https://disk.yandex.ru/i/doc" + id}}
}
func manifest(profiles ...Profile) Manifest {
	return Manifest{Version: 1, ValidUntil: time.Now().Add(time.Minute).Unix(), Profiles: profiles}
}
func await(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestManifestValidation(t *testing.T) {
	valid := manifest(profile("1"), profile("2"))
	valid.Profiles[0].VolgaURL = "https://disk.yandex.ru/i/volga1"
	if err := valid.Validate(time.Now()); err != nil {
		t.Fatal(err)
	} // Same virtual IP is isolated by stack.
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.Version = 2 }, func(m *Manifest) { m.ValidUntil = time.Now().Unix() }, func(m *Manifest) { m.ValidUntil = time.Now().Add(time.Hour).Unix() },
		func(m *Manifest) { m.Profiles[1].ID = "1" }, func(m *Manifest) { m.Profiles[0].ID = "../1" },
		func(m *Manifest) { m.Profiles[1].Documents = m.Profiles[0].Documents }, func(m *Manifest) { m.Profiles[1].Token = m.Profiles[0].Token },
		func(m *Manifest) { m.Profiles[0].ClientIP = "127.0.0.1" }, func(m *Manifest) { m.Profiles[0].Documents = []string{"https://disk.yandex.ru@127.0.0.1/i/a"} },
		func(m *Manifest) { m.Profiles[0].Transport = "unknown" }, func(m *Manifest) { m.Profiles = make([]Profile, MaxProfiles+1) },
		func(m *Manifest) { m.Profiles[0].VolgaURL = m.Profiles[0].Documents[0] },
		func(m *Manifest) { m.Profiles[0].VolgaURL = m.Profiles[1].Documents[0] },
		func(m *Manifest) { m.Profiles[0].VolgaURL = "https://evil.invalid/i/volga" },
		func(m *Manifest) { m.Acknowledged = []string{"bad"} },
	} {
		m := manifest(profile("1"), profile("2"))
		change(&m)
		if m.Validate(time.Now()) == nil {
			t.Fatal("bad manifest accepted")
		}
	}
}

func TestStandaloneVolgaManifestIsBounded(t *testing.T) {
	p := profile("1")
	p.Transport = "vyandex"
	if err := manifest(p).Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	p.Documents = append(p.Documents, "https://disk.yandex.ru/i/extra")
	if manifest(p).Validate(time.Now()) == nil {
		t.Fatal("multiple standalone Volga documents accepted")
	}
}

func TestUnacknowledgedAccountingBackpressuresStarts(t *testing.T) {
	g := New(func(Profile) (Runtime, error) { return &fakeRuntime{}, nil })
	defer g.Close()
	for i := 0; i < MaxProfiles; i++ {
		g.retired = append(g.retired, Row{Epoch: strings.Repeat(string(rune('a'+i%6)), 32), Metrics: Metrics{RX: 100}})
	}
	m := manifest(profile("1"))
	if err := g.Apply(m, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(g.entries) != 0 || len(g.retired) != MaxProfiles {
		t.Fatal("unacknowledged counters discarded or starts not bounded")
	}
	m.Acknowledged = []string{strings.Repeat("f", 32)}
	if err := g.Apply(m, time.Now()); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool {
		s := g.Snapshot(time.Now())
		return len(s.Profiles) == 1 && s.Profiles[0].State == "running"
	})
	for _, row := range g.retired {
		if row.Epoch == m.Acknowledged[0] {
			t.Fatal("acknowledgement not applied")
		}
	}
	before := g.Snapshot(time.Now()).Profiles[0].Epoch
	m.Acknowledged = []string{before}
	g.Apply(m, time.Now())
	if g.Snapshot(time.Now()).Profiles[0].Epoch != before {
		t.Fatal("ACK changed active profile")
	}
}
func TestStrictPrivateManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m := manifest(profile("1"))
	data, _ := json.Marshal(m)
	for _, body := range [][]byte{append(data, []byte(` {}`)...), []byte(strings.Replace(string(data), `"version":1`, `"version":1,"unknown":true`, 1)), make([]byte, MaxManifestBytes+1)} {
		os.WriteFile(path, body, 0600)
		if _, err := ReadManifest(path, time.Now()); err == nil {
			t.Fatal("unsafe manifest accepted")
		}
	}
	os.WriteFile(path, data, 0600)
	if _, err := ReadManifest(path, time.Now()); err != nil {
		t.Fatal(err)
	}
}
func TestUnchangedRenewalDoesNotRestartAndRemovalIsScoped(t *testing.T) {
	var mu sync.Mutex
	created := map[string]*fakeRuntime{}
	g := New(func(p Profile) (Runtime, error) {
		mu.Lock()
		defer mu.Unlock()
		f := &fakeRuntime{}
		created[p.ID] = f
		return f, nil
	})
	defer g.Close()
	m := manifest(profile("1"), profile("2"))
	if err := g.Apply(m, time.Now()); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool {
		s := g.Snapshot(time.Now())
		return len(s.Profiles) == 2 && s.Profiles[0].State == "running" && s.Profiles[1].State == "running"
	})
	before := g.Snapshot(time.Now())
	m.ValidUntil++
	g.Apply(m, time.Now())
	if g.Snapshot(time.Now()).Profiles[0].Epoch != before.Profiles[0].Epoch {
		t.Fatal("renewal restarted profile")
	}
	g.Apply(manifest(profile("2")), time.Now())
	await(t, func() bool { g.Tick(time.Now()); return len(g.Snapshot(time.Now()).Profiles) == 1 })
	mu.Lock()
	defer mu.Unlock()
	if created["1"].closes.Load() != 1 || created["2"].closes.Load() != 0 {
		t.Fatal("wrong profile closed")
	}
}
func TestLeaseExpiryAndInvalidReloadFailClosed(t *testing.T) {
	g := New(func(Profile) (Runtime, error) { return &fakeRuntime{}, nil })
	defer g.Close()
	m := manifest(profile("1"))
	g.Apply(m, time.Now())
	await(t, func() bool { return g.Snapshot(time.Now()).Profiles[0].State == "running" })
	invalid := manifest(profile("1"))
	invalid.Profiles[0].Token = "secret-invalid"
	if g.Apply(invalid, time.Now()) == nil {
		t.Fatal("invalid accepted")
	}
	if len(g.Snapshot(time.Now()).Profiles) != 1 {
		t.Fatal("invalid manifest mutated running group")
	}
	after := time.Unix(m.ValidUntil+1, 0)
	g.Tick(after)
	await(t, func() bool { g.Tick(after); return len(g.Snapshot(after).Profiles) == 0 })
}
func TestStartConcurrencyBoundAndCancellation(t *testing.T) {
	release := make(chan struct{})
	var concurrent, maximum atomic.Int32
	var runtimesMu sync.Mutex
	var runtimes []*fakeRuntime
	g := New(func(Profile) (Runtime, error) {
		n := concurrent.Add(1)
		for old := maximum.Load(); n > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, n) {
				break
			}
		}
		<-release
		concurrent.Add(-1)
		f := &fakeRuntime{}
		runtimesMu.Lock()
		runtimes = append(runtimes, f)
		runtimesMu.Unlock()
		return f, nil
	})
	m := manifest(profile("1"), profile("2"), profile("3"), profile("4"))
	g.Apply(m, time.Now())
	await(t, func() bool { return concurrent.Load() == 2 })
	g.Apply(manifest([]Profile{}...), time.Now())
	close(release)
	g.Close()
	if maximum.Load() > 2 {
		t.Fatal("unbounded starts")
	}
	for _, f := range runtimes {
		if f.starts.Load() != 0 || f.closes.Load() != 1 {
			t.Fatal("cancelled startup resurrected")
		}
	}
}
func TestQuotaAndSecretFreeSnapshot(t *testing.T) {
	g := New(func(Profile) (Runtime, error) { return &fakeRuntime{metrics: Metrics{RX: 8, TX: 4}}, nil })
	defer g.Close()
	p := profile("1")
	p.MaxBytes = 10
	g.Apply(manifest(p), time.Now())
	await(t, func() bool { return g.Snapshot(time.Now()).Profiles[0].State == "running" })
	g.Tick(time.Now())
	await(t, func() bool { g.Tick(time.Now()); return len(g.entries) == 0 })
	g.Tick(time.Now().Add(time.Hour))
	if len(g.entries) != 0 {
		t.Fatal("quota restarts")
	}
	s := g.Snapshot(time.Now())
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), p.Token) || strings.Contains(string(data), p.Documents[0]) {
		t.Fatal("secrets in stats")
	}
	if len(s.Retired) != 1 || s.Retired[0].State != "quota" || s.Retired[0].RX != 8 {
		t.Fatal("missing final accounting")
	}
	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := WriteSnapshot(path, s); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshot(path, s); err != nil {
		t.Fatal(err)
	}
}
