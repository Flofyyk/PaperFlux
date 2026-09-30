package exitgroup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"
)

type Metrics struct {
	Connected     bool   `json:"connected"`
	RX            uint64 `json:"rx"`
	TX            uint64 `json:"tx"`
	QueueBytes    int    `json:"queueBytes"`
	Dropped       uint64 `json:"dropped"`
	InvalidDrops  uint64 `json:"invalidDrops,omitempty"`
	QueueDrops    uint64 `json:"queueDrops,omitempty"`
	ActiveStack   bool   `json:"activeStack"`
	Flows         int    `json:"flows"`
	SessionResets uint64 `json:"sessionResets,omitempty"`
	StaleDrops    uint64 `json:"staleDrops,omitempty"`
}
type Runtime interface {
	Start() error
	Close()
	Metrics() Metrics
	Reap(time.Time)
}
type Factory func(Profile) (Runtime, error)

type entry struct {
	profile Profile
	epoch   string
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	runtime Runtime
	state   string
	final   Metrics
}
type Row struct {
	ID    string `json:"id"`
	Epoch string `json:"epoch"`
	State string `json:"state"`
	Metrics
}

func (e *entry) snapshot() Row {
	e.mu.Lock()
	defer e.mu.Unlock()
	metrics := e.final
	if e.runtime != nil {
		metrics = e.runtime.Metrics()
	}
	return Row{ID: e.profile.ID, Epoch: e.epoch, State: e.state, Metrics: metrics}
}

type failure struct {
	attempt int
	after   time.Time
}

// Group is controlled by one reconciliation loop. Only entry workers are
// concurrent; callers must serialize Apply/Tick/Snapshot/Close.
type Group struct {
	factory    Factory
	slots      chan struct{}
	wanted     map[string]Profile
	entries    map[string]*entry
	failures   map[string]failure
	validUntil int64
	closed     bool
	// Final counters remain until the supervisor commits and acknowledges them.
	// Backpressure on starts bounds this journal without losing billing rows.
	retired []Row
}

func New(factory Factory) *Group {
	return &Group{factory: factory, slots: make(chan struct{}, 2), wanted: map[string]Profile{}, entries: map[string]*entry{}, failures: map[string]failure{}}
}

func (g *Group) Apply(m Manifest, now time.Time) error {
	if g.closed {
		return errors.New("group closed")
	}
	if err := m.Validate(now); err != nil {
		return err
	}
	acks := make(map[string]bool, len(m.Acknowledged))
	for _, epoch := range m.Acknowledged {
		acks[epoch] = true
	}
	retained := g.retired[:0]
	for _, row := range g.retired {
		if !acks[row.Epoch] {
			retained = append(retained, row)
		}
	}
	g.retired = retained
	wanted := make(map[string]Profile, len(m.Profiles))
	for _, p := range m.Profiles {
		p.Documents = append([]string(nil), p.Documents...)
		wanted[p.ID] = p
	}
	for id, p := range wanted {
		if !reflect.DeepEqual(g.wanted[id], p) {
			delete(g.failures, id)
		}
	}
	for id := range g.failures {
		if _, ok := wanted[id]; !ok {
			delete(g.failures, id)
		}
	}
	g.wanted = wanted
	g.validUntil = m.ValidUntil
	g.Tick(now)
	return nil
}

func (g *Group) Tick(now time.Time) {
	if g.closed {
		return
	}
	if now.Unix() >= g.validUntil {
		g.wanted = map[string]Profile{}
	}
	changing := false
	for id, e := range g.entries {
		p, wanted := g.wanted[id]
		if !wanted || !reflect.DeepEqual(p, e.profile) {
			e.cancel()
			changing = true
		}
		select {
		case <-e.done:
			row := e.snapshot()
			g.retired = append(g.retired, row)
			delete(g.entries, id)
			if wanted && reflect.DeepEqual(p, e.profile) {
				if row.State == "quota" {
					g.failures[id] = failure{after: now.Add(100 * 365 * 24 * time.Hour)}
				} else {
					f := g.failures[id]
					f.attempt = min(f.attempt+1, 6)
					f.after = now.Add(time.Duration(1<<f.attempt) * time.Second)
					g.failures[id] = f
				}
			}
		default:
			e.mu.Lock()
			if e.runtime != nil {
				e.runtime.Reap(now)
				metrics := e.runtime.Metrics()
				if p.MaxBytes > 0 && (metrics.RX >= p.MaxBytes || metrics.TX >= p.MaxBytes-metrics.RX) {
					e.state = "quota"
					e.cancel()
				}
			}
			e.mu.Unlock()
		}
	}
	// Drain changed/removed profiles before reusing their documents/listeners.
	// A cancelled slow startup cannot later resurrect an obsolete profile.
	if changing || len(g.retired) >= MaxProfiles {
		return
	}
	ids := make([]string, 0, len(g.wanted))
	for id := range g.wanted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if g.entries[id] != nil || now.Before(g.failures[id].after) {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			cancel()
			continue
		}
		e := &entry{profile: g.wanted[id], epoch: hex.EncodeToString(nonce[:]), cancel: cancel, done: make(chan struct{}), state: "starting"}
		g.entries[id] = e
		go g.run(ctx, e)
	}
}

func (g *Group) run(ctx context.Context, e *entry) {
	defer close(e.done)
	select {
	case g.slots <- struct{}{}:
	case <-ctx.Done():
		e.mu.Lock()
		e.state = "stopped"
		e.mu.Unlock()
		return
	}
	runtime, err := g.factory(e.profile)
	if err == nil && ctx.Err() == nil {
		err = runtime.Start()
	}
	<-g.slots
	if err != nil || ctx.Err() != nil {
		if runtime != nil {
			runtime.Close()
		}
		e.mu.Lock()
		e.state = "start_failed"
		if ctx.Err() != nil {
			e.state = "stopped"
		}
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.runtime = runtime
	e.state = "running"
	e.mu.Unlock()
	<-ctx.Done()
	e.mu.Lock()
	e.final = runtime.Metrics()
	e.runtime = nil
	if e.state != "quota" {
		e.state = "stopped"
	}
	e.mu.Unlock()
	runtime.Close()
	e.mu.Lock()
	e.final = runtime.Metrics()
	e.mu.Unlock()
}

type Snapshot struct {
	Version    int   `json:"version"`
	UpdatedAt  int64 `json:"updatedAt"`
	ValidUntil int64 `json:"validUntil"`
	Profiles   []Row `json:"profiles"`
	Retired    []Row `json:"retired"`
}

func (g *Group) Snapshot(now time.Time) Snapshot {
	s := Snapshot{Version: 1, UpdatedAt: now.Unix(), ValidUntil: g.validUntil, Profiles: []Row{}, Retired: append([]Row(nil), g.retired...)}
	for _, e := range g.entries {
		s.Profiles = append(s.Profiles, e.snapshot())
	}
	sort.Slice(s.Profiles, func(i, j int) bool { return s.Profiles[i].ID < s.Profiles[j].ID })
	return s
}
func (g *Group) Close() {
	if g.closed {
		return
	}
	g.closed = true
	for _, e := range g.entries {
		e.cancel()
	}
	for _, e := range g.entries {
		<-e.done
	}
}

func WriteSnapshot(path string, s Snapshot) error {
	content, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".metrics-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(content)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
