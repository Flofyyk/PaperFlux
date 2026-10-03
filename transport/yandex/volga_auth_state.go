package yandex

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var errVolgaAuthRefresh = errors.New("Volga authorization refresh failed")
var errVolgaUnauthorized = errors.New("Volga authorization rejected")

// Generation-based coordination follows the approach in GEFSED/OpenFlux's
// volga-http-401-reauth branch, retaining PaperFlux's bounded workers/queues.
type volgaAuthSnapshot struct {
	auth       *volgaAuth
	generation uint64
	completed  uint64
	changed    <-chan struct{}
}

type volgaAuthAttempt struct {
	id     uint64
	done   chan struct{}
	result volgaAuthSnapshot
	err    error
}

type volgaAuthState struct {
	mu         sync.Mutex
	current    *volgaAuth
	generation uint64
	completed  uint64
	changed    chan struct{}
	last       *volgaAuthAttempt
	retryAfter time.Time
	authorize  func(context.Context) (*volgaAuth, error)
	onPublish  func()
	expired    atomic.Bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func cloneVolgaAuth(auth *volgaAuth) *volgaAuth {
	if auth == nil {
		return nil
	}
	copyAuth := *auth
	if auth.Session != nil {
		client := *auth.Session
		copyAuth.Session = &client // Jar is concurrency-safe, Client fields are not.
	}
	copyAuth.Cookies = nil
	for _, c := range auth.Cookies {
		if c == nil {
			continue
		}
		cookie := *c
		cookie.Unparsed = append([]string(nil), c.Unparsed...)
		copyAuth.Cookies = append(copyAuth.Cookies, &cookie)
	}
	return &copyAuth
}

func newVolgaAuthState(ctx context.Context, auth *volgaAuth) *volgaAuthState {
	ctx, cancel := context.WithCancel(ctx)
	return &volgaAuthState{ctx: ctx, cancel: cancel, current: cloneVolgaAuth(auth), generation: 1, changed: make(chan struct{})}
}

func (a *volgaAuthState) snapshotLocked() volgaAuthSnapshot {
	return volgaAuthSnapshot{a.current, a.generation, a.completed, a.changed}
}

func (a *volgaAuthState) snapshot() volgaAuthSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.snapshotLocked()
}

func (a *volgaAuthState) Load() *volgaAuth { return a.snapshot().auth }

func (a *volgaAuthState) reject(stale volgaAuthSnapshot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.generation == stale.generation {
		a.expired.Store(true)
	}
}

func (a *volgaAuthState) refresh(ctx context.Context, stale volgaAuthSnapshot) (volgaAuthSnapshot, error) {
	a.mu.Lock()
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return volgaAuthSnapshot{}, err
	}
	if err := a.ctx.Err(); err != nil {
		a.mu.Unlock()
		return volgaAuthSnapshot{}, err
	}
	if a.generation != stale.generation {
		fresh := a.snapshotLocked()
		a.mu.Unlock()
		return fresh, nil
	}
	attempt := a.last
	if attempt == nil || (stale.completed >= attempt.id && !time.Now().Before(a.retryAfter)) {
		attempt = &volgaAuthAttempt{id: a.completed + 1, done: make(chan struct{})}
		a.last = attempt
		a.wg.Add(1)
		go a.runRefresh(attempt)
	}
	a.mu.Unlock()
	select {
	case <-ctx.Done():
		return volgaAuthSnapshot{}, ctx.Err()
	case <-a.ctx.Done():
		return volgaAuthSnapshot{}, a.ctx.Err()
	case <-attempt.done:
		if err := ctx.Err(); err != nil {
			return volgaAuthSnapshot{}, err
		}
		if err := a.ctx.Err(); err != nil {
			return volgaAuthSnapshot{}, err
		}
		return attempt.result, attempt.err
	}
}

func (a *volgaAuthState) runRefresh(attempt *volgaAuthAttempt) {
	defer a.wg.Done()
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	var fresh *volgaAuth
	err := errVolgaAuthRefresh
	if a.authorize != nil {
		fresh, err = a.authorize(ctx)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil || fresh == nil || ctx.Err() != nil {
		// Do not leak URLs/tokens from the authorizer or destroy last good auth.
		attempt.err = errVolgaAuthRefresh
		a.retryAfter = time.Now().Add(time.Second)
	} else {
		a.current = cloneVolgaAuth(fresh)
		a.generation++
		a.expired.Store(false)
		a.retryAfter = time.Time{}
		if a.onPublish != nil {
			a.onPublish()
		}
		close(a.changed)
		a.changed = make(chan struct{})
	}
	a.completed = attempt.id
	attempt.result = a.snapshotLocked()
	close(attempt.done)
}

func (a *volgaAuthState) stop() {
	a.cancelRefresh()
	a.wg.Wait()
}

// Cancellation and publication share the lock: Stop cannot return while a
// late success is about to publish. It does not wait on an authorizer callback.
func (a *volgaAuthState) cancelRefresh() {
	a.mu.Lock()
	a.cancel()
	a.mu.Unlock()
}
