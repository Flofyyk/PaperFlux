package mailru

import (
	"strings"
	"sync"
	"time"
	"universal-bypass-tool/transport"
)

// Lifecycle and privacy integration only. Cursor and editor messages follow upstream.
func (t *MailruDocsTransport) Stop() error {
	_ = t.BaseTransport.Stop()
	t.Mu.Lock()
	session, pending := t.session, t.pending
	t.session, t.pending = nil, nil
	t.Mu.Unlock()
	if session != nil && session.Conn != nil {
		_ = session.Conn.Close()
	}
	if pending != nil && pending.Conn != nil {
		_ = pending.Conn.Close()
	}
	return nil
}

func (t *MailruDocsTransport) dropSession(session *DocSession) bool {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	if t.session != session {
		return false
	}
	t.session = nil
	t.SetConnected(false)
	return true
}

func (t *MailruDocsTransport) Stats() transport.TransportStats {
	s := t.BaseTransport.Stats()
	t.Mu.RLock()
	s.QueuePackets = uint64(len(t.writeQueue))
	t.Mu.RUnlock()
	s.WriteFailures = t.writeFailures.Load()
	return s
}

func (t *MailruDocsTransport) LaneHealth() transport.LaneHealth {
	t.Mu.RLock()
	load := float64(len(t.writeQueue)) / float64(max(1, cap(t.writeQueue)))
	t.Mu.RUnlock()
	return transport.LaneHealth{Connected: t.IsConnected(), QueueLoad: load, WriteFailures: t.writeFailures.Load()}
}

var warningTimes = struct {
	sync.Mutex
	values map[string]time.Time
}{values: map[string]time.Time{}}

func mailruThrottled(key string, interval time.Duration) bool {
	warningTimes.Lock()
	defer warningTimes.Unlock()
	now := time.Now()
	if now.Sub(warningTimes.values[key]) < interval {
		return false
	}
	warningTimes.values[key] = now
	return true
}

// Never exchange Mail.ru account authentication cookies between VPN peers.
func shareMailruCookie(name string) bool {
	switch strings.ToLower(name) {
	case "mpop", "m_auth2", "m_auth", "auth", "auth_token", "access_token", "refresh_token", "password":
		return false
	case "solution429", "hitw429":
		return false // Address-bound WAF cookies remain in the local profile store.
	}
	return len(name) > 0 && len(name) < 256
}
