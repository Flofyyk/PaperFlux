package manager

import (
	"errors"
	"time"
	"universal-bypass-tool/transport/control"
)

// An authenticated, nonce-bound status query recovers a lost completion or
// exit restart. It carries no jar and causes no HTTP/provider activity.
func (m *Manager) RequestCookieVerification(name, requestID string) {
	if m.session == nil || m.IsExit() || requestID == "" || len(requestID) > 64 {
		return
	}
	doc := m.entryURL(name)
	if doc == "" {
		return
	}
	m.mu.Lock()
	if m.verificationRequested == nil {
		m.verificationRequested = make(map[string]time.Time)
	}
	if time.Since(m.verificationRequested[name]) < 10*time.Second {
		m.mu.Unlock()
		return
	}
	m.verificationRequested[name] = time.Now()
	m.mu.Unlock()
	body, err := (&control.CookiesPayload{Transport: name, Doc: doc, Reason: "verify", RequestID: requestID}).Encode()
	if err == nil {
		err = m.SendControl(control.SubtypeCookiesRequest, body)
	}
	if err != nil {
		m.mu.Lock()
		delete(m.verificationRequested, name)
		m.mu.Unlock()
	}
}

func (m *Manager) IsExit() bool { return m.session != nil && m.session.IsExit() }

// A verified notification carries no cookies and is emitted only by the
// authenticated exit after this exact configured document actually connects.
func (m *Manager) SendCookieVerification(name string) error {
	if !m.IsExit() || !m.IsCookieCarrierConnected(name) {
		return errors.New("document is not verified")
	}
	doc := m.entryURL(name)
	if doc == "" {
		return errors.New("document identity missing")
	}
	m.mu.RLock()
	id := m.verificationIDs[name]
	m.mu.RUnlock()
	body, err := (&control.CookiesPayload{Transport: name, Doc: doc, Reason: "verified", RequestID: id}).Encode()
	if err != nil {
		return err
	}
	return m.SendControl(control.SubtypeCookiesResponse, body)
}

// Re-send a stored, still-blocked check to a peer that connected after the
// provider reported it. This uses only the encrypted control channel: it
// does not poll Yandex or generate another local request/nonce.
func (m *Manager) ForwardPendingCookieCheck(name, url, reason string) {
	if !m.IsExit() || m.entryURL(name) == "" || m.IsCookieCarrierConnected(name) {
		return
	}
	m.forwardAuth(name, url, reason)
}

func (m *Manager) MatchesVerifiedDocument(name, doc string) bool {
	// Do not use the legacy type/name fallback for a completion proof.
	return name != "" && doc != "" && m.entryURL(name) == doc
}
