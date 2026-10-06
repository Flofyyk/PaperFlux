package manager

import (
	"net/url"
	"time"
	"universal-bypass-tool/transport/yandexhosts"
)

func yandexCookieRoot(entry *Entry) string {
	if entry == nil || entry.Provider == nil || (entry.Type != "yandex" && entry.Type != "vyandex") {
		return ""
	}
	u, err := url.Parse(entry.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return ""
	}
	root, _ := yandexhosts.Root(u.Hostname())
	return root
}

// This Manager belongs to exactly one profile on one node. Copy only an
// accepted anonymous check/browser identity within its primary Yandex root.
// Never copy login cookies, peer/IP-bound proofs, regional jars or a healthy
// sibling. An unchanged check is tried once, not on every recovery tick.
func (m *Manager) ShareConnectedYandexCheck() {
	m.mu.RLock()
	entries := make([]Entry, 0, len(m.order))
	for _, name := range m.order {
		entries = append(entries, *m.entries[name])
	}
	m.mu.RUnlock()
	for _, source := range entries {
		root := yandexCookieRoot(&source)
		if root == "" || !source.Raw.IsConnected() {
			continue
		}
		jar, err := m.FetchCookiesFor(source.Name)
		if err != nil || jar["spravka"] == "" || jar["yandexuid"] == "" {
			continue
		}
		shared := make(map[string]string)
		for _, name := range []string{"spravka", "yandexuid", "yuidss", "ymex", "i", "bh", "_yasc", "yashr"} {
			if value, exists := jar[name]; exists {
				shared[name] = value
			}
		}
		for _, target := range entries {
			if target.Name == source.Name || yandexCookieRoot(&target) != root || target.Raw.IsConnected() {
				continue
			}
			m.cookieMu.Lock()
			m.mu.RLock()
			recent := m.browserSubmitted[target.Name]
			m.mu.RUnlock()
			current, err := m.FetchCookiesFor(target.Name)
			if err == nil && time.Since(recent) >= 30*time.Second &&
				(current["spravka"] != shared["spravka"] || current["yandexuid"] != shared["yandexuid"]) {
				_ = m.acceptCookiesForDomainLocked(target.Name, "", shared, true)
			}
			m.cookieMu.Unlock()
		}
		// Choose one stable priority source; never oscillate between two
		// simultaneously accepted but different browser identities.
		return
	}
}
