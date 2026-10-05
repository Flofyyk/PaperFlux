package manager

import (
	"fmt"
	"net/url"
	"universal-bypass-tool/transport/yandexhosts"
)

type domainCookieProvider interface {
	ApplyCookiesForDomain(string, map[string]string) error
	FetchCookiesForDomain(string) (map[string]string, error)
}

func domainStoreKey(key, root string) string { return key + "|verification-domain:" + root }

func (m *Manager) cookieDomainProvider(name, domain string) (domainCookieProvider, string, error) {
	root, ok := yandexhosts.Root(domain)
	if !ok {
		return nil, "", fmt.Errorf("unsupported verification cookie domain")
	}
	m.mu.RLock()
	e := m.entries[name]
	m.mu.RUnlock()
	if e == nil {
		return nil, "", fmt.Errorf("unknown cookie transport")
	}
	provider, ok := e.Provider.(domainCookieProvider)
	if !ok {
		return nil, "", fmt.Errorf("transport does not support scoped verification cookies")
	}
	return provider, root, nil
}

func (m *Manager) fetchCookiesForDomain(name, domain string) (map[string]string, error) {
	if domain == "" {
		return m.FetchCookiesFor(name)
	}
	provider, root, err := m.cookieDomainProvider(name, domain)
	if err != nil {
		return nil, err
	}
	return provider.FetchCookiesForDomain(root)
}

// Existing Domain fields in IPC/control now keep regional cookies scoped.
// Old offers without Domain retain their historical document-domain behavior.
func (m *Manager) AcceptCookiesForDomain(name, domain string, jar map[string]string) error {
	return m.acceptCookiesForDomain(name, domain, jar, true)
}

// A background snapshot from another node is not a fresh browser result on
// this node. Preserve local values; provider checks can be IP/UA-bound.
func (m *Manager) acceptPeerCookiesForDomain(name, domain string, jar map[string]string) error {
	return m.acceptCookiesForDomain(name, domain, shareableCookies(jar), false)
}

func (m *Manager) acceptCookiesForDomain(name, domain string, jar map[string]string, incomingWins bool) error {
	m.cookieMu.Lock()
	defer m.cookieMu.Unlock()
	var root string
	apply := func(values map[string]string) error { return m.ApplyCookiesFor(name, values) }
	if domain != "" {
		provider, normalized, err := m.cookieDomainProvider(name, domain)
		if err != nil {
			return err
		}
		root = normalized
		apply = func(values map[string]string) error { return provider.ApplyCookiesForDomain(root, values) }
	}
	current, err := m.fetchCookiesForDomain(name, domain)
	if err != nil {
		return err
	}
	// An empty offer is not an instruction to erase the profile's login.
	if len(jar) == 0 {
		return nil
	}
	m.mu.RLock()
	store, key := m.store, m.cookieKeys[name]
	docURL := ""
	if entry := m.entries[name]; entry != nil {
		docURL = entry.URL
	}
	m.mu.RUnlock()
	// The primary record keeps backward compatibility with profile seeding.
	// A regional offer must never import the primary domain's saved cookies.
	if root != "" && key != "" {
		primary := ""
		if doc, err := url.Parse(docURL); err == nil {
			primary, _ = yandexhosts.Root(doc.Hostname())
		}
		if primary != root {
			key = domainStoreKey(key, root)
		}
	}
	var saved map[string]string
	if store != nil && key != "" {
		saved = store.Load(key)
	}
	// Live HTTP cookies can be fresher than the persisted snapshot; the
	// just-completed verification takes precedence over both of them.
	merged := mergeCookies(saved, current, jar)
	if !incomingWins {
		merged = mergeCookies(saved, jar, current)
		// A stale background response must not wake or rewrite this lane.
		if containsCookies(current, merged) {
			return nil
		}
	}
	if err := apply(merged); err != nil {
		return err
	}
	if store != nil && key != "" {
		return store.Save(key, merged)
	}
	return nil
}
