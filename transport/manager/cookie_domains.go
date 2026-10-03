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
	if domain == "" {
		return m.AcceptCookies(name, jar)
	}
	provider, root, err := m.cookieDomainProvider(name, domain)
	if err != nil {
		return err
	}
	if err := provider.ApplyCookiesForDomain(root, jar); err != nil {
		return err
	}
	m.mu.RLock()
	store, key := m.store, m.cookieKeys[name]
	m.mu.RUnlock()
	if store != nil && key != "" {
		// Keep the primary-domain key compatible with existing profile seeding
		// and older peers; only other regions need a separate scoped record.
		if doc, err := url.Parse(m.entryURL(name)); err == nil {
			if primary, ok := yandexhosts.Root(doc.Hostname()); ok && primary == root {
				return store.Save(key, jar)
			}
		}
		return store.Save(domainStoreKey(key, root), jar)
	}
	return nil
}
