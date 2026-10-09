package manager

import "maps"

// Later jars win. Never mutate a provider snapshot or the caller's offer.
func mergeCookies(jars ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, jar := range jars {
		maps.Copy(out, jar)
	}
	return out
}

// Confirmation checks the offered values, allowing unrelated retained cookies.
// Presence matters: a missing cookie is not an accepted empty-valued cookie.
func containsCookies(current, offered map[string]string) bool {
	for name, value := range offered {
		got, ok := current[name]
		if !ok || got != value {
			return false
		}
	}
	return true
}

// Cookies identifying an account are private to the node where it signed in.
// Only non-account cookies (including a passed CAPTCHA) answer peer requests.
func shareableCookies(jar map[string]string) map[string]string {
	out := make(map[string]string, len(jar))
	for name, value := range jar {
		switch name {
		case "Session_id", "sessionid2", "sessar", "sessguard", "L", "yandex_login", "lah", "mda2_beacon":
			continue
		case "solution429", "hitw429":
			continue // Mail.ru WAF verification belongs to the sender's address.
		}
		out[name] = value
	}
	return out
}
