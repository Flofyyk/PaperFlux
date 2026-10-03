package yandexhosts

import "testing"

func TestTrustedRootsAndDocumentHosts(t *testing.T) {
	for _, root := range Roots() {
		for _, prefix := range []string{"docs.", "disk."} {
			host := prefix + root
			if got, ok := Root(host); !ok || got != root || !DocumentHost(host) {
				t.Fatal(host)
			}
			if _, ok := Root(host + ".evil.invalid"); ok {
				t.Fatal("lookalike accepted")
			}
		}
		if DocumentHost("passport." + root) {
			t.Fatal("login host accepted as document fetch")
		}
	}
	for _, host := range []string{"127.0.0.1", "yandex.kz.evil.invalid", "evilyandex.ru", "yandex.ru@evil.invalid"} {
		if _, ok := Root(host); ok {
			t.Fatal(host)
		}
	}
}
