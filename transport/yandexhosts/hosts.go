// Package yandexhosts keeps verification endpoints on explicit trusted roots.
package yandexhosts

import "strings"

func Roots() []string {
	return []string{"yandex.ru", "yandex.com", "yandex.by", "yandex.kz", "yandex.uz", "yandex.com.tr"}
}

func Root(host string) (string, bool) {
	host = strings.ToLower(strings.TrimPrefix(host, "."))
	for _, root := range Roots() {
		if host == root || strings.HasSuffix(host, "."+root) {
			return root, true
		}
	}
	return "", false
}

func DocumentHost(host string) bool {
	host = strings.ToLower(host)
	for _, root := range Roots() {
		if host == "disk."+root || host == "docs."+root {
			return true
		}
	}
	return false
}
