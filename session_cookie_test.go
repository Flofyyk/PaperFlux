package main

import (
	"path/filepath"
	"testing"

	"universal-bypass-tool/transport"
)

func TestSeedProfileYandexCookiesOnlyMissingDocuments(t *testing.T) {
	store, err := transport.NewCookieStore(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc1 := "https://disk.yandex.ru/i/first"
	doc2 := "https://disk.yandex.ru/i/second"
	volga := "https://disk.yandex.ru/i/fallback"
	if err := store.Save(profileCookieKey("yandex", doc2), map[string]string{"session": "from-second"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(profileCookieKey("mailru", "unrelated"), map[string]string{"session": "other-provider"}); err != nil {
		t.Fatal(err)
	}
	if err := seedProfileYandexCookies(store, []string{doc1, doc2}, volga); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{profileCookieKey("yandex", doc1), profileCookieKey("vyandex", volga)} {
		if got := store.Load(key)["session"]; got != "from-second" {
			t.Fatalf("new document jar was not seeded: %q", got)
		}
	}
	if got := store.Load(profileCookieKey("mailru", "unrelated"))["session"]; got != "other-provider" {
		t.Fatalf("other provider changed: %q", got)
	}
	if err := store.Save(profileCookieKey("yandex", doc1), map[string]string{"session": "own-cookie"}); err != nil {
		t.Fatal(err)
	}
	if err := seedProfileYandexCookies(store, []string{doc1, doc2}, volga); err != nil {
		t.Fatal(err)
	}
	if got := store.Load(profileCookieKey("yandex", doc1))["session"]; got != "own-cookie" {
		t.Fatalf("existing document jar overwritten: %q", got)
	}
}
