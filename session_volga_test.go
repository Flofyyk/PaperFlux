package main

import (
	"strings"
	"testing"

	"universal-bypass-tool/transport"
)

func TestVolgaFallbackIsSeparateLowerPriorityLane(t *testing.T) {
	const ws = "https://disk.yandex.ru/i/ws_doc"
	const volga = "https://disk.yandex.ru/i/text_doc"
	runtime, err := newProfileSessionRuntime("yandex", []string{ws}, volga,
		transport.DefaultConfig(), true, "", "", sessionIdentity{ID: "42", Token: strings.Repeat("a", 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	names := runtime.Transports()
	if len(names) != 2 || names[0] != "yandex-1" || names[1] != "volga-1" {
		t.Fatalf("unexpected lane order: %v", names)
	}
}

func TestVolgaFallbackRejectsSharedOrUnsafeDocument(t *testing.T) {
	const ws = "https://disk.yandex.ru/i/ws_doc"
	for _, volga := range []string{ws, "http://disk.yandex.ru/i/text", "https://evil.invalid/i/text", "https://disk.yandex.ru/i/text?x=1"} {
		_, err := newProfileSessionRuntime("yandex", []string{ws}, volga,
			transport.DefaultConfig(), true, "", "", sessionIdentity{ID: "42", Token: strings.Repeat("a", 32)})
		if err == nil {
			t.Fatalf("unsafe Volga document accepted: %q", volga)
		}
	}
}
