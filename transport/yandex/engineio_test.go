package yandex

import "testing"

func TestEnginePollingURL(t *testing.T) {
	got, err := enginePollingURL("wss://example.test/doc/c/?EIO=4&transport=websocket&sid=old")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://example.test/doc/c/?EIO=4&transport=polling"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
