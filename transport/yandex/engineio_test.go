package yandex

import (
	"testing"
)

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

func TestDisconnectReasonSummary(t *testing.T) {
	valid := []byte(`42["message",{"type":"disconnectReason","code":4007,"description":"drop"}]`)
	if got, ok := disconnectReasonSummary(valid); !ok || got != `code=4007 description="drop"` {
		t.Fatalf("valid disconnect reason = %q, %v", got, ok)
	}
	// Auth frames may include arbitrary editor metadata. They must never be
	// mistaken for a command to close a healthy session.
	nonEvent := []byte(`42["message",{"type":"auth","description":"disconnectReason","result":1}]`)
	if got, ok := disconnectReasonSummary(nonEvent); ok || got != "" {
		t.Fatalf("auth frame misclassified as disconnect reason: %q, %v", got, ok)
	}
}
