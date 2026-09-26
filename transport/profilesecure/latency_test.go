package profilesecure

import (
	"testing"
	"time"
)

func TestSlowChannelProofIsNotOverwritten(t *testing.T) {
	aRaw, bRaw := &memoryTransport{latency: 700 * time.Millisecond}, &memoryTransport{latency: 700 * time.Millisecond}
	aRaw.peer, bRaw.peer = bRaw, aRaw
	a, _ := New(aRaw, "7", "local-test-token-at-least-32-characters", "mailru", false)
	b, _ := New(bRaw, "7", "local-test-token-at-least-32-characters", "mailru", true)
	_ = a.Start()
	_ = b.Start()
	defer a.Stop()
	defer b.Stop()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if a.IsConnected() && b.IsConnected() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("1.4s RTT never became ready: pending proof was replaced")
}
