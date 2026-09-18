package yandex

import (
	"testing"
	"time"

	"universal-bypass-tool/transport"
)

func TestFailedBatchIsRetriedBeforeNewerPackets(t *testing.T) {
	y := NewYandexDocsTransport("https://disk.yandex.ru/test", transport.DefaultConfig(), "1", "12345678901234567890123456789012", "client")
	first := queuedPacket{data: []byte{1}, queuedAt: time.Now()}
	second := queuedPacket{data: []byte{2}, queuedAt: time.Now()}
	y.queuedPackets.Store(2)
	y.queuedBytes.Store(2)
	y.requeueBatch([]queuedPacket{first, second})
	batch := y.takeRetryBatch()
	if len(batch) != 2 || batch[0].data[0] != 1 || batch[1].data[0] != 2 {
		t.Fatalf("retry order = %#v", batch)
	}
	if y.Stats().RetryQueued != 2 || y.Stats().QueuePackets != 2 {
		t.Fatalf("queue stats = %+v", y.Stats())
	}
}

func TestExpiredRetryIsDropped(t *testing.T) {
	y := NewYandexDocsTransport("https://disk.yandex.ru/test", transport.DefaultConfig(), "1", "12345678901234567890123456789012", "client")
	y.queuedPackets.Store(1)
	y.queuedBytes.Store(1)
	y.requeueBatch([]queuedPacket{{data: []byte{1}, queuedAt: time.Now().Add(-maxQueuedPacketAge - time.Second)}})
	if got := y.takeRetryBatch(); len(got) != 0 {
		t.Fatalf("expired batch retained: %#v", got)
	}
	stats := y.Stats()
	if stats.ExpiredDrops != 1 || stats.QueuePackets != 0 || stats.QueueBytes != 0 {
		t.Fatalf("queue stats = %+v", stats)
	}
}

func TestReplacingDocumentSessionRequiresFreshPeerProof(t *testing.T) {
	y := NewYandexDocsTransport("https://disk.yandex.ru/test", transport.DefaultConfig(), "1", "12345678901234567890123456789012", "client")
	y.peerReady.Store(true)
	y.lastProof.Store(time.Now().UnixNano())
	y.proofMu.Lock()
	y.pendingProof[7] = pendingProof{sent: time.Now()}
	y.proofMu.Unlock()

	y.resetPeerReadiness()

	if y.peerReady.Load() || y.lastProof.Load() != 0 {
		t.Fatal("replacement session inherited readiness from retired WebSocket")
	}
	y.proofMu.Lock()
	remaining := len(y.pendingProof)
	y.proofMu.Unlock()
	if remaining != 0 {
		t.Fatalf("retired proofs remain: %d", remaining)
	}
}

func TestShortDocumentFailuresOpenLaneCircuit(t *testing.T) {
	y := NewYandexDocsTransport("https://disk.yandex.ru/test", transport.DefaultConfig(), "1", "12345678901234567890123456789012", "client")
	now := time.Now()
	y.peerReadyAt.Store(now.Add(-5 * time.Second).UnixNano())

	if got := y.shortFailureCooldown(now); got != 0 {
		t.Fatalf("first short failure cooldown = %s, want 0", got)
	}
	if got := y.shortFailureCooldown(now.Add(time.Second)); got != 0 {
		t.Fatalf("second short failure cooldown = %s, want 0", got)
	}
	if got := y.shortFailureCooldown(now.Add(2 * time.Second)); got != circuitCooldownBase {
		t.Fatalf("third short failure cooldown = %s, want %s", got, circuitCooldownBase)
	}
}

func TestStableDocumentClearsLaneCircuit(t *testing.T) {
	y := NewYandexDocsTransport("https://disk.yandex.ru/test", transport.DefaultConfig(), "1", "12345678901234567890123456789012", "client")
	now := time.Now()
	y.peerReadyAt.Store(now.Add(-shortSessionWindow).UnixNano())
	y.shortFailures.Store(4)
	y.circuitOpenUntil.Store(now.Add(time.Minute).UnixNano())

	if got := y.shortFailureCooldown(now); got != 0 {
		t.Fatalf("stable session cooldown = %s, want 0", got)
	}
	if got := y.shortFailures.Load(); got != 0 {
		t.Fatalf("stable session kept short failures = %d", got)
	}
	if got := y.circuitOpenUntil.Load(); got != 0 {
		t.Fatalf("stable session kept circuit deadline = %d", got)
	}
}
