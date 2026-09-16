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
