package yandex

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func makeTestBatch(packets ...[]byte) []byte {
	out := append([]byte(nil), batchMagic...)
	for _, packet := range packets {
		var n [2]byte
		binary.BigEndian.PutUint16(n[:], uint16(len(packet)))
		out = append(out, n[:]...)
		out = append(out, packet...)
	}
	return out
}

func TestUnpackBatchPreservesOrderAndBytes(t *testing.T) {
	want := [][]byte{[]byte("first"), []byte{0, 1, 2, 3}, bytes.Repeat([]byte{0xaa}, 1500)}
	var got [][]byte
	if !unpackBatch(makeTestBatch(want...), func(packet []byte) {
		got = append(got, append([]byte(nil), packet...))
	}) {
		t.Fatal("valid batch rejected")
	}
	if len(got) != len(want) {
		t.Fatalf("packet count: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d changed", i)
		}
	}
}

func TestUnpackBatchRejectsTruncatedFrameWithoutEmitting(t *testing.T) {
	data := makeTestBatch([]byte("complete"))
	data = data[:len(data)-2]
	emitted := 0
	if unpackBatch(data, func([]byte) { emitted++ }) {
		t.Fatal("truncated batch accepted")
	}
	if emitted != 0 {
		t.Fatalf("partial frame emitted %d packets", emitted)
	}
}
