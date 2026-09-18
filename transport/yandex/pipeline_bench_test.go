package yandex

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
)

func benchmarkSecurePair(b *testing.B) (*secureChannel, *secureChannel) {
	b.Helper()
	a, err := newSecureChannel("bench", "0123456789abcdef0123456789abcdef", "bench-document", false)
	if err != nil {
		b.Fatal(err)
	}
	c, err := newSecureChannel("bench", "0123456789abcdef0123456789abcdef", "bench-document", true)
	if err != nil {
		b.Fatal(err)
	}
	ackC, err := c.receiveHandshake(a.hello())
	if err != nil {
		b.Fatal(err)
	}
	ackA, err := a.receiveHandshake(c.hello())
	if err != nil {
		b.Fatal(err)
	}
	if _, err = a.receiveHandshake(ackC); err != nil {
		b.Fatal(err)
	}
	if _, err = c.receiveHandshake(ackA); err != nil {
		b.Fatal(err)
	}
	return a, c
}

func benchmarkPayload(size int) []byte {
	batch := append([]byte(nil), batchMagic...)
	for len(batch) < size {
		block := sha256.Sum256([]byte(fmt.Sprintf("packet-%d", len(batch))))
		chunk := block[:]
		if remaining := size - len(batch) - 2; remaining < len(chunk) {
			chunk = chunk[:max(0, remaining)]
		}
		if len(chunk) == 0 {
			break
		}
		var n [2]byte
		binary.BigEndian.PutUint16(n[:], uint16(len(chunk)))
		batch = append(batch, n[:]...)
		batch = append(batch, chunk...)
	}
	return batch
}

func BenchmarkYandexFramePipeline(b *testing.B) {
	for _, size := range []int{16 << 10, 32 << 10, 48 << 10, 64 << 10} {
		for _, deflate := range []bool{false, true} {
			name := fmt.Sprintf("batch_%dK/deflate_%t", size>>10, deflate)
			b.Run(name, func(b *testing.B) {
				a, _ := benchmarkSecurePair(b)
				payload := benchmarkPayload(size)
				b.SetBytes(int64(len(payload)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					sealed, err := a.seal(payload)
					if err != nil {
						b.Fatal(err)
					}
					encoded := make([]byte, base64.StdEncoding.EncodedLen(len(sealed)))
					base64.StdEncoding.Encode(encoded, sealed)
					if deflate {
						var compressed bytes.Buffer
						writer, err := flate.NewWriter(&compressed, flate.BestSpeed)
						if err != nil {
							b.Fatal(err)
						}
						if _, err = writer.Write(encoded); err != nil {
							b.Fatal(err)
						}
						if err = writer.Close(); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func TestYandexFrameCompressionRatio(t *testing.T) {
	for _, size := range []int{16 << 10, 32 << 10, 48 << 10, 64 << 10} {
		a, _ := pair(t)
		sealed, err := a.seal(benchmarkPayload(size))
		if err != nil {
			t.Fatal(err)
		}
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(sealed)))
		base64.StdEncoding.Encode(encoded, sealed)
		var compressed bytes.Buffer
		writer, err := flate.NewWriter(&compressed, flate.BestSpeed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = writer.Write(encoded); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("batch=%dKiB wire=%d compressed=%d ratio=%.3f", size>>10, len(encoded), compressed.Len(), float64(compressed.Len())/float64(len(encoded)))
	}
}
