package ctls

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func newTestRecordPair(t testing.TB) (*encryptedRecord, *encryptedRecord) {
	t.Helper()
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("key: %v", err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("iv: %v", err)
	}

	send, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	recv, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	return newEncryptedRecord(send, iv), newEncryptedRecord(recv, iv)
}

// TestSealRecordRoundTrip pins that a sealed record carries a correct header
// and decrypts back to the original plaintext and inner type, including when
// the write buffer is reused across records — reuse is what makes the write
// path allocation-free, and it is also how a stale-buffer bug would show up.
func TestSealRecordRoundTrip(t *testing.T) {
	send, recv := newTestRecordPair(t)

	payloads := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte("x"), 4096),
		{},
		[]byte("short again"),
		bytes.Repeat([]byte("y"), maxPlaintextRecord),
	}

	var buf []byte
	for i, payload := range payloads {
		record, err := send.sealRecord(buf, payload, recordTypeApplicationData)
		if err != nil {
			t.Fatalf("record %d: sealRecord: %v", i, err)
		}
		buf = record

		if got := record[0]; got != recordTypeApplicationData {
			t.Fatalf("record %d: type byte = %d", i, got)
		}
		bodyLen := int(record[3])<<8 | int(record[4])
		if bodyLen != len(record)-recordHeaderLen {
			t.Fatalf("record %d: header says %d bytes, body is %d",
				i, bodyLen, len(record)-recordHeaderLen)
		}

		// decrypt works in place, so hand it a copy the way a real read would.
		body := append([]byte(nil), record[recordHeaderLen:]...)
		plaintext, innerType, err := recv.decrypt(body)
		if err != nil {
			t.Fatalf("record %d: decrypt: %v", i, err)
		}
		if innerType != recordTypeApplicationData {
			t.Fatalf("record %d: inner type = %d", i, innerType)
		}
		if !bytes.Equal(plaintext, payload) {
			t.Fatalf("record %d: round trip lost data (%d vs %d bytes)",
				i, len(plaintext), len(payload))
		}
	}
}

// TestSealRecordSequence pins that each record advances the nonce. Reusing a
// nonce under the same key is a total loss of AEAD security, so a record must
// never decrypt at the wrong sequence position.
func TestSealRecordSequence(t *testing.T) {
	send, recv := newTestRecordPair(t)

	first, err := send.sealRecord(nil, []byte("one"), recordTypeApplicationData)
	if err != nil {
		t.Fatalf("sealRecord: %v", err)
	}
	firstBody := append([]byte(nil), first[recordHeaderLen:]...)

	second, err := send.sealRecord(nil, []byte("two"), recordTypeApplicationData)
	if err != nil {
		t.Fatalf("sealRecord: %v", err)
	}
	secondBody := append([]byte(nil), second[recordHeaderLen:]...)

	// The receiver is at seq 0, so the record sealed at seq 1 must not open.
	if _, _, err := recv.decrypt(append([]byte(nil), secondBody...)); err == nil {
		t.Fatal("record accepted out of sequence; the nonce is not advancing")
	}

	// In order, both open.
	send2, recv2 := newTestRecordPair(t)
	a, err := send2.sealRecord(nil, []byte("one"), recordTypeApplicationData)
	if err != nil {
		t.Fatalf("sealRecord: %v", err)
	}
	aBody := append([]byte(nil), a[recordHeaderLen:]...)
	b, err := send2.sealRecord(nil, []byte("two"), recordTypeApplicationData)
	if err != nil {
		t.Fatalf("sealRecord: %v", err)
	}
	bBody := append([]byte(nil), b[recordHeaderLen:]...)

	if p, _, err := recv2.decrypt(aBody); err != nil || string(p) != "one" {
		t.Fatalf("first record: %q, %v", p, err)
	}
	if p, _, err := recv2.decrypt(bBody); err != nil || string(p) != "two" {
		t.Fatalf("second record: %q, %v", p, err)
	}
	_ = firstBody
}

// BenchmarkSealRecord measures the write path with a reused buffer. It should
// report zero allocations: the old encrypt path allocated the inner buffer, the
// Seal output and the record header buffer on every record.
func BenchmarkSealRecord(b *testing.B) {
	send, _ := newTestRecordPair(b)
	payload := bytes.Repeat([]byte("x"), 1400)

	var buf []byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record, err := send.sealRecord(buf, payload, recordTypeApplicationData)
		if err != nil {
			b.Fatal(err)
		}
		buf = record
	}
}

// BenchmarkDecryptRecord measures the read path, which opens in place.
//
// decrypt consumes its input buffer, so each iteration copies a pre-sealed
// record into a reusable scratch slice; that copy is allocation-free and does
// not disturb the reported allocs.
func BenchmarkDecryptRecord(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1400)
	const window = 256

	var send, recv *encryptedRecord
	records := make([][]byte, window)
	reseal := func() {
		send, recv = newTestRecordPair(b)
		for j := range records {
			r, err := send.sealRecord(nil, payload, recordTypeApplicationData)
			if err != nil {
				b.Fatal(err)
			}
			records[j] = append(records[j][:0], r[recordHeaderLen:]...)
		}
	}
	reseal()

	scratch := make([]byte, 0, len(records[0]))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % window
		if j == 0 && i > 0 {
			// The receiver's sequence has caught up with the window; reseal so
			// nonces stay in step.
			b.StopTimer()
			reseal()
			b.StartTimer()
		}
		scratch = append(scratch[:0], records[j]...)
		if _, _, err := recv.decrypt(scratch); err != nil {
			b.Fatal(err)
		}
	}
}
