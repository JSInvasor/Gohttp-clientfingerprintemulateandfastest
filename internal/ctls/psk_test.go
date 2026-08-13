package ctls

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"testing"
	"time"
)

// testdata/resumed-clienthello.txt: Chrome's resumed ClientHello carries exactly
// one extension more than its fresh one, and pre_shared_key is the last of them
// — after even the trailing GREASE, which is otherwise always final. RFC 8446
// §4.2.11 requires the position; the capture is what says Chrome obeys it
// rather than reordering something else to compensate.
func TestPSKIsTheLastExtension(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	offer := &pskOffer{
		ticket: &sessionTicket{
			psk:      bytes.Repeat([]byte{7}, 32),
			identity: bytes.Repeat([]byte{9}, 64),
			suite:    cipherTLS_AES_128_GCM_SHA256,
		},
		age: 12345,
	}

	// Extension order is shuffled per hello, so this has to hold every time.
	for i := 0; i < 200; i++ {
		msg, err := buildChromeClientHello("example.com", []string{"h2"}, km, offer)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		ch, err := parseClientHello(msg)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(ch.extTypes) == 0 {
			t.Fatal("no extensions")
		}
		if last := ch.extTypes[len(ch.extTypes)-1]; last != extPreSharedKey {
			t.Fatalf("last extension is 0x%04x, want pre_shared_key", last)
		}
	}
}

// The fresh hello must be untouched: offering no PSK has to leave the shape
// this package was verified against exactly as it was.
func TestNoPSKLeavesTheHelloAlone(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	withOffer, err := buildChromeClientHello("example.com", []string{"h2"}, km, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ch, err := parseClientHello(withOffer)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, e := range ch.extTypes {
		if e == extPreSharedKey {
			t.Fatal("a hello built without an offer carried pre_shared_key")
		}
	}
}

// One extension more, and no other change to the count.
func TestPSKAddsExactlyOneExtension(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	fresh, err := buildChromeClientHello("example.com", []string{"h2"}, km, nil)
	if err != nil {
		t.Fatalf("build fresh: %v", err)
	}
	offer := &pskOffer{ticket: &sessionTicket{
		psk:      bytes.Repeat([]byte{1}, 32),
		identity: bytes.Repeat([]byte{2}, 48),
		suite:    cipherTLS_AES_128_GCM_SHA256,
	}}
	resumed, err := buildChromeClientHello("example.com", []string{"h2"}, km, offer)
	if err != nil {
		t.Fatalf("build resumed: %v", err)
	}

	f, _ := parseClientHello(fresh)
	r, _ := parseClientHello(resumed)
	if len(r.extTypes) != len(f.extTypes)+1 {
		t.Errorf("resumed hello has %d extensions, fresh has %d — want exactly one more",
			len(r.extTypes), len(f.extTypes))
	}
}

// The binder is an HMAC over the hello truncated immediately before the binder
// itself. If the truncation point moves, every resumption is refused — so this
// pins where it is rather than trusting the arithmetic.
func TestBinderCoversTheTruncatedHello(t *testing.T) {
	psk := bytes.Repeat([]byte{0x5A}, 32)
	identity := bytes.Repeat([]byte{0xC3}, 32)
	h := hashForCipher(cipherTLS_AES_128_GCM_SHA256)
	hl := h().Size()

	ext := buildPSKExtension(identity, 999, hl)
	if got := len(ext); got != pskExtensionLen(len(identity), hl) {
		t.Fatalf("extension is %d bytes, pskExtensionLen says %d", got, pskExtensionLen(len(identity), hl))
	}
	// Built with a zero binder, because it cannot be computed yet.
	if !bytes.Equal(ext[len(ext)-hl:], make([]byte, hl)) {
		t.Error("binder placeholder is not zero")
	}

	msg := append([]byte{handshakeTypeClientHello, 0, 0, 0}, ext...)
	binary.BigEndian.PutUint16(msg[2:], uint16(len(ext)))
	finishBinder(msg, h, psk)

	binder := msg[len(msg)-hl:]
	if bytes.Equal(binder, make([]byte, hl)) {
		t.Fatal("binder was not filled in")
	}

	// Recompute independently: HMAC(finished_key, Hash(msg without the binders)).
	truncated := msg[:len(msg)-(2+1+hl)]
	th := h()
	th.Write(truncated)
	want := hmacSum(h, binderFinishedKey(h, psk), th.Sum(nil))
	if !bytes.Equal(binder, want) {
		t.Error("binder does not cover the hello truncated before the binders list")
	}
}

func TestParseSelectedIdentity(t *testing.T) {
	psk := func(idx uint16) []byte {
		b := binary.BigEndian.AppendUint16(nil, extPreSharedKey)
		b = binary.BigEndian.AppendUint16(b, 2)
		return binary.BigEndian.AppendUint16(b, idx)
	}

	// Declining is silence, not an error.
	if ok, err := parseSelectedIdentity(nil); ok || err != nil {
		t.Errorf("empty extensions -> %v, %v; want declined and no error", ok, err)
	}
	if ok, err := parseSelectedIdentity(psk(0)); !ok || err != nil {
		t.Errorf("identity 0 -> %v, %v; want accepted", ok, err)
	}
	// Only one identity is ever offered, so anything else names an offer that
	// was never made.
	if _, err := parseSelectedIdentity(psk(1)); err == nil {
		t.Error("a server selecting identity 1 was accepted")
	}
}

func TestPSKOfferTakesFromTheCache(t *testing.T) {
	cache := NewSessionCache(4)
	now := time.Now()
	cache.put("site.test", &sessionTicket{
		psk: []byte{1}, identity: []byte{2}, received: now,
		lifetime: time.Hour, suite: cipherTLS_AES_128_GCM_SHA256,
	})

	if got := newPSKOffer(nil, "site.test", resumableSuites, now); got != nil {
		t.Error("a nil cache produced an offer")
	}
	offer := newPSKOffer(cache, "site.test", resumableSuites, now)
	if offer == nil {
		t.Fatal("no offer from a cache holding a live ticket")
	}
	// Single use: the second call must find nothing.
	if again := newPSKOffer(cache, "site.test", resumableSuites, now); again != nil {
		t.Error("the same ticket was offered twice")
	}
}

// hmacSum is the independent recomputation the binder test compares against.
func hmacSum(h func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(h, key)
	m.Write(data)
	return m.Sum(nil)
}
