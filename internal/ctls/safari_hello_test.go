package ctls

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Reference values captured from a real iPhone 13 running iOS 26.5.2
// (Safari 26.5.2) against tls.peet.ws.
//
// These are the whole point of the profile: if a change shifts any of them the
// client stops looking like Safari and starts looking like a unique, trackable
// client. Two past regressions would have been caught here — a padding
// extension that pushed JA4_a from 2013 to 2014, and a "deduplication" of the
// repeated 0x0805 signature algorithm that changed JA4_c.
const (
	realSafariJA3 = "771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10," +
		"0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0"
	realSafariJA3Hash = "ecdf4f49dd59effc439639da29186671"
	realSafariJA4     = "t13d2013h2_a09f3c656075_7f0f34a4126d"
)

func TestSafariClientHelloMatchesRealDevice(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	raw, err := buildSafariClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km)
	if err != nil {
		t.Fatalf("buildSafariClientHello: %v", err)
	}

	ch, err := parseClientHello(raw)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}

	if got := ch.ja3(); got != realSafariJA3 {
		t.Errorf("JA3 mismatch\n got: %s\nwant: %s", got, realSafariJA3)
	}
	if got := ch.ja3Hash(); got != realSafariJA3Hash {
		t.Errorf("JA3 hash = %s, want %s", got, realSafariJA3Hash)
	}
	if got := ch.ja4(); got != realSafariJA4 {
		t.Errorf("JA4 mismatch\n got: %s\nwant: %s", got, realSafariJA4)
	}
}

// TestSafariClientHelloStableAcrossConnections guards the other half of the
// contract: Apple does not permute extensions, so every Safari ClientHello must
// hash identically. (Chrome is the opposite — see chrome_hello_test.go.)
func TestSafariClientHelloStableAcrossConnections(t *testing.T) {
	var first string
	for i := 0; i < 16; i++ {
		km, err := generateKeyMaterial()
		if err != nil {
			t.Fatalf("generateKeyMaterial: %v", err)
		}
		raw, err := buildSafariClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km)
		if err != nil {
			t.Fatalf("buildSafariClientHello: %v", err)
		}
		ch, err := parseClientHello(raw)
		if err != nil {
			t.Fatalf("parseClientHello: %v", err)
		}
		got := ch.ja3Hash()
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("JA3 hash changed between connections: %s then %s "+
				"(Safari must not permute its ClientHello)", first, got)
		}
	}
}

// TestSafariSigAlgsKeepDuplicate states the invariant explicitly so a future
// "cleanup" of the list fails with a message explaining why.
func TestSafariSigAlgsKeepDuplicate(t *testing.T) {
	if len(safariIOS18SigAlgs) != 10 {
		t.Fatalf("got %d signature algorithms, want 10", len(safariIOS18SigAlgs))
	}
	var n int
	for _, a := range safariIOS18SigAlgs {
		if a == 0x0805 {
			n++
		}
	}
	if n != 2 {
		t.Errorf("rsa_pss_rsae_sha384 (0x0805) appears %d time(s), want 2 — "+
			"a real device repeats it and removing it breaks JA4_c", n)
	}
}

// TestSafariSendsNoPadding pins the absence of extension 0x0015.
func TestSafariSendsNoPadding(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	raw, err := buildSafariClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km)
	if err != nil {
		t.Fatalf("buildSafariClientHello: %v", err)
	}
	ch, err := parseClientHello(raw)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	for _, e := range ch.extTypes {
		if e == 0x0015 {
			t.Error("padding extension (0x0015) present; a real device sends none " +
				"once key_share carries the 1216-byte X25519MLKEM768 entry")
		}
	}
}

// TestSafariKeyShareCarriesMLKEM checks the post-quantum entry is well-formed:
// GREASE, then X25519MLKEM768 (1184-byte ML-KEM public key || 32-byte X25519),
// then bare X25519.
func TestSafariKeyShareCarriesMLKEM(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	data := buildSafariKeyShare(km, newGreaseSet())

	if len(data) < 2 {
		t.Fatal("key_share too short")
	}
	if int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		t.Fatalf("key_share inner length %d does not match payload %d",
			binary.BigEndian.Uint16(data), len(data)-2)
	}

	type entry struct {
		group uint16
		size  int
	}
	var got []entry
	for off := 2; off+4 <= len(data); {
		group := binary.BigEndian.Uint16(data[off:])
		size := int(binary.BigEndian.Uint16(data[off+2:]))
		off += 4 + size
		if off > len(data) {
			t.Fatalf("key_share entry for group 0x%04x overruns buffer", group)
		}
		got = append(got, entry{group, size})
	}

	if len(got) != 3 {
		t.Fatalf("got %d key_share entries, want 3 (GREASE, X25519MLKEM768, X25519)", len(got))
	}
	if !isGreaseValue(got[0].group) {
		t.Errorf("entry 0 group = 0x%04x, want a GREASE value", got[0].group)
	}
	if got[1].group != groupX25519MLKEM768 {
		t.Errorf("entry 1 group = 0x%04x, want X25519MLKEM768 (0x%04x)", got[1].group, groupX25519MLKEM768)
	}
	if want := mlkem768PubKeySize + 32; got[1].size != want {
		t.Errorf("X25519MLKEM768 share = %d bytes, want %d", got[1].size, want)
	}
	if got[2].group != groupX25519 {
		t.Errorf("entry 2 group = 0x%04x, want X25519 (0x%04x)", got[2].group, groupX25519)
	}
	if got[2].size != 32 {
		t.Errorf("X25519 share = %d bytes, want 32", got[2].size)
	}
}

// ---------- minimal ClientHello parser + JA3/JA4 for tests ----------

type parsedHello struct {
	legacyVersion uint16
	ciphers       []uint16
	extTypes      []uint16
	groups        []uint16
	ecPointFmts   []byte
	sigAlgs       []uint16
	supportedVers []uint16
	alpn          []string
	hasSNI        bool
}

func parseClientHello(msg []byte) (*parsedHello, error) {
	if len(msg) < 4 || msg[0] != handshakeTypeClientHello {
		return nil, fmt.Errorf("not a ClientHello")
	}
	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	b := msg[4:]
	if len(b) != bodyLen {
		return nil, fmt.Errorf("body length %d does not match header %d", len(b), bodyLen)
	}

	h := &parsedHello{}
	p := 0
	need := func(n int) error {
		if p+n > len(b) {
			return fmt.Errorf("truncated at offset %d", p)
		}
		return nil
	}

	if err := need(2 + 32 + 1); err != nil {
		return nil, err
	}
	h.legacyVersion = binary.BigEndian.Uint16(b[p:])
	p += 2 + 32
	sidLen := int(b[p])
	p++
	if err := need(sidLen + 2); err != nil {
		return nil, err
	}
	p += sidLen

	csLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if err := need(csLen); err != nil {
		return nil, err
	}
	for i := 0; i+1 < csLen; i += 2 {
		h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(b[p+i:]))
	}
	p += csLen

	if err := need(1); err != nil {
		return nil, err
	}
	compLen := int(b[p])
	p++
	if err := need(compLen + 2); err != nil {
		return nil, err
	}
	p += compLen

	extTotal := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if err := need(extTotal); err != nil {
		return nil, err
	}
	end := p + extTotal
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(b[p:])
		dLen := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+dLen > end {
			return nil, fmt.Errorf("extension 0x%04x overruns", typ)
		}
		data := b[p : p+dLen]
		p += dLen
		h.extTypes = append(h.extTypes, typ)

		switch typ {
		case extServerName:
			h.hasSNI = true
		case extSupportedGroups:
			if len(data) >= 2 {
				for i := 2; i+1 < len(data); i += 2 {
					h.groups = append(h.groups, binary.BigEndian.Uint16(data[i:]))
				}
			}
		case extECPointFormats:
			if len(data) >= 1 {
				h.ecPointFmts = append(h.ecPointFmts, data[1:]...)
			}
		case extSignatureAlgorithms:
			if len(data) >= 2 {
				for i := 2; i+1 < len(data); i += 2 {
					h.sigAlgs = append(h.sigAlgs, binary.BigEndian.Uint16(data[i:]))
				}
			}
		case extSupportedVersions:
			if len(data) >= 1 {
				for i := 1; i+1 < len(data); i += 2 {
					h.supportedVers = append(h.supportedVers, binary.BigEndian.Uint16(data[i:]))
				}
			}
		case extALPN:
			for i := 2; i < len(data); {
				n := int(data[i])
				if i+1+n > len(data) {
					break
				}
				h.alpn = append(h.alpn, string(data[i+1:i+1+n]))
				i += 1 + n
			}
		}
	}
	return h, nil
}

func isGreaseValue(v uint16) bool {
	for _, g := range greaseValues {
		if v == g {
			return true
		}
	}
	return false
}

func dropGrease(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGreaseValue(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinDec(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func joinHexSorted(vals []uint16) string {
	cp := append([]uint16(nil), vals...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	parts := make([]string, len(cp))
	for i, v := range cp {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func joinHex(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// ja3 renders the JA3 string: version,ciphers,extensions,groups,ec_point_formats
// with GREASE values removed and everything in wire order.
func (h *parsedHello) ja3() string {
	pf := make([]string, len(h.ecPointFmts))
	for i, b := range h.ecPointFmts {
		pf[i] = fmt.Sprintf("%d", b)
	}
	return strings.Join([]string{
		fmt.Sprintf("%d", h.legacyVersion),
		joinDec(dropGrease(h.ciphers)),
		joinDec(dropGrease(h.extTypes)),
		joinDec(dropGrease(h.groups)),
		strings.Join(pf, "-"),
	}, ",")
}

func (h *parsedHello) ja3Hash() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(h.ja3())))
}

// ja4 renders the JA4 string per the FoxIO spec: the a-part counts non-GREASE
// ciphers and extensions (SNI and ALPN are counted here but excluded from the
// c-part hash), the b-part hashes sorted ciphers, and the c-part hashes sorted
// extensions plus the signature algorithms in wire order.
func (h *parsedHello) ja4() string {
	ciphers := dropGrease(h.ciphers)
	exts := dropGrease(h.extTypes)

	var maxVer uint16
	for _, v := range dropGrease(h.supportedVers) {
		if v > maxVer {
			maxVer = v
		}
	}
	ver := "12"
	switch maxVer {
	case versionTLS13:
		ver = "13"
	case versionTLS12:
		ver = "12"
	}

	sni := "i"
	if h.hasSNI {
		sni = "d"
	}

	alpn := "00"
	if len(h.alpn) > 0 {
		first := h.alpn[0]
		if len(first) >= 2 {
			alpn = first[:1] + first[len(first)-1:]
		}
	}

	hashed := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e == extServerName || e == extALPN {
			continue
		}
		hashed = append(hashed, e)
	}

	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, len(ciphers), len(exts), alpn)
	b := trunc12(joinHexSorted(ciphers))
	c := trunc12(joinHexSorted(hashed) + "_" + joinHex(h.sigAlgs))
	return a + "_" + b + "_" + c
}

func trunc12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)[:12]
}
