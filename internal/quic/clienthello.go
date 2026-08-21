package quic

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Reading a ClientHello, and the two fingerprints computed from it.
//
// This parses rather than builds. Building is internal/ctls's job and stays
// there; what is needed here is the other direction — taking apart what a real
// Chrome put on the wire, so reference.go's values can be checked against it
// rather than asserted.

// ClientHello is the parsed content of a TLS 1.3 ClientHello.
type ClientHello struct {
	SNI        string
	ALPN       []string
	SessionID  int
	Ciphers    []uint16
	Extensions []uint16 // wire order, which Chrome permutes per connection
	ExtData    map[uint16][]byte
	Groups     []uint16
	KeyShares  []uint16
	SigAlgs    []uint16
	Versions   []uint16
}

// IsGREASE reports whether v is one of the sixteen GREASE values (RFC 8701):
// 0x0a0a, 0x1a1a, ... 0xfafa.
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// ParseClientHello reads a handshake stream that begins with a ClientHello.
func ParseClientHello(b []byte) (*ClientHello, error) {
	if len(b) < 4 || b[0] != 0x01 {
		return nil, errors.New("quic: handshake stream does not begin with a ClientHello")
	}
	l := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if 4+l > len(b) {
		return nil, fmt.Errorf("quic: ClientHello wants %d bytes, stream has %d", 4+l, len(b))
	}
	body := b[4 : 4+l]
	ch := &ClientHello{ExtData: map[uint16][]byte{}}

	i := 2 + 32 // legacy_version, random
	if i >= len(body) {
		return nil, errShort
	}
	ch.SessionID = int(body[i])
	i += 1 + ch.SessionID
	if i+2 > len(body) {
		return nil, errShort
	}

	csLen := int(binary.BigEndian.Uint16(body[i:]))
	i += 2
	if i+csLen > len(body) {
		return nil, errShort
	}
	for j := 0; j+1 < csLen; j += 2 {
		ch.Ciphers = append(ch.Ciphers, binary.BigEndian.Uint16(body[i+j:]))
	}
	i += csLen

	i += 1 + int(body[i]) // compression methods
	if i+2 > len(body) {
		return nil, errShort
	}
	end := i + 2 + int(binary.BigEndian.Uint16(body[i:]))
	i += 2
	if end > len(body) {
		return nil, errShort
	}

	list := func(d []byte, skip int) []uint16 {
		var out []uint16
		for j := skip; j+1 < len(d); j += 2 {
			out = append(out, binary.BigEndian.Uint16(d[j:]))
		}
		return out
	}

	for i+4 <= end {
		et := binary.BigEndian.Uint16(body[i:])
		el := int(binary.BigEndian.Uint16(body[i+2:]))
		i += 4
		if i+el > end {
			return nil, errShort
		}
		d := body[i : i+el]
		i += el
		ch.Extensions = append(ch.Extensions, et)
		ch.ExtData[et] = d

		switch et {
		case 0x0000: // server_name
			if len(d) >= 5 {
				ch.SNI = string(d[5:])
			}
		case 0x000a: // supported_groups
			ch.Groups = list(d, 2)
		case 0x000d: // signature_algorithms
			ch.SigAlgs = list(d, 2)
		case 0x0010: // alpn
			for p := d[min(2, len(d)):]; len(p) > 0 && 1+int(p[0]) <= len(p); p = p[1+int(p[0]):] {
				ch.ALPN = append(ch.ALPN, string(p[1:1+int(p[0])]))
			}
		case 0x002b: // supported_versions
			ch.Versions = list(d, 1)
		case 0x0033: // key_share
			for p := d[min(2, len(d)):]; len(p) >= 4; {
				ch.KeyShares = append(ch.KeyShares, binary.BigEndian.Uint16(p))
				n := int(binary.BigEndian.Uint16(p[2:]))
				if 4+n > len(p) {
					break
				}
				p = p[4+n:]
			}
		}
	}
	return ch, nil
}

// TransportParam is one entry of the quic_transport_parameters extension.
type TransportParam struct {
	ID    uint64
	Value []byte
}

// TransportParams reads extension 0x0039 in wire order.
//
// Order is not preserved anywhere else because Chrome shuffles it — see
// ReferenceQUIC — but it is returned as-read so a caller can see that it moved.
func (ch *ClientHello) TransportParams() ([]TransportParam, error) {
	b, ok := ch.ExtData[0x0039]
	if !ok {
		return nil, errors.New("quic: ClientHello carries no quic_transport_parameters")
	}
	var out []TransportParam
	for i := 0; i < len(b); {
		id, n, ok := ReadVarint(b[i:])
		if !ok {
			return out, errShort
		}
		i += n
		ln, n, ok := ReadVarint(b[i:])
		if !ok {
			return out, errShort
		}
		i += n
		if i+int(ln) > len(b) {
			return out, errShort
		}
		out = append(out, TransportParam{ID: id, Value: b[i : i+int(ln)]})
		i += int(ln)
	}
	return out, nil
}

// Uint returns a transport parameter's value read as a varint, which is how
// every one of the integer-valued parameters is encoded (RFC 9000 section 18.2).
func (p TransportParam) Uint() (uint64, bool) {
	v, n, ok := ReadVarint(p.Value)
	return v, ok && n == len(p.Value)
}

// IsGREASETransportParam reports whether id is one of the reserved values
// RFC 9000 section 18.1 sets aside to exercise a peer's unknown-parameter path:
// 31*N + 27.
func IsGREASETransportParam(id uint64) bool {
	return id >= 27 && (id-27)%31 == 0
}

// JA4 returns the hashed and unhashed JA4 for this ClientHello.
//
// The QUIC variant differs from the TLS-over-TCP one only in its first
// character: 'q' rather than 't'. Everything after that is the same
// computation, which is the point — it is what lets a scoring stack compare a
// client's h3 identity against its h2 one and notice they disagree.
func (ch *ClientHello) JA4() (ja4, ja4r string) {
	ver := "00"
	var best uint16
	for _, v := range ch.Versions {
		if !IsGREASE(v) && v > best {
			best = v
		}
	}
	switch best {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	}
	sni := "i"
	if ch.SNI != "" {
		sni = "d"
	}

	var ciphers, exts, sigs []string
	for _, c := range ch.Ciphers {
		if !IsGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", c))
		}
	}
	extCount := 0
	for _, e := range ch.Extensions {
		if IsGREASE(e) {
			continue
		}
		extCount++
		// server_name and alpn are counted in the a-part and then left out of
		// the hashed list, because both are already described by it.
		if e != 0x0000 && e != 0x0010 {
			exts = append(exts, fmt.Sprintf("%04x", e))
		}
	}
	for _, s := range ch.SigAlgs {
		if !IsGREASE(s) {
			sigs = append(sigs, fmt.Sprintf("%04x", s))
		}
	}

	alpn := "00"
	if len(ch.ALPN) > 0 {
		a := ch.ALPN[0]
		alpn = string(a[0]) + string(a[len(a)-1])
	}

	sort.Strings(ciphers)
	sort.Strings(exts)

	a := fmt.Sprintf("q%s%s%02d%02d%s", ver, sni, len(ciphers), extCount, alpn)
	cPart := strings.Join(exts, ",")
	if len(sigs) > 0 {
		cPart += "_" + strings.Join(sigs, ",")
	}

	h12 := func(s string) string {
		if s == "" {
			return "000000000000"
		}
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])[:12]
	}
	return a + "_" + h12(strings.Join(ciphers, ",")) + "_" + h12(cPart),
		a + "_" + strings.Join(ciphers, ",") + "_" + cPart
}
