package ctls

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

// Certificate compression is on the path of every connection to an edge that
// offers it, and Cloudflare does — the ClientHello advertises zlib for Safari
// and brotli for Chrome, so a live handshake takes this branch rather than the
// plain Certificate one. Nothing exercised it.
//
// What is under test is both halves: that a well-formed compressed certificate
// parses back to the chain that went in, and that the malformed ones are
// refused rather than trusted. The length fields here are attacker-controlled —
// they arrive before any signature has been checked — so the bounds are a
// security property, not a formatting one.

// compressTestCert builds a self-signed certificate to carry through the compressors.
func compressTestCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "compressed.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

// certificateMessage assembles a TLS 1.3 Certificate body around one DER cert:
// context(1) + cert_list_len(3) + [ cert_len(3) + der + ext_len(2) ].
func certificateMessage(der []byte) []byte {
	entry := make([]byte, 0, 3+len(der)+2)
	entry = append(entry, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
	entry = append(entry, der...)
	entry = append(entry, 0, 0) // no extensions

	out := make([]byte, 0, 4+len(entry))
	out = append(out, 0) // empty certificate_request_context
	out = append(out, byte(len(entry)>>16), byte(len(entry)>>8), byte(len(entry)))
	return append(out, entry...)
}

// compressedCertificate wraps compressed bytes in the RFC 8879 header:
// algorithm(2) + uncompressed_length(3) + compressed_length(3) + data.
func compressedCertificate(algorithm uint16, uncompressedLen int, compressed []byte) []byte {
	out := make([]byte, 8, 8+len(compressed))
	binary.BigEndian.PutUint16(out[0:], algorithm)
	out[2], out[3], out[4] = byte(uncompressedLen>>16), byte(uncompressedLen>>8), byte(uncompressedLen)
	out[5], out[6], out[7] = byte(len(compressed)>>16), byte(len(compressed)>>8), byte(len(compressed))
	return append(out, compressed...)
}

func zlibBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func brotliBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

// The two algorithms the ClientHello actually offers have to round-trip.
func TestCompressedCertificateRoundTrips(t *testing.T) {
	der := compressTestCert(t)
	raw := certificateMessage(der)

	for _, tc := range []struct {
		name string
		algo uint16
		comp []byte
	}{
		{"zlib (Safari offers this)", certCompressionZlib, zlibBytes(t, raw)},
		{"brotli (Chrome offers this)", certCompressionBrotli, brotliBytes(t, raw)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := parseCompressedCertificate(compressedCertificate(tc.algo, len(raw), tc.comp))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(certs) != 1 {
				t.Fatalf("got %d certificates, want 1", len(certs))
			}
			if certs[0].Subject.CommonName != "compressed.example" {
				t.Errorf("common name = %q, want the certificate that went in", certs[0].Subject.CommonName)
			}
			if !bytes.Equal(certs[0].Raw, der) {
				t.Error("the DER that came back is not the DER that went in")
			}
		})
	}
}

// Every one of these arrives before a signature has been checked, so refusing
// them is the only thing standing between a hostile peer and the parser.
func TestCompressedCertificateRejectsMalformed(t *testing.T) {
	der := compressTestCert(t)
	raw := certificateMessage(der)
	good := zlibBytes(t, raw)

	// A declared size past the 256 KiB ceiling. The check has to happen before
	// anything is allocated against it — that is what it is for.
	bomb := make([]byte, 4*1024*1024)
	bombCompressed := zlibBytes(t, bomb)

	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "zstd is advertised by neither profile",
			body: compressedCertificate(certCompressionZstd, len(raw), good),
			want: "zstd",
		},
		{
			name: "an algorithm nobody offered",
			body: compressedCertificate(0x00ff, len(raw), good),
			want: "unknown compression algorithm",
		},
		{
			name: "header shorter than the fixed 8 bytes",
			body: []byte{0x00, 0x02, 0x00},
			want: "too short",
		},
		{
			name: "compressed_length points past the end of the message",
			body: compressedCertificate(certCompressionZlib, len(raw), good)[:12],
			want: "truncated",
		},
		{
			name: "declared size above the handshake ceiling",
			body: compressedCertificate(certCompressionZlib, len(bomb), bombCompressed),
			want: "exceeds",
		},
		{
			name: "declared size disagrees with what came out",
			body: compressedCertificate(certCompressionZlib, len(raw)+1, good),
			want: "header declared",
		},
		{
			name: "compressed data is not the algorithm it claims",
			body: compressedCertificate(certCompressionZlib, len(raw), []byte("not zlib at all")),
			want: "decompress",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := parseCompressedCertificate(tc.body)
			if err == nil {
				t.Fatalf("accepted a malformed compressed certificate, returning %d certs", len(certs))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the problem (want it to mention %q)", err, tc.want)
			}
		})
	}
}

// A compression bomb must not be decompressed past the ceiling even when the
// declared length is honest about being small. The limit reader is what bounds
// it; without one, a few hundred bytes on the wire expands to whatever the peer
// chose.
func TestCompressedCertificateBoundsTheExpansion(t *testing.T) {
	// 8 MiB of zeroes compresses to a few KiB.
	bomb := make([]byte, 8*1024*1024)
	body := compressedCertificate(certCompressionZlib, 64, zlibBytes(t, bomb))

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := parseCompressedCertificate(body); err == nil {
			t.Error("a bomb declaring 64 bytes and expanding to 8 MiB was accepted")
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("parse did not return: the expansion is not bounded")
	}
}
