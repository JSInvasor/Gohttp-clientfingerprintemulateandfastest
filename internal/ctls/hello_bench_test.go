package ctls

import "testing"

// What a connection costs before its first byte, and why the builder is not
// where to look for it.
//
// The ClientHello is assembled once per connection — for a -no-keepalive run,
// once per request — so it is a fair question whether its allocations matter.
// Measured on a 4-core box, they do not:
//
//	BuildChromeHello       8.0 us    12068 B    71 allocs
//	GenerateKeyMaterial   97.8 us    10256 B    19 allocs
//
// The X25519 and ML-KEM-768 key generation that accompanies every hello is
// twelve times the cost of building one, so the builder is 8% of the thing it
// sits inside. That is the opposite of the header encoder in internal/http2,
// which was worth rewriting: that ran once per *request* and held the
// connection's write lock while it did. This runs once per connection, beside
// something far larger. Left alone deliberately.
func BenchmarkBuildChromeHello(b *testing.B) {
	km, err := generateKeyMaterial()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := buildChromeClientHello("site.example", []string{"h2", "http/1.1"}, km, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateKeyMaterial(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := generateKeyMaterial(); err != nil {
			b.Fatal(err)
		}
	}
}
