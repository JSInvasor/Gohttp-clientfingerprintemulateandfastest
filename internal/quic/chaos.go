package quic

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// The chaos protector.
//
// Chrome does not put its ClientHello in one CRYPTO frame. Google's QUIC stack
// cuts the first flight into randomly sized pieces, emits them out of order,
// and scatters PING and PADDING frames between them, so that a DPI box watching
// the only unencrypted packet of a connection has no stable byte pattern to
// match. The three captures under testdata show it plainly: 1767 bytes of
// ClientHello arriving as 18 fragments between 1 and 824 bytes long, with 14
// PINGs and 7 separate runs of padding, spread across two datagrams.
//
// This reproduces those observable properties. It does not reproduce Google's
// algorithm, and that distinction is worth keeping straight: the point of the
// randomisation is that there is nothing to match, so matching it exactly would
// be neither possible from three samples nor useful if it were. What has to
// hold is the shape — many fragments of widely varying size, out of order,
// interleaved with PINGs and padding — because the shape is what separates this
// from the one tidy CRYPTO frame a straightforward implementation emits.
//
// The inverse of this is Assemble in initial.go, and the round trip is what the
// tests check: a flight built here, decoded by the same reader used on Chrome's
// own datagrams, has to yield back the ClientHello it started from.

// chaosParams bounds the randomisation. The ranges come from the captures
// rather than from taste; where a capture gives one number, the range is opened
// around it so that this client does not become recognisable by always sitting
// exactly where Chrome happened to sit on the day it was recorded.
type chaosParams struct {
	minFragments int
	maxFragments int
	minPings     int
	maxPings     int
	// padChance is the reciprocal of the probability that a run of padding is
	// inserted before any given frame: 4 means one time in four.
	padChance int
	maxPadRun int
}

var defaultChaos = chaosParams{
	minFragments: 8, // the captures show 9, 14, 15 and 18
	maxFragments: 20,
	minPings:     3, // 3, 7, 14 and 17 observed
	maxPings:     18,
	padChance:    4,
	maxPadRun:    48,
}

// ChaosProtect turns a handshake stream into the frame payloads of a flight of
// Initial packets, each exactly payloadSize bytes.
//
// Every returned payload is full: QUIC requires a datagram carrying an Initial
// to be padded, and Chrome pads to a fixed size rather than to the minimum, so
// there is no such thing as a short one here.
func ChaosProtect(crypto []byte, payloadSize int) ([][]byte, error) {
	return chaosProtect(crypto, payloadSize, defaultChaos)
}

// The three functions below exist so that a packet builder which is not this
// one can produce the same shape.
//
// internal/quicgo owns packet numbers, loss recovery and coalescing, so it
// cannot hand its first flight to ChaosProtect and take datagrams back — a
// CRYPTO frame it did not create is a frame it cannot retransmit. What it needs
// instead are the three decisions this file makes: where to cut, how many PINGs
// to scatter, and how to break up the padding. Exporting them keeps one copy of
// a distribution that took four corrections to get right, and keeps the tests
// that measure it pointed at the code both callers run.

// Fragment is one slice of the handshake stream: where it starts, and how long
// it is.
//
// Nothing here holds the bytes. A fragment's offset travels with it in the
// CRYPTO frame, which is what lets the pieces be sent in any order, and it is
// also what lets a caller with its own copy of the handshake slice it without
// this package having one.
type Fragment struct {
	Offset uint64
	Length int
}

// SplitHandshake cuts a handshake stream of n bytes into the shuffled fragments
// Chrome's chaos protector emits, none of them longer than maxFragment.
//
// The order is the order to send in. See splitCrypto for why the cuts are made
// the way they are, and what the two obvious alternatives got wrong.
func SplitHandshake(n, maxFragment int) ([]Fragment, error) {
	frags, err := splitCrypto(n, defaultChaos, maxFragment)
	if err != nil {
		return nil, err
	}
	if err := shuffle(len(frags), func(i, j int) { frags[i], frags[j] = frags[j], frags[i] }); err != nil {
		return nil, err
	}
	return frags, nil
}

// ChaosPings returns how many PING frames belong in one Initial packet.
//
// The captures count PINGs per flight — 3, 7, 14 and 17 across two datagrams —
// and chaosProtect draws once against those bounds because it builds a whole
// flight at a time. A packer that emits one datagram at a time cannot know how
// many are still to come, so this halves the range and draws per packet, which
// puts a two-packet flight back where the captures are.
func ChaosPings() (int, error) {
	lo := defaultChaos.minPings / 2
	if lo < 1 {
		lo = 1
	}
	return randInt(lo, defaultChaos.maxPings/2)
}

// ChaosPadRuns splits total bytes of padding into gaps runs.
//
// Run i goes before frame i, and the last one is the tail of the packet, which
// is why a caller passes one more gap than it has frames. Interior runs are
// short and sparse, matching the captures — one gap in four carries padding, of
// at most a few dozen bytes — and whatever is left over lands in the tail,
// because a flight's last Initial is mostly padding however it is arranged.
//
// The runs are what makes several PADDING stretches per packet rather than one
// at the end, which is what Chrome's packets show and what ParseFrames counts.
func ChaosPadRuns(total, gaps int) ([]int, error) {
	return chaosPadRuns(total, gaps, defaultChaos)
}

func chaosPadRuns(total, gaps int, p chaosParams) ([]int, error) {
	if gaps <= 0 {
		return nil, fmt.Errorf("quic: %d gaps to pad", gaps)
	}
	out := make([]int, gaps)
	if total <= 0 {
		return out, nil
	}
	left := total
	for i := 0; i < gaps-1 && left > 0; i++ {
		pick, err := randInt(0, p.padChance-1)
		if err != nil {
			return nil, err
		}
		if pick != 0 {
			continue
		}
		hi := p.maxPadRun
		if hi > left {
			hi = left
		}
		run, err := randInt(1, hi)
		if err != nil {
			return nil, err
		}
		out[i] = run
		left -= run
	}
	out[gaps-1] = left
	return out, nil
}

func chaosProtect(crypto []byte, payloadSize int, p chaosParams) ([][]byte, error) {
	if len(crypto) == 0 {
		return nil, errors.New("quic: nothing to protect")
	}
	// A fragment needs to fit, framing included, in an empty payload — that is
	// the only thing the packer requires, since a frame that will not fit in the
	// current datagram opens a new one. Twenty-four bytes of headroom covers the
	// frame type and two varints with room to spare.
	//
	// An earlier revision capped at half the payload instead, on the vague
	// grounds that it would pack better. Measuring showed what that cost: the
	// cap bound on most flights, so the largest fragment came out at exactly the
	// cap over and over. A fragment size that repeats to the byte across
	// connections is precisely the kind of constant this file exists to avoid,
	// and it was invisible until the distribution was printed rather than
	// reasoned about.
	maxFragment := payloadSize - 24
	if maxFragment < 1 {
		return nil, fmt.Errorf("quic: payload size %d is too small to fragment", payloadSize)
	}

	frags, err := splitCrypto(len(crypto), p, maxFragment)
	if err != nil {
		return nil, err
	}

	// Each fragment becomes an encoded CRYPTO frame; the PINGs join them, and
	// then the whole lot is shuffled. Shuffling after encoding is what puts the
	// fragments out of order on the wire: their stream offsets travel with them,
	// so the receiver reassembles regardless.
	frames := make([][]byte, 0, len(frags)+p.maxPings)
	for _, f := range frags {
		frames = append(frames, encodeCrypto(f.Offset, crypto[f.Offset:f.Offset+uint64(f.Length)]))
	}
	pings, err := randInt(p.minPings, p.maxPings)
	if err != nil {
		return nil, err
	}
	for i := 0; i < pings; i++ {
		frames = append(frames, []byte{0x01}) // PING
	}
	if err := shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] }); err != nil {
		return nil, err
	}

	return pack(frames, payloadSize, p)
}

// splitCrypto cuts a stream of n bytes by repeatedly splitting a piece it
// already has.
//
// It takes a length rather than the bytes because it never looks at them: what
// comes back is offsets and lengths, which the caller uses against its own copy.
//
// The obvious implementation — draw N cut points uniformly across the stream
// and sort them — was written first and was wrong, and the test that caught it
// is worth keeping in mind: uniform cuts on a 1767-byte hello give fragments
// spanning roughly 60 to 450 bytes, while Chrome's captures span 1 to 824. The
// difference is not noise. Uniform order statistics cluster; what Chrome
// produces is heavily skewed, with a cluster of one- and two-byte fragments at
// the front and a single piece carrying hundreds.
//
// Splitting recursively reproduces that. Start with one fragment covering the
// whole stream and, N times over, pick a fragment at random and cut it at a
// random interior point. Because the pick is uniform over fragments rather than
// over bytes, a large piece is no likelier to be chosen than a one-byte one, so
// large pieces survive while the ones already small get cut again — which is
// the shape the captures show.
func splitCrypto(streamLen int, p chaosParams, maxFragment int) ([]Fragment, error) {
	n, err := randInt(p.minFragments, p.maxFragments)
	if err != nil {
		return nil, err
	}
	if n > streamLen {
		n = streamLen
	}

	out := []Fragment{{Offset: 0, Length: streamLen}}
	// Bound the attempts: once most fragments are a single byte there may be
	// nothing left to split, and looping forever waiting for a splittable pick
	// would hang rather than fail.
	for attempts := 0; len(out) < n && attempts < n*8; attempts++ {
		i, err := randInt(0, len(out)-1)
		if err != nil {
			return nil, err
		}
		if out[i].Length < 2 {
			continue
		}
		// The cut point is drawn log-uniformly rather than uniformly, and that
		// is a second correction the captures forced. A uniform cut leaves a
		// smallest fragment in the tens of bytes; Chrome's flights carry one-
		// and two-byte fragments clustered at low offsets — 0(1), 1(9), 10(5),
		// 15(1), 16(2) in the first capture — alongside one piece of several
		// hundred. Uniform cuts cannot produce both, and neither can a mild
		// bias: measured over a thousand flights, the ratio between the largest
		// and smallest fragment stayed near 8 where Chrome's captures range from
		// 113 to 824.
		//
		// Drawing the octave first and the value inside it second gives every
		// power-of-two band equal weight, so single-digit cuts are as likely as
		// three-digit ones and the large remainder survives.
		at, err := cutPoint(out[i].Length)
		if err != nil {
			return nil, err
		}
		left := Fragment{Offset: out[i].Offset, Length: at}
		right := Fragment{Offset: out[i].Offset + uint64(at), Length: out[i].Length - at}
		out[i] = left
		out = append(out, right)
	}

	// Nothing may exceed the cap, so the packer can always place a frame whole
	// in a fresh datagram. A stream long enough to need this has usually been
	// cut below it already; this is the guarantee, not the common path.
	// Anything over the cap is chopped at a RANDOM size below it, not at the cap
	// itself. Chopping at the cap was the first version and it reintroduced the
	// constant this whole function is trying to avoid: whenever the cap bound,
	// the largest fragment came out at exactly maxFragment, so a value that
	// repeats byte for byte across connections appeared in perhaps one flight in
	// a hundred — rare enough to survive a green test run and just as usable to
	// anyone collecting samples.
	var capped []Fragment
	for _, f := range out {
		for f.Length > maxFragment {
			n, err := randInt(maxFragment/2, maxFragment)
			if err != nil {
				return nil, err
			}
			capped = append(capped, Fragment{Offset: f.Offset, Length: n})
			f.Offset += uint64(n)
			f.Length -= n
		}
		capped = append(capped, f)
	}
	return capped, nil
}

// encodeCrypto builds a CRYPTO frame (RFC 9000 section 19.6).
func encodeCrypto(offset uint64, data []byte) []byte {
	b := make([]byte, 0, 9+len(data))
	b = append(b, 0x06)
	b = appendVarint(b, offset)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// pack lays the frames into fixed-size payloads, inserting runs of padding
// between them.
//
// Padding is written as explicit runs rather than left to the tail because the
// captures show several separate runs per packet, not one at the end. A frame
// that will not fit closes the current payload, and since no frame exceeds half
// a payload, the next one always has room.
func pack(frames [][]byte, payloadSize int, p chaosParams) ([][]byte, error) {
	var out [][]byte
	cur := make([]byte, 0, payloadSize)

	flush := func() {
		// The remainder is PADDING, which is a run of zero bytes.
		cur = append(cur, make([]byte, payloadSize-len(cur))...)
		out = append(out, cur)
		cur = make([]byte, 0, payloadSize)
	}

	for _, f := range frames {
		pad, err := randInt(0, p.padChance-1)
		if err != nil {
			return nil, err
		}
		if pad == 0 {
			run, err := randInt(1, p.maxPadRun)
			if err != nil {
				return nil, err
			}
			if len(cur)+run+len(f) <= payloadSize {
				cur = append(cur, make([]byte, run)...)
			}
		}
		if len(cur)+len(f) > payloadSize {
			flush()
		}
		cur = append(cur, f...)
	}
	if len(cur) > 0 {
		flush()
	}
	return out, nil
}

// cutPoint chooses where inside a fragment of length n to cut.
//
// It mixes two draws, and the mixture is the point. Log-uniform cuts alone
// concentrate so hard near the low end that they shave slivers off the front
// and leave one enormous remainder — measured, the largest fragment then sat at
// whatever cap was imposed, on flight after flight, which is a constant on the
// wire rather than the absence of one. Uniform cuts alone give the opposite:
// a tidy spread with nothing small in it.
//
// One time in three the cut is uniform, which breaks a large piece up; the rest
// of the time it is log-uniform from one end or the other, which is what
// produces the one- and two-byte fragments the captures show.
func cutPoint(n int) (int, error) {
	if n <= 2 {
		return 1, nil
	}
	mode, err := randInt(0, 2)
	if err != nil {
		return 0, err
	}
	if mode == 0 {
		return randInt(1, n-1)
	}
	at, err := logUniform(n - 1)
	if err != nil {
		return 0, err
	}
	if mode == 2 {
		at = n - at // a sliver off the far end instead of the near one
	}
	if at < 1 {
		at = 1
	}
	if at > n-1 {
		at = n - 1
	}
	return at, nil
}

// logUniform returns a value in [1, hi] with every power-of-two band equally
// likely, which concentrates draws near 1 while still reaching hi.
func logUniform(hi int) (int, error) {
	if hi <= 1 {
		return 1, nil
	}
	octaves := 0
	for 1<<(octaves+1) <= hi {
		octaves++
	}
	e, err := randInt(0, octaves)
	if err != nil {
		return 0, err
	}
	lo := 1 << e
	top := lo*2 - 1
	if top > hi {
		top = hi
	}
	return randInt(lo, top)
}

// randInt returns a uniform value in [lo, hi].
func randInt(lo, hi int) (int, error) {
	if hi < lo {
		return 0, fmt.Errorf("quic: empty range [%d,%d]", lo, hi)
	}
	if hi == lo {
		return lo, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return 0, err
	}
	return lo + int(n.Int64()), nil
}

// sortUint64 is an insertion sort; the slices here are tens of entries at most.
func sortUint64(s []uint64) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
