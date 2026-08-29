package tamper

import (
	"math/rand/v2"
	"sync"
	"time"
)

var (
	globalRand = rand.New(rand.NewPCG(rand.Uint64(), uint64(time.Now().UnixNano())))
	randMu     sync.Mutex
)

type randPCG struct {
	p *rand.Rand
}

func (r *randPCG) IntN(n int) int {
	randMu.Lock()
	defer randMu.Unlock()
	return r.p.IntN(n)
}

var shared *randPCG

func randSource() *randPCG {
	if shared == nil {
		shared = &randPCG{p: globalRand}
	}
	return shared
}

// randBool returns a random boolean with ~50/50 probability.
func randBool() bool {
	return randSource().IntN(2) == 0
}

// whitespaceChars holds the whitespace substitutes used by space2randomblank.
var whitespaceChars = []byte{0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0}

// randWhitespace returns one random whitespace character.
func randWhitespace() byte {
	return whitespaceChars[randSource().IntN(len(whitespaceChars))]
}

// randOverlongWhitespace returns a random overlong-UTF8 encoded whitespace
// sequence. Overlong encodings use redundant lead bytes for a single code
// point, which some naive WAF decoders fail to expand.
func randOverlongWhitespace() string {
	v := randSource().IntN(6)
	switch v {
	case 0:
		return "\xc0\xa0" // U+0020 overlong
	case 1:
		return "\xc0\xaf" // U+000F overlong (form feed variant)
	case 2:
		return "\xc1\x8f" // U+000F overlong
	case 3:
		return "\xc0\x9c" // U+001C overlong
	case 4:
		return "\xc1\x9c" // U+001C overlong
	default:
		return "\xc0\x8d" // U+000D overlong
	}
}

// isSpace reports whether r is ASCII whitespace.
func isSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}
