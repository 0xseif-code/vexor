package hash

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

// Target is one hash value to crack, annotated with everything the cracker
// needs to verify candidates.
type Target struct {
	// Hash is the normalized value produced by Identify (or matched to it).
	Hash string
	// Algorithm selects the digest family to brute-force.
	Algorithm Algorithm
	// Username is required for PostgreSQL MD5 (md5(password || username)).
	Username string
}

// Options tunes one cracker run.
type Options struct {
	// Concurrency is the worker pool size; 0 selects runtime.NumCPU()*4.
	Concurrency int
	// ProgressEvery is the cadence of ProgressFn callbacks; 0 uses 1s.
	ProgressEvery time.Duration
	// ProgressFn is invoked roughly every ProgressEvery with live stats.
	ProgressFn func(Progress)
	// IncludeBcrypt enables slow Bcrypt targets. Bcrypt work factors make a
	// full dictionary sweep impractical (thousands of candidates/sec), so it
	// stays opt-in: without this flag bcrypt hashes are reported in
	// Report.Skipped and never attempted.
	IncludeBcrypt bool
}

// Progress carries a live snapshot of one cracking run.
type Progress struct {
	Solved   int
	Total    int
	Attempts uint64
	HashRate float64 // hashes per second over the last interval
	Elapsed  time.Duration
}

// Result pairs one input target with its cracked plaintext.
type Result struct {
	// Index is the position of the target in the slice passed to New.
	Index int
	Hash  string
	// Algorithm is the algorithm that actually matched.
	Algorithm Algorithm
	Plaintext string
}

// Report summarises a cracking run.
type Report struct {
	Results  []Result
	Solved   int
	Total    int
	Attempts uint64
	Elapsed  time.Duration
	// Skipped lists hashes that could not be attempted (Bcrypt unless
	// enabled, PostgreSQL without a username, unknown algorithms).
	Skipped []string
}

// Cracker shares state across one worker pool run. Build it with New.
type Cracker struct {
	targets   []Target
	crackable []int    // target indexes that will be attempted
	skipped   []string // hashes excluded from the run
	opts      Options

	groups   []*group
	solved   []atomic.Bool
	plain    []string
	remain   atomic.Int64
	attempts atomic.Uint64

	cancel context.CancelFunc
}

// group is one digest family sharing a word-to-digest function. PostgreSQL
// needs one group per username (the salt changes the digest), every other
// algorithm uses a single flat group.
type group struct {
	algo   Algorithm
	salt   string // username for PostgreSQL
	hashFn func(string) string
	lookup map[string][]int // digest hex -> target indexes
	bcrypt []bcryptTarget   // used only for the Bcrypt family
}

type bcryptTarget struct {
	idx  int
	hash string
}

// New builds a cracker for the given targets. Normalized lookup keys are
// derived here so the hot loop only performs hash arithmetic and map probes.
func New(targets []Target, opts Options) *Cracker {
	c := &Cracker{
		targets: targets,
		opts:    opts,
		plain:   make([]string, len(targets)),
		solved:  make([]atomic.Bool, len(targets)),
		groups:  make([]*group, 0, 8),
	}

	byKey := make(map[string]*group, 8)
	for i, t := range targets {
		if !crackable(t, opts) {
			if t.Hash != "" {
				c.skipped = append(c.skipped, skipReason(t, opts))
			}
			continue
		}
		c.crackable = append(c.crackable, i)

		if t.Algorithm == Bcrypt {
			key := "bcrypt"
			g := byKey[key]
			if g == nil {
				g = &group{algo: Bcrypt, hashFn: bcryptNeverMatches}
				byKey[key] = g
				c.groups = append(c.groups, g)
			}
			g.bcrypt = append(g.bcrypt, bcryptTarget{idx: i, hash: t.Hash})
			continue
		}

		salt := ""
		if t.Algorithm == PostgreSQL {
			salt = t.Username
		}
		key := string(t.Algorithm) + "\x00" + salt
		g := byKey[key]
		if g == nil {
			g = &group{algo: t.Algorithm, salt: salt, hashFn: digestFn(t.Algorithm, salt), lookup: make(map[string][]int)}
			byKey[key] = g
			c.groups = append(c.groups, g)
		}
		g.lookup[t.Hash] = append(g.lookup[t.Hash], i)
	}
	c.remain.Store(int64(len(c.crackable)))
	return c
}

// Run executes the dictionary attack over words and blocks until every word
// is consumed, every hash is solved, or ctx is cancelled. Fast hash families
// run in parallel across a worker pool with an early-exit once all hashes in
// the batch are cracked. words is loaded fully into memory; prefer RunStream
// when the dictionary is large.
func (c *Cracker) Run(ctx context.Context, words []string) *Report {
	wordsCh := make(chan string, 64)
	go func() {
		defer close(wordsCh)
		for _, w := range words {
			select {
			case wordsCh <- w:
			case <-ctx.Done():
				return
			}
		}
	}()
	return c.RunStream(ctx, wordsCh)
}

// RunStream executes the dictionary attack over a streaming word channel and
// blocks until the producer closes it, every hash is solved, or ctx is
// cancelled. Fast hash families run in parallel across a worker pool with an
// early-exit once all hashes in the batch are cracked.
func (c *Cracker) RunStream(ctx context.Context, words <-chan string) *Report {
	start := time.Now()
	if len(c.crackable) == 0 {
		return c.finish(start)
	}

	cctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	defer cancel()
	done := cctx.Done()

	conc := c.opts.Concurrency
	if conc < 1 {
		conc = runtime.NumCPU() * 4
	}

	every := c.opts.ProgressEvery
	if every <= 0 {
		every = time.Second
	}

	wordsCh := make(chan string, conc*4)
	var wg sync.WaitGroup

	// Progress reporter.
	progDone := make(chan struct{})
	go func() {
		defer close(progDone)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		lastAttempts := uint64(0)
		last := start
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				att := c.attempts.Load()
				secs := now.Sub(last).Seconds()
				var rate float64
				if secs > 0 {
					rate = float64(att-lastAttempts) / secs
				}
				lastAttempts = att
				last = now
				if c.opts.ProgressFn != nil {
					c.opts.ProgressFn(Progress{
						Solved:   c.solvedCount(),
						Total:    len(c.crackable),
						Attempts: att,
						HashRate: rate,
						Elapsed:  now.Sub(start),
					})
				}
			}
		}
	}()

	// Producer: fan the dictionary stream into the pool, stopping on early exit.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(wordsCh)
		for w := range words {
			select {
			case wordsCh <- w:
			case <-done:
				return
			}
		}
	}()

	// Workers.
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				case w, ok := <-wordsCh:
					if !ok {
						return
					}
					c.checkWord(w)
				}
			}
		}()
	}

	wg.Wait()
	cancel() // stop the progress reporter (idempotent if already fired)
	<-progDone

	return c.finish(start)
}

// checkWord hashes one candidate across every digest group and resolves any
// hits, triggering early exit once the whole batch is solved.
func (c *Cracker) checkWord(w string) {
	for _, g := range c.groups {
		var slots []int
		if g.algo == Bcrypt {
			c.attempts.Add(uint64(len(g.bcrypt)))
			for _, t := range g.bcrypt {
				if bcryptCompare(t.hash, w) {
					slots = append(slots, t.idx)
				}
			}
		} else {
			c.attempts.Add(1)
			d := g.hashFn(w)
			slots = g.lookup[d]
		}
		if len(slots) == 0 {
			continue
		}
		if c.resolve(slots, w) {
			return
		}
	}
}

// resolve marks every still-unsolved slot solved with the matching plaintext.
// It returns true when the whole batch is done so the worker can exit early.
func (c *Cracker) resolve(slots []int, w string) bool {
	won := 0
	for _, idx := range slots {
		if c.solved[idx].CompareAndSwap(false, true) {
			c.plain[idx] = w
			won++
		}
	}
	if won == 0 {
		return false
	}
	if c.remain.Add(-int64(won)) <= 0 {
		c.cancel()
		return true
	}
	return false
}

func (c *Cracker) solvedCount() int {
	return len(c.crackable) - int(c.remain.Load())
}

func (c *Cracker) finish(start time.Time) *Report {
	elapsed := time.Since(start)
	rep := &Report{
		Solved:   c.solvedCount(),
		Total:    len(c.crackable),
		Attempts: c.attempts.Load(),
		Elapsed:  elapsed,
		Skipped:  c.skipped,
	}
	for i, t := range c.targets {
		if c.solved[i].Load() {
			rep.Results = append(rep.Results, Result{Index: i, Hash: t.Hash, Algorithm: t.Algorithm, Plaintext: c.plain[i]})
		}
	}
	return rep
}

func crackable(t Target, opts Options) bool {
	switch t.Algorithm {
	case Bcrypt:
		return opts.IncludeBcrypt
	case PostgreSQL:
		return t.Username != ""
	case "", MD5, SHA1, SHA256, SHA512, MySQL323, MySQL41, NTLM:
		return t.Hash != ""
	default:
		return false
	}
}

func skipReason(t Target, opts Options) string {
	switch t.Algorithm {
	case Bcrypt:
		if opts.IncludeBcrypt {
			return t.Hash + " skipped (bcrypt too slow even when forced)"
		}
		return t.Hash + " skipped (bcrypt is impractical for dictionary attacks)"
	case PostgreSQL:
		return t.Hash + " skipped (PostgreSQL-MD5 needs its username as salt)"
	default:
		return t.Hash + " skipped (unknown algorithm)"
	}
}

// ---------------------------------------------------------------------------
// Digest families
// ---------------------------------------------------------------------------

func digestFn(a Algorithm, salt string) func(string) string {
	switch a {
	case MD5:
		return hashMD5
	case SHA1:
		return hashSHA1
	case SHA256:
		return hashSHA256
	case SHA512:
		return hashSHA512
	case MySQL323:
		return hashMySQL323
	case MySQL41:
		return hashMySQL41
	case NTLM:
		return hashNTLM
	case PostgreSQL:
		return func(s string) string { return hashPostgreSQL(salt, s) }
	case Bcrypt:
		return bcryptNeverMatches
	}
	return func(string) string { return "" }
}

func hashMD5(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hashSHA1(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hashSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hashSHA512(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

// hashMySQL323 implements the historical MySQL 3.23 PASSWORD() algorithm:
// two rotating 32-bit accumulators, masking the output to 31 bits, producing
// a 16-character hex digest.
func hashMySQL323(s string) string {
	const start = uint32(0x50305735) // 1345345333
	nr, nr2 := start, uint32(0x12345671)
	add := uint32(7)
	for i := 0; i < len(s); i++ {
		c := uint32(s[i])
		if c == ' ' || c == '\t' {
			continue
		}
		nr ^= (((nr & 63) + add) * c) + (nr << 8)
		nr2 += (nr2 << 8) ^ nr
		add += c
	}
	return fmt.Sprintf("%08x%08x", nr&0x7fffffff, nr2&0x7fffffff)
}

// hashMySQL41 implements MySQL 4.1+ PASSWORD(): '*' plus the uppercase hex of
// SHA1(SHA1(password)).
func hashMySQL41(s string) string {
	first := sha1.Sum([]byte(s))
	second := sha1.Sum(first[:])
	return "*" + toUpperHex(second[:])
}

// hashPostgreSQL implements PostgreSQL rolpassword('md5' || md5(password ||
// username)); the username is the salt and is appended, not prepended.
func hashPostgreSQL(username, s string) string {
	sum := md5.Sum([]byte(s + username))
	return "md5" + hex.EncodeToString(sum[:])
}

// hashNTLM implements the NTLM digest: MD4 of the UTF-16LE encoding of the
// password.
func hashNTLM(s string) string {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	sum := md4(buf)
	return hex.EncodeToString(sum[:])
}

func toUpperHex(b []byte) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}

// bcryptNeverMatches is a placeholder; the real Bcrypt verification uses
// bcryptCompare below and never goes through the digest-lookup path.
func bcryptNeverMatches(string) string { return "" }

// FormatRate renders a hashes-per-second figure with thousands separators,
// e.g. "1,450,000 H/s".
func FormatRate(hps float64) string {
	return commaGroup(int64(hps)) + " H/s"
}

func commaGroup(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}
