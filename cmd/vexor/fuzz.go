package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/0xseif-code/vexor/internal/fuzz"
	"github.com/0xseif-code/vexor/internal/wordlists"
	"github.com/spf13/cobra"
)

// fuzzPresets maps the built-in fuzz wordlist presets to their sizes.
var fuzzPresets = map[string]wordlists.Size{
	"parameters":      wordlists.SizeParameters,
	"extensions":      wordlists.SizeExtensions,
	"usernames":       wordlists.SizeUsernames,
	"passwords":       wordlists.SizePasswords,
	"passwords-large": wordlists.SizePasswordsLarge,
	"endpoints":       wordlists.SizeEndpoints,
}

func newFuzzCmd() *cobra.Command {
	var (
		url, method, data, wordlist string
		matchStatus, filterStatus   string
		filterSize                  string
		matchRegex, filterRegex     string
		delay                       time.Duration
	)

	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Fuzz web requests with payloads",
		Long: `Fuzz one or more request components by marking them with a FUZZ keyword.
Payloads are drawn from a preset or custom wordlist and injected into the
URL, headers, and body. Responses are filtered by status, size, and regex.

Example:
  vexor fuzz -u "https://example.com/page?file=FUZZ&id=1"
  vexor fuzz -u "http://target/login" -d "user=FUZZ&pass=x" -X POST`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFuzz(cmd.Context(), fuzzOptions{
				url:          url,
				method:       method,
				data:         data,
				wordlist:     wordlist,
				matchStatus:  matchStatus,
				filterStatus: filterStatus,
				filterSize:   filterSize,
				matchRegex:   matchRegex,
				filterRegex:  filterRegex,
				delay:        delay,
			})
		},
	}

	f := cmd.Flags()
	f.StringVarP(&url, "url", "u", "", `target URL containing FUZZ markers, e.g. /dir?param=FUZZ (required)`)
	f.StringVarP(&method, "method", "X", "GET", "HTTP method")
	f.StringVarP(&data, "data", "d", "", "request body (FUZZ markers supported)")
	f.StringVarP(&wordlist, "wordlist", "w", "parameters", "fuzz preset (parameters, extensions, usernames, passwords, passwords-large, endpoints) or a custom wordlist path")
	f.StringVar(&matchStatus, "match-status", "", "only report responses with these status codes, comma-separated")
	f.StringVar(&filterStatus, "filter-status", "", "exclude responses with these status codes, comma-separated")
	f.StringVar(&filterSize, "filter-size", "", "exclude responses with these content-length byte sizes, comma-separated")
	f.StringVar(&matchRegex, "match-regex", "", "only report responses whose body matches this regex")
	f.StringVar(&filterRegex, "filter-regex", "", "exclude responses whose body matches this regex")
	f.DurationVar(&delay, "delay", 0, "delay between requests, e.g. 100ms")

	return cmd
}

type fuzzOptions struct {
	url          string
	method       string
	data         string
	wordlist     string
	matchStatus  string
	filterStatus string
	filterSize   string
	matchRegex   string
	filterRegex  string
	delay        time.Duration
}

func runFuzz(ctx context.Context, o fuzzOptions) error {
	start := time.Now()

	if o.url == "" {
		return fmt.Errorf("no target URL: set -u (include a FUZZ marker)")
	}
	if !strings.Contains(o.url, "FUZZ") && !strings.Contains(o.data, "FUZZ") {
		return fmt.Errorf(`no FUZZ marker found in URL or data; mark an injection point with "FUZZ"`)
	}

	wlOpts, err := resolveFuzzWordlist(o.wordlist)
	if err != nil {
		return err
	}

	matchStatus, err := intList(o.matchStatus)
	if err != nil {
		return err
	}
	filterStatus, err := intList(o.filterStatus)
	if err != nil {
		return err
	}
	filterSize, err := int64List(o.filterSize)
	if err != nil {
		return err
	}

	client, err := newHTTPClient()
	if err != nil {
		return err
	}
	selector, err := newSelector()
	if err != nil {
		return err
	}
	pub, err := newPublisher(app.format, app.output)
	if err != nil {
		return err
	}
	defer pub.Close()

	method := strings.ToUpper(o.method)
	if method == "" {
		method = "GET"
	}

	cfg := fuzz.Config{
		Method:  method,
		URL:     o.url,
		Headers: parsedHeaders(),
		Body:    o.data,
		DefaultWordlist: wordlists.Options{
			Category:   wordlists.CategoryFuzz,
			Size:       wlOpts.Size,
			CustomPath: wlOpts.CustomPath,
		},
		Threads:      threads(),
		Delay:        o.delay,
		Timeout:      timeoutDur(),
		MatchStatus:  matchStatus,
		FilterStatus: filterStatus,
		FilterSize:   filterSize,
		MatchRegex:   o.matchRegex,
		FilterRegex:  o.filterRegex,
		Proxy:        app.proxy,
	}

	logStep("starting fuzzing %s %s (threads=%d, wordlist=%s)", method, o.url, threads(), fuzzWordlistLabel(wlOpts))

	fuzzer := fuzz.New(cfg, client, selector)
	resCh, errCh := fuzzer.Run(ctx)

	header := []string{"status", "size", "url", "content_type", "redirect_to", "words", "lines", "duration", "payload", "reason"}
	errCount := 0
	var lastErr error
	count := 0
	for r := range resCh {
		count++
		size := humanSize(r.ContentLength)
		pub.Publish(
			fmt.Sprintf("[%d] %s (%s)", r.StatusCode, r.URL, payloadSummary(r.Payload)),
			struct {
				URL           string            `json:"url"`
				Payload       map[string]string `json:"payload"`
				StatusCode    int               `json:"status"`
				ContentLength int64             `json:"size"`
				Words         int               `json:"words"`
				Lines         int               `json:"lines"`
				Duration      string            `json:"duration"`
				RedirectTo    string            `json:"redirect_to,omitempty"`
				ContentType   string            `json:"content_type,omitempty"`
				Matched       bool              `json:"matched"`
				MatchReason   string            `json:"match_reason,omitempty"`
			}{
				URL: r.URL, Payload: r.Payload, StatusCode: r.StatusCode, ContentLength: r.ContentLength,
				Words: r.Words, Lines: r.Lines, Duration: humanDur(r.Duration),
				RedirectTo: r.RedirectTo, ContentType: r.ContentType, Matched: r.Matched, MatchReason: r.MatchReason,
			},
			header,
			[]string{fmt.Sprint(r.StatusCode), size, r.URL, r.ContentType, r.RedirectTo, fmt.Sprint(r.Words), fmt.Sprint(r.Lines), humanDur(r.Duration), payloadSummary(r.Payload), r.MatchReason},
		)
	}
	for err := range errCh {
		errCount++
		lastErr = err
		logWarn("fuzz: %v", err)
	}

	st := fuzzer.Stats()
	if st.Hits == 0 && errCount > 0 {
		return fmt.Errorf("no hits: %w", lastErr)
	}
	logOK("fuzzing complete: %d hits, %d/%d checked, %d errors in %s", st.Hits, st.Checked, st.Total, st.Errors, humanDur(time.Since(start)))
	return nil
}

// resolveFuzzWordlist maps a preset name or path onto wordlists options.
func resolveFuzzWordlist(w string) (wordlists.Options, error) {
	if size, ok := fuzzPresets[w]; ok {
		return wordlists.Options{Category: wordlists.CategoryFuzz, Size: size}, nil
	}
	if _, err := os.Stat(w); err == nil {
		return wordlists.Options{Category: wordlists.CategoryFuzz, CustomPath: w}, nil
	}
	presets := make([]string, 0, len(fuzzPresets))
	for k := range fuzzPresets {
		presets = append(presets, k)
	}
	sort.Strings(presets)
	return wordlists.Options{}, fmt.Errorf("unknown wordlist %q: not a preset (%s) or an existing file", w, strings.Join(presets, ", "))
}

func fuzzWordlistLabel(o wordlists.Options) string {
	if o.CustomPath != "" {
		return o.CustomPath
	}
	return string(o.Size)
}

// payloadSummary renders "MARKER=value" pairs in stable order.
func payloadSummary(p map[string]string) string {
	if len(p) == 0 {
		return ""
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+p[k])
	}
	return strings.Join(parts, ", ")
}
