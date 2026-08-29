package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/0xseif-code/vexor/internal/enum/directory"
	"github.com/0xseif-code/vexor/internal/wordlists"
	"github.com/spf13/cobra"
)

func newDirCmd() *cobra.Command {
	var (
		url, sizeWordlist, wordlist       string
		extensions                        []string
		recursion                         bool
		depth, rate                       int
		matchStatus, filterStatus, filter string
	)

	cmd := &cobra.Command{
		Use:     "dir",
		Aliases: []string{"directory", "enum"},
		Short:   "Discover files and directories on a web target",
		Long: `Discover web content via wordlist-driven directory/endpoint probing,
with soft-404 calibration, recursion, extension presets, and response
size/status filtering.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDir(cmd.Context(), dirOptions{
				url:          url,
				sizeWordlist: sizeWordlist,
				wordlist:     wordlist,
				extensions:   extensions,
				recursion:    recursion,
				depth:        depth,
				rate:         rate,
				matchStatus:  matchStatus,
				filterStatus: filterStatus,
				filterSize:   filter,
			})
		},
	}

	f := cmd.Flags()
	f.StringVarP(&url, "url", "u", "", "target URL, e.g. https://example.com/ (required)")
	f.StringVarP(&sizeWordlist, "size", "s", "medium", "wordlist size: small, medium, large")
	f.StringVarP(&wordlist, "wordlist", "w", "", "custom wordlist path (overrides --size)")
	f.StringSliceVarP(&extensions, "ext", "x", nil, "extensions or presets (php, asp, all) to append")
	f.BoolVarP(&recursion, "recursion", "r", false, "recursively scan discovered directories")
	f.IntVar(&depth, "depth", 2, "maximum recursion depth (used with --recursion)")
	f.StringVar(&matchStatus, "match-status", "", "only report these status codes, comma-separated")
	f.StringVar(&filterStatus, "filter-status", "", "exclude these status codes, comma-separated")
	f.StringVar(&filter, "filter-size", "", "exclude these content-length byte sizes, comma-separated")
	f.IntVar(&rate, "rate", 0, "maximum requests per second (0 = unlimited)")

	return cmd
}

type dirOptions struct {
	url          string
	sizeWordlist string
	wordlist     string
	extensions   []string
	recursion    bool
	depth        int
	rate         int
	matchStatus  string
	filterStatus string
	filterSize   string
}

func runDir(ctx context.Context, o dirOptions) error {
	start := time.Now()

	if o.url == "" {
		return fmt.Errorf("no target URL: set -u")
	}
	if o.wordlist != "" {
		if _, err := os.Stat(o.wordlist); err != nil {
			return fmt.Errorf("custom wordlist: %w", err)
		}
		o.sizeWordlist = ""
	}

	exts, err := resolveExtensions(o.extensions)
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

	cfg := directory.Config{
		TargetURL:    o.url,
		Extensions:   exts,
		Concurrency:  threads(),
		RateLimit:    o.rate,
		Timeout:      timeoutDur(),
		Recursion:    o.recursion,
		MaxDepth:     o.depth,
		MatchStatus:  matchStatus,
		FilterStatus: filterStatus,
		FilterSize:   filterSize,
		Headers:      parsedHeaders(),
		WordlistOpts: wordlists.Options{
			Category:   wordlists.CategoryDirectory,
			Size:       wordlists.Size(o.sizeWordlist),
			CustomPath: o.wordlist,
		},
	}

	logStep("starting content discovery on %s (threads=%d, depth=%d%s)", o.url, threads(), o.depth, extSummary(exts))

	scanner := directory.New(cfg, client, selector)
	resCh, errCh := scanner.Run(ctx)

	header := []string{"status", "size", "url", "content_type", "redirect_to", "title", "words", "lines", "duration", "depth"}
	count := 0
	errCount := 0
	var lastErr error
	for f := range resCh {
		count++
		title := cleanTitle(f.Title)
		size := humanSize(f.ContentLength)
		pub.Publish(
			fmt.Sprintf("%d\t%s\t%s\t%s", f.StatusCode, size, f.URL, title),
			struct {
				URL           string `json:"url"`
				StatusCode    int    `json:"status"`
				ContentLength int64  `json:"size"`
				ContentType   string `json:"content_type,omitempty"`
				RedirectTo    string `json:"redirect_to,omitempty"`
				Title         string `json:"title,omitempty"`
				Words         int    `json:"words"`
				Lines         int    `json:"lines"`
				Duration      string `json:"duration"`
				Depth         int    `json:"depth"`
			}{
				URL: f.URL, StatusCode: f.StatusCode, ContentLength: f.ContentLength,
				ContentType: f.ContentType, RedirectTo: f.RedirectTo, Title: csvEscape(title),
				Words: f.Words, Lines: f.Lines, Duration: humanDur(f.Duration), Depth: f.Depth,
			},
			header,
			[]string{fmt.Sprint(f.StatusCode), size, f.URL, f.ContentType, f.RedirectTo, csvEscape(title), fmt.Sprint(f.Words), fmt.Sprint(f.Lines), humanDur(f.Duration), fmt.Sprint(f.Depth)},
		)
	}
	for err := range errCh {
		errCount++
		lastErr = err
		logWarn("discovery: %v", err)
	}

	st := scanner.Stats()
	if st.Findings == 0 && errCount > 0 {
		return fmt.Errorf("no findings: %w", lastErr)
	}
	logOK("content discovery complete: %d findings, %d requests, %d errors in %s", st.Findings, st.Requests, st.Errors, humanDur(time.Since(start)))
	return nil
}

// resolveExtensions expands preset names into extension lists and normalizes
// literal extensions.
func resolveExtensions(exts []string) ([]string, error) {
	var out []string
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if preset, ok := directory.ExtensionPresets[e]; ok {
			out = append(out, preset...)
			continue
		}
		out = append(out, strings.TrimPrefix(e, "."))
	}
	return out, nil
}

func extSummary(exts []string) string {
	if len(exts) == 0 {
		return ""
	}
	return ", exts=" + strings.Join(exts, ",")
}
