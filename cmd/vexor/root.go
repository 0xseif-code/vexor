package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/wordlists"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Version is the Vexor release version, overridable at build time with
	// -ldflags "-X main.Version=...".
	Version = "1.0.0"

	// BuildDate stamps the binary build time at compile time.
	BuildDate = "unknown"
)

// appGlobal holds resolved global flags shared by every subcommand.
type appGlobal struct {
	timeout int
	threads int
	proxy   string
	headers []string

	silent  bool
	output  string
	format  string
	noColor bool

	headerMap map[string]string
}

var app = &appGlobal{}

var rootCmd = &cobra.Command{
	Use:   "vexor",
	Short: "Vexor high-performance offensive security toolkit",
	Long: `Vexor is a high-performance offensive security toolkit focused on web
application security assessment and penetration testing.

It bundles subdomain enumeration, content discovery, web fuzzing, SQL
injection detection and exploitation, and wordlist management into one
fast, scriptable command-line interface.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if app.noColor {
			color.NoColor = true
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		printBanner()
		fmt.Fprintln(os.Stderr, colorHeading.Sprintf("Vexor v%s (build %s)", Version, BuildDate))
		fmt.Fprintln(os.Stderr)
		return cmd.Help()
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	flags := rootCmd.PersistentFlags()
	flags.IntVar(&app.timeout, "timeout", 10, "global request timeout in seconds")
	flags.IntVar(&app.threads, "threads", 50, "global concurrency thread count")
	flags.StringVar(&app.proxy, "proxy", "", "HTTP/SOCKS5 proxy URL, e.g. http://127.0.0.1:8080")
	flags.StringArrayVar(&app.headers, "headers", nil, `custom HTTP header, repeatable, e.g. -H "User-Agent: custom"`)
	flags.BoolVar(&app.silent, "silent", false, "suppress banner, progress bars, and info logs")
	flags.StringVar(&app.output, "output", "", "save output results to the specified file")
	flags.StringVar(&app.format, "format", "plain", "output format: plain, json, csv")
	flags.BoolVar(&app.noColor, "no-color", false, "disable ANSI colored output")

	rootCmd.AddCommand(
		newSubdomainCmd(),
		newDirCmd(),
		newFuzzCmd(),
		newSQLiCmd(),
		newWordlistsCmd(),
		newVersionCmd(),
	)
}

// Execute wires up an interrupt-aware context and runs the CLI. It returns a
// process exit code.
func Execute() int {
	rootCmd.SetOut(os.Stderr)
	rootCmd.SetErr(os.Stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, color.YellowString("[!] interrupted"))
		} else {
			fmt.Fprintln(os.Stderr, color.RedString("[-] %v", err))
		}
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Shared global helpers
// ---------------------------------------------------------------------------

// threads returns the effective concurrency, never below the engine minimum.
func threads() int {
	if app.threads < 1 {
		return 50
	}
	return app.threads
}

func timeoutDur() time.Duration {
	if app.timeout < 1 {
		return 10 * time.Second
	}
	return time.Duration(app.timeout) * time.Second
}

// parsedHeaders turns -H "Name: value" flags into a map (last wins).
func parsedHeaders() map[string]string {
	if app.headerMap != nil {
		return app.headerMap
	}
	m := make(map[string]string, len(app.headers))
	for _, h := range app.headers {
		if i := strings.IndexByte(h, ':'); i > 0 {
			k := strings.TrimSpace(h[:i])
			v := strings.TrimSpace(h[i+1:])
			if k != "" {
				m[k] = v
			}
		}
	}
	app.headerMap = m
	return m
}

// newHTTPClient builds a client from the global flags, failing fast when a
// proxy or other init-level option is unusable.
func newHTTPClient() (*httpclient.Client, error) {
	opts := httpclient.DefaultOptions()
	opts.Timeout = timeoutDur()
	opts.Concurrency = threads()
	opts.ProxyURL = app.proxy
	if len(app.headers) > 0 {
		opts.Headers = parsedHeaders()
	}
	c := httpclient.NewClient(opts)
	if err := c.InitError(); err != nil {
		return nil, fmt.Errorf("http client: %w", err)
	}
	return c, nil
}

// newSelector builds a wordlist selector backed by the default cache manager.
func newSelector() (*wordlists.Selector, error) {
	m, err := wordlists.NewManager()
	if err != nil {
		return nil, err
	}
	return wordlists.NewSelector(m), nil
}
