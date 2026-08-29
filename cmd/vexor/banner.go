package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

const vexorBanner = `
 ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗
 ██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
 ██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
 ╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
        Offensive Security Toolkit
`

var (
	colorHeading = color.New(color.FgHiCyan, color.Bold)
	colorDim     = color.New(color.FgBlack)
	colorWarn    = color.New(color.FgYellow)
	colorErr     = color.New(color.FgRed)
	colorOK      = color.New(color.FgGreen, color.Bold)
)

func printBanner() {
	printBannerTo(os.Stderr)
}

func printBannerTo(w io.Writer) {
	if app.silent {
		return
	}
	if color.NoColor {
		fmt.Fprintf(w, "Vexor v%s\n", Version)
		return
	}
	fmt.Fprintln(w, colorHeading.Sprint(vexorBanner))
}

func logInfo(format string, args ...any) {
	if app.silent {
		return
	}
	fmt.Fprintf(os.Stderr, color.CyanString("[*] ")+format+"\n", args...)
}

func logWarn(format string, args ...any) {
	if app.silent {
		return
	}
	fmt.Fprintf(os.Stderr, color.YellowString("[!] ")+format+"\n", args...)
}

func logOK(format string, args ...any) {
	if app.silent {
		return
	}
	fmt.Fprintf(os.Stderr, color.GreenString("[+] ")+format+"\n", args...)
}

func logStep(format string, args ...any) {
	if app.silent {
		return
	}
	fmt.Fprintln(os.Stderr, colorHeading.Sprintf("[*] "+format, args...))
}

// progressWriter returns the stream engine progress should be written to.
func progressWriter() io.Writer {
	if app.silent {
		return io.Discard
	}
	return os.Stderr
}

// ---------------------------------------------------------------------------
// Output publishing
// ---------------------------------------------------------------------------

type OutputFormat string

const (
	FormatPlain OutputFormat = "plain"
	FormatJSON  OutputFormat = "json"
	FormatCSV   OutputFormat = "csv"
)

// Publisher renders findings to stdout in the selected format and optionally
// mirrors them into an output file. stdout stays monochrome and pipe-friendly;
// banner, bars, and logs are never routed through the publisher.
type Publisher struct {
	mu     sync.Mutex
	stdout io.Writer
	format OutputFormat
	file   *os.File
	csvW   *csv.Writer

	stdoutCSVHeader bool
	fileCSVHeader   bool
}

func newPublisher(formatFlag, outputPath string) (*Publisher, error) {
	var f OutputFormat
	switch formatFlag {
	case "", "plain":
		f = FormatPlain
	case "json":
		f = FormatJSON
	case "csv":
		f = FormatCSV
	default:
		return nil, fmt.Errorf("invalid output format %q: expected plain, json, or csv", formatFlag)
	}

	p := &Publisher{stdout: os.Stdout, format: f}
	if outputPath != "" {
		fh, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("create output file: %w", err)
		}
		p.file = fh
	}
	return p, nil
}

// Publish emits one finding. plain is always used for plain format; v encodes
// the finding for json output, header+row for csv output.
func (p *Publisher) Publish(plain string, v any, header, row []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var stdoutLine string
	switch p.format {
	case FormatJSON:
		if v == nil {
			stdoutLine = plain
		} else if b, err := json.Marshal(v); err == nil {
			stdoutLine = string(b)
		} else {
			stdoutLine = plain
		}
	case FormatCSV:
		if len(row) == 0 {
			row, header = []string{plain}, nil
		}
		stdoutLine = csvLine(header, row, &p.stdoutCSVHeader)
	default:
		stdoutLine = plain
	}
	fmt.Fprintln(p.stdout, stdoutLine)

	if p.file != nil {
		switch p.format {
		case FormatJSON:
			fmt.Fprintln(p.file, stdoutLine)
		case FormatCSV:
			if p.csvW == nil {
				p.csvW = csv.NewWriter(p.file)
			}
			if len(row) == 0 {
				row, header = []string{plain}, nil
			}
			if !p.fileCSVHeader && len(header) > 0 {
				_ = p.csvW.Write(header)
				p.fileCSVHeader = true
			}
			_ = p.csvW.Write(row)
			p.csvW.Flush()
		default:
			fmt.Fprintln(p.file, plain)
		}
	}
}

// WriteRaw writes arbitrary bytes straight to stdout and, when a file is
// configured, to the file. Used for --read-file content that must stay intact.
func (p *Publisher) WriteRaw(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _ = p.stdout.Write(data)
	if p.file != nil {
		_, _ = p.file.Write(data)
	}
}

func (p *Publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.csvW != nil {
		p.csvW.Flush()
	}
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

func csvLine(header, row []string, headerWritten *bool) string {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if len(header) > 0 && (headerWritten == nil || !*headerWritten) {
		_ = w.Write(header)
		if headerWritten != nil {
			*headerWritten = true
		}
	}
	_ = w.Write(row)
	w.Flush()
	return strings.TrimSuffix(b.String(), "\n")
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

func humanSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(1024*1024*1024))
	}
}

func humanDur(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}

func cleanTitle(t string) string {
	return strings.Join(strings.Fields(t), " ")
}

// intList splits a comma-separated string into ints.
func intList(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid integer %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// int64List splits a comma-separated string into int64s.
func int64List(s string) ([]int64, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n int64
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid integer %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// csvEscape flattens a cell so csv output stays on one line.
func csvEscape(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t':
			return ' '
		}
		return r
	}, s)
}
