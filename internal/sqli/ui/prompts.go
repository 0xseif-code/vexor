// Package ui implements Vexor's interactive prompt engine for the SQLi
// module. It mirrors sqlmap's user-decision prompts (DBMS filtering, WAF
// tampering, parameter narrowing, dump size confirmation) while remaining
// fully non-interactive whenever the --batch flag is set or stdin is not a
// terminal, in which case every question resolves to its default value without
// blocking.
package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// batchMode records whether the caller opted into non-interactive behaviour
// (--batch). It is set globally by the CLI once flags are parsed and may also
// be set library-side through SetBatch.
var batchMode bool

// readStdin and writeErr are package variables so tests can substitute a pipe
// and capture prompt text without depending on a real terminal.
var (
	readStdin func() (string, error)
	writeErr  io.Writer = os.Stderr
)

func init() {
	readStdin = func() (string, error) {
		return bufio.NewReader(os.Stdin).ReadString('\n')
	}
}

// SetBatch toggles non-interactive mode. When true, every prompt resolves to
// its default immediately, without printing or reading stdin.
func SetBatch(v bool) { batchMode = v }

// Batch reports whether non-interactive mode is active.
func Batch() bool { return batchMode }

// interactive reports whether we may block for human input: batch mode must be
// off and stdin must be an interactive terminal.
func interactive() bool {
	if batchMode {
		return false
	}
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	// ModeCharDevice is set for terminals on both Linux and Windows; when
	// stdin is a pipe or redirected file it is absent.
	return fi.Mode()&os.ModeCharDevice != 0
}

// AskYesNo presents a yes/no question and returns the user's decision. The
// prompt is rendered as "[Y/n]" (Yes default) or "[y/N]" (No default)
// depending on defaultYes. In batch or non-TTY mode it returns defaultYes
// without printing or reading.
func AskYesNo(prompt string, defaultYes bool) bool {
	if !interactive() {
		return defaultYes
	}
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	fmt.Fprintf(writeErr, "[?] %s %s ", prompt, suffix)
	line, err := readStdin()
	if err != nil {
		// EOF or a read error on a broken stdin: fall back to the default.
		return defaultYes
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return parseYesNo(answer, defaultYes)
}

// parseYesNo interprets a raw user answer. 'y'/'yes' => true, 'n'/'no' =>
// false, anything else (including empty) falls back to defaultYes so a stray
// keystroke never crashes or hangs the scan.
func parseYesNo(answer string, defaultYes bool) bool {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defaultYes
	}
}

// AskChoice presents a numbered menu of options and returns the chosen label.
// Empty input resolves to defaultChoice. Unknown choices resolve to the default
// as well, and in batch/non-TTY mode defaultChoice is returned immediately.
func AskChoice(prompt string, options []string, defaultChoice string) string {
	if !interactive() {
		return defaultChoice
	}
	fmt.Fprintf(writeErr, "[?] %s\n", prompt)
	for i, opt := range options {
		fmt.Fprintf(writeErr, "    [%d] %s\n", i+1, opt)
	}
	idx := indexOf(options, defaultChoice)
	fmt.Fprintf(writeErr, "    choice [%d]: ", idx+1)
	line, err := readStdin()
	if err != nil {
		return defaultChoice
	}
	return pickChoice(line, options, defaultChoice)
}

// pickChoice resolves a raw menu answer (either an index or a label) to one of
// options, falling back to defaultChoice on empty / unknown input.
func pickChoice(answer string, options []string, defaultChoice string) string {
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return defaultChoice
	}
	if n, cerr := strconv.Atoi(answer); cerr == nil && n >= 1 && n <= len(options) {
		return options[n-1]
	}
	for _, opt := range options {
		if strings.EqualFold(opt, answer) {
			return opt
		}
	}
	return defaultChoice
}

// AskInput requests a free-form value from the user. Empty input (or any
// non-interactive context) resolves to defaultValue.
func AskInput(prompt string, defaultValue string) string {
	if !interactive() {
		return defaultValue
	}
	if defaultValue != "" {
		fmt.Fprintf(writeErr, "[?] %s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Fprintf(writeErr, "[?] %s: ", prompt)
	}
	line, err := readStdin()
	if err != nil {
		return defaultValue
	}
	answer := strings.TrimSpace(line)
	if answer == "" {
		return defaultValue
	}
	return answer
}

func indexOf(items []string, want string) int {
	for i, it := range items {
		if it == want {
			return i
		}
	}
	return 0
}
