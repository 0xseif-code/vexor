package ui

import (
	"strings"
	"testing"
)

// refresh resets package state between tests so batch mode and captured
// output never leak across cases.
func refresh() {
	SetBatch(false)
	writeErr = &strings.Builder{}
	readStdin = func() (string, error) { return "\n", nil }
}

func TestAskYesNoBatchReturnsDefault(t *testing.T) {
	refresh()
	SetBatch(true)
	defer SetBatch(false)
	if got := AskYesNo("proceed?", true); !got {
		t.Fatal("expected default yes in batch mode")
	}
	if got := AskYesNo("proceed?", false); got {
		t.Fatal("expected default no in batch mode")
	}
	if sb := writeErr.(*strings.Builder).String(); sb != "" {
		t.Fatalf("batch mode should not print a prompt, got %q", sb)
	}
}

func TestAskInputBatchReturnsDefault(t *testing.T) {
	refresh()
	SetBatch(true)
	defer SetBatch(false)
	if got := AskInput("value?", "abc"); got != "abc" {
		t.Fatalf("expected default %q, got %q", "abc", got)
	}
}

func TestAskChoiceBatchReturnsDefault(t *testing.T) {
	refresh()
	SetBatch(true)
	defer SetBatch(false)
	if got := AskChoice("pick", []string{"a", "b", "c"}, "b"); got != "b" {
		t.Fatalf("expected default %q, got %q", "b", got)
	}
}

// Non-batch but non-TTY (piped stdin, as in CI) must also resolve to defaults
// without printing or blocking. This is environment-dependent (a test runner
// may present a real terminal), so it only asserts the default when stdin is
// not interactive.
func TestAskYesNoNonTTYReturnsDefault(t *testing.T) {
	refresh()
	SetBatch(false)
	if !interactive() {
		if got := AskYesNo("proceed?", true); !got {
			t.Fatal("expected default yes when stdin is not a TTY")
		}
		if sb := writeErr.(*strings.Builder).String(); sb != "" {
			t.Fatalf("non-TTY mode should not print a prompt, got %q", sb)
		}
	}
}

func TestParseYesNo(t *testing.T) {
	cases := []struct {
		in      string
		def     bool
		want    bool
		interp  string
	}{
		{"y", true, true, "y"},
		{"Y", false, true, "Y is yes"},
		{"yes", false, true, "yes"},
		{"n", true, false, "n overrides yes default"},
		{"N", true, false, "N overrides yes default"},
		{"no", true, false, "no"},
		{"", true, true, "empty falls back to default"},
		{"", false, false, "empty falls back to default"},
		{"", true, true, ""},
		{"garbage", true, true, "unknown falls back to default"},
		{"garbage", false, false, "unknown falls back to default"},
	}
	for _, c := range cases {
		if got := parseYesNo(c.in, c.def); got != c.want {
			t.Errorf("parseYesNo(%q, %v) = %v, want %v (%s)", c.in, c.def, got, c.want, c.interp)
		}
	}
}

func TestParseChoiceAndInputSelection(t *testing.T) {
	opts := []string{"red", "green", "blue"}
	if got := pickChoice("3", opts, "red"); got != "blue" {
		t.Fatalf("index selection: got %q want %q", got, "blue")
	}
	if got := pickChoice("green", opts, "red"); got != "green" {
		t.Fatalf("name selection: got %q want %q", got, "green")
	}
	if got := pickChoice("", opts, "red"); got != "red" {
		t.Fatalf("empty selection defaults: got %q want %q", got, "red")
	}
	if got := pickChoice("99", opts, "red"); got != "red" {
		t.Fatalf("out-of-range defaults: got %q want %q", got, "red")
	}
}
