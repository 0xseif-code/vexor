package tamper

import (
	"strings"
	"testing"
)

func TestListAvailableCount(t *testing.T) {
	names := ListAvailable()
	if len(names) < 40 {
		t.Fatalf("expected at least 40 tampers, got %d: %v", len(names), names)
	}
}

func TestCaseTampers(t *testing.T) {
	in := "select 1 from"
	cases := map[string]string{
		"lowercase": "select 1 from",
		"uppercase": "SELECT 1 FROM",
	}
	tamper, _ := GetTamper("lowercase")
	if got := tamper(in); got != "select 1 from" {
		t.Errorf("lowercase: got %q", got)
	}
	tamper, _ = GetTamper("uppercase")
	if got := tamper(in); got != "SELECT 1 FROM" {
		t.Errorf("uppercase: got %q", got)
	}
	_ = cases

	// swapcase
	tamper, _ = GetTamper("swapcase")
	got := tamper("Select")
	if got != "sELECT" {
		t.Errorf("swapcase 'Select': got %q", got)
	}

	// randomcase only changes case, never length/content
	tamper, _ = GetTamper("randomcase")
	out := tamper("select")
	if len(out) != len("select") {
		t.Errorf("randomcase length changed: %q", out)
	}
}

func TestCommentTampers(t *testing.T) {
	checks := []struct {
		name string
		in   string
		want string
	}{
		{"space2comment", "select 1 from", "select/**/1/**/from"},
		{"space2plus", "select 1", "select+1"},
		{"versionedmorph", "select 1", "/*!50000select 1*/"},
	}
	for _, c := range checks {
		tamper, err := GetTamper(c.name)
		if err != nil {
			t.Fatalf("missing tamper %s: %v", c.name, err)
		}
		if got := tamper(c.in); got != c.want {
			t.Errorf("%s(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}

	tamper, _ := GetTamper("space2hash")
	got := tamper("a b")
	if !strings.Contains(got, "#") {
		t.Errorf("space2hash missing #: %q", got)
	}
	tamper, _ = GetTamper("versionedkeywords")
	got = tamper("SELECT 1 FROM")
	if !strings.Contains(got, "/*!SELECT*/") {
		t.Errorf("versionedkeywords missing versioned SELECT: %q", got)
	}
	tamper, _ = GetTamper("commentbeforeparen")
	got = tamper("IF(1,2,3)")
	if !strings.Contains(got, "IF/**/(") {
		t.Errorf("commentbeforeparen: got %q", got)
	}
}

func TestWhitespaceTampers(t *testing.T) {
	tamper, _ := GetTamper("space2tab")
	if got := tamper("a b"); !strings.Contains(got, "\t") {
		t.Errorf("space2tab: %q", got)
	}
	tamper, _ = GetTamper("space2newline")
	if got := tamper("a b"); !strings.Contains(got, "\n") {
		t.Errorf("space2newline: %q", got)
	}
	for _, n := range []string{"space2randomblank", "multiplespaces", "overlongutf8"} {
		tamper, err := GetTamper(n)
		if err != nil {
			t.Fatalf("missing %s", n)
		}
		_ = tamper("select 1 from")
	}
}

func TestEncodingTampers(t *testing.T) {
	tamper, _ := GetTamper("charencode")
	// Alphanumerics are left raw; special chars are URL-encoded.
	if got := tamper("a b"); got != "a%20b" {
		t.Errorf("charencode: got %q", got)
	}
	tamper, _ = GetTamper("chardoubleencode")
	if got := tamper("a b"); got != "a%2520b" {
		t.Errorf("chardoubleencode: got %q", got)
	}
	tamper, _ = GetTamper("base64encode")
	want := "c2VsZWN0"
	if got := tamper("select"); got != want {
		t.Errorf("base64encode: got %q want %q", got, want)
	}
	tamper, _ = GetTamper("apostrophenullencode")
	if got := tamper("'a'"); got != "%00%27a%00%27" {
		t.Errorf("apostrophenullencode: got %q", got)
	}
	tamper, _ = GetTamper("equaltolike")
	if got := tamper("x=1"); got != "x LIKE 1" {
		t.Errorf("equaltolike: got %q", got)
	}
	tamper, _ = GetTamper("between")
	if got := tamper("x>5"); !strings.Contains(got, "BETWEEN 6 AND 999") {
		t.Errorf("between: got %q", got)
	}
	for _, n := range []string{
		"charunicodeencode", "charunicodeescape", "hex2char", "htmlencode",
		"percentage", "apostrophemask", "equaltorlike", "greatest",
	} {
		tamper, err := GetTamper(n)
		if err != nil {
			t.Fatalf("missing tamper %s", n)
		}
		_ = tamper("select 1 from users")
	}
}

func TestKeywordTampers(t *testing.T) {
	in := "SELECT 1 FROM users WHERE id=1"
	checks := []string{
		"randomcomments", "modsecurityversioned", "modsecurityzeroversioned",
		"bluecoat", "halfversionedmorphkeywords", "unmagicquotes",
		"appendnullbyte", "schemasplit", "concat2concatws", "lowercasekeywords",
	}
	for _, n := range checks {
		tamper, err := GetTamper(n)
		if err != nil {
			t.Fatalf("missing tamper %s", n)
		}
		out := tamper(in)
		if out == "" {
			t.Errorf("%s returned empty for %q", n, in)
		}
		if n == "appendnullbyte" && !strings.HasSuffix(out, "%00") {
			t.Errorf("appendnullbyte: got %q", out)
		}
		if n == "lowercasekeywords" && !strings.Contains(out, "select 1 from") {
			t.Errorf("lowercasekeywords: got %q", out)
		}
	}
}

func TestChainApply(t *testing.T) {
	ch, err := NewChain([]string{"space2comment", "randomcase", "charencode"})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	got := ch.Apply("select 1 from")
	if got == "" {
		t.Fatal("empty chain result")
	}
	if len(ch.Names()) != 3 {
		t.Fatalf("expected 3 names, got %v", ch.Names())
	}
}

func TestUnknownTamperError(t *testing.T) {
	_, err := GetTamper("doesnotexist")
	if err == nil {
		t.Fatal("expected error for unknown tamper")
	}
	if !strings.Contains(err.Error(), "doesnotexist") {
		t.Errorf("error should name the tamper: %v", err)
	}
}

func TestTerminalTamperWarning(t *testing.T) {
	_, err := NewChain([]string{"base64encode", "charencode"})
	if err == nil {
		t.Fatal("expected warning for base64 not last")
	}
	if !strings.Contains(err.Error(), "LAST") {
		t.Errorf("warning should mention LAST: %v", err)
	}
}

func TestSuggestForWAF(t *testing.T) {
	s := SuggestForWAF("Cloudflare")
	if len(s) == 0 {
		t.Fatal("no suggestions for Cloudflare")
	}
	if s[0] != "space2comment" {
		t.Errorf("Cloudflare chain starts with %q", s[0])
	}
	// Unknown WAF falls back to default chain.
	if len(SuggestForWAF("totally_unknown")) == 0 {
		t.Fatal("expected default suggestions for unknown WAF")
	}
}

func TestTampersPure(t *testing.T) {
	// Calling a tamper twice with the same input and no randomness should be
	// deterministic for deterministic tampers.
	tamper, _ := GetTamper("uppercase")
	a := tamper("select")
	b := tamper("select")
	if a != b {
		t.Errorf("uppercase not deterministic: %q vs %q", a, b)
	}
}
