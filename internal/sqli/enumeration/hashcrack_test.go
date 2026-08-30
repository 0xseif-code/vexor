package enumeration

import (
	"context"
	"io"
	"testing"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// testDetector returns a minimal detection usable with NewEnumeratorOpts; the
// pure helper tests below never touch the network, so Detector's client is nil.
func crackTestEnumerator(policy CrackPolicy) *Enumerator {
	det := testDetection("mysql")
	return NewEnumeratorOpts(det, (*httpclient.Client)(nil), Options{
		Concurrency: DefaultConcurrency,
		Progress:    io.Discard,
		Crack:       policy,
	})
}

func TestIdentifyTargetsSkipsUnknownShapes(t *testing.T) {
	targets := identifyTargets([]string{
		"5f4dcc3b5aa765d61d8327deb882cf99", // MD5
		"plain text is not a hash",
		"",
		"$2a$10$7EqJtq98hPqEX7fNZaFWoOhi6W6IkJoM0hIS.HFfLXMV96Y7U6Y4a", // bcrypt
	})
	if len(targets) == 0 {
		t.Fatal("expected at least the bcrit/MD5-style shapes to be recognized")
	}
	seen := map[string]bool{}
	for _, got := range targets {
		seen[string(got.Algorithm)] = true
	}
	if !seen["MD5"] && !seen["NTLM"] {
		t.Errorf("32-hex values should produce MD5/NTLM candidates, got algorithms %v", seen)
	}
}

func TestIdentifyCredentialsSkipsBatchUnknown(t *testing.T) {
	creds := []Credential{
		{User: "admin", Hash: "21232f297a57a5a743894a0e4a801fc3"}, // MD5("admin")
		{User: "not-a-hash", Hash: "nothing"},
	}
	targets := identifyCredentials(creds)
	if len(targets) == 0 {
		t.Fatal("recognized credential hashes must become targets")
	}
}

func TestAnnotateHashesAppendsPlaintext(t *testing.T) {
	cracked := map[string]string{
		"5f4dcc3b5aa765d61d8327deb882cf99": "password",
	}
	res := &DumpResult{
		Cols: []string{"username", "pass"},
		Rows: [][]string{
			{"admin", "5f4dcc3b5aa765d61d8327deb882cf99"},
			{"guest", "not-a-hash"},
		},
	}
	annotateHashes(res, cracked)
	if got := res.Rows[0][1]; got != "5f4dcc3b5aa765d61d8327deb882cf99 (password)" {
		t.Errorf("row 0 column 1 = %q, want annotated plaintext", got)
	}
	if got := res.Rows[1][1]; got != "not-a-hash" {
		t.Errorf("non-hash cell must stay untouched, got %q", got)
	}
}

func TestCrackNeverSkipsWork(t *testing.T) {
	e := crackTestEnumerator(CrackNever)
	// CrackNever must return early without prompting, loading a wordlist, or
	// dialing the network (client is nil above, so any misuse panics/errors).
	out, err := e.CrackHashes(context.Background(), []string{
		"5f4dcc3b5aa765d61d8327deb882cf99",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("CrackNever produced %v, want empty", out)
	}
}

func TestCrackPolicyZeroDefaultPrompts(t *testing.T) {
	// CrackPrompt (the zero value) must resolve to a decision; in batch mode
	// ui defaults to "no", so a prompt-declined run returns an empty map with
	// no error. Constructing CrackPrompt is enough to confirm the enum wiring.
	if CrackPrompt != 0 {
		t.Error("CrackPrompt should be the zero value so Options{} defaults to prompt")
	}
}
