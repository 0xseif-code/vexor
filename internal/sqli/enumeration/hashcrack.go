package enumeration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/0xseif-code/vexor/internal/sqli/hash"
	"github.com/0xseif-code/vexor/internal/sqli/ui"
	"github.com/0xseif-code/vexor/internal/wordlists"
)

// CrackPolicy controls whether password hashes recovered during dump or
// password enumeration are pushed through the dictionary cracker.
type CrackPolicy int

const (
	// CrackPrompt asks the user before cracking (default). Batch/non-TTY runs
	// resolve to "no" so scripted scans never unexpectedly download a
	// wordlist or hammer the CPU.
	CrackPrompt CrackPolicy = iota
	// CrackForce runs the attack without prompting (--crack).
	CrackForce
	// CrackNever disables cracking entirely (--no-crack).
	CrackNever
)

// CrackHashes inspects extracted values, identifies any password hashes and,
// following the enumerator's crack policy, runs the concurrent dictionary
// cracker. The returned map is keyed by normalized hash (see hash.Identify)
// and holds the cracked plaintexts. Values without a known signature are
// ignored; a declined or disabled crack returns an empty map.
func (e *Enumerator) CrackHashes(ctx context.Context, values []string) (map[string]string, error) {
	return e.crackTargets(ctx, identifyTargets(values))
}

// CrackCredentials runs the dictionary cracking flow over recovered
// credentials, propagating the account name so PostgreSQL hashes
// (md5(password || username)) can be validated. Returns normalized-hash ->
// plaintext; callers annotate their own rows.
func (e *Enumerator) CrackCredentials(ctx context.Context, creds []Credential) (map[string]string, error) {
	return e.crackTargets(ctx, identifyCredentials(creds))
}

// crackFromResult drives the dump integration: every cell of every row is
// scanned for hash signatures and the resulting plaintexts are used to
// annotate the matching cells. Errors degrade to a warning, never to a failed
// dump.
func (e *Enumerator) crackFromResult(ctx context.Context, res *DumpResult) map[string]string {
	var values []string
	for _, row := range res.Rows {
		for _, cell := range row {
			if strings.TrimSpace(cell) != "" {
				values = append(values, cell)
			}
		}
	}
	cracked, err := e.CrackHashes(ctx, values)
	if err != nil {
		e.progressf("[!] hash cracking: %v", err)
		return nil
	}
	return cracked
}

// annotateHashes appends "(plaintext)" to every dumped cell whose value
// matched a cracked hash, mirroring sqlmap's table annotation.
func annotateHashes(res *DumpResult, cracked map[string]string) {
	for _, row := range res.Rows {
		for j := range row {
			cell := strings.TrimSpace(row[j])
			if cell == "" {
				continue
			}
			m := hash.Identify(cell)
			if m == nil {
				continue
			}
			if pw, ok := cracked[m.Hash]; ok {
				row[j] = cell + " (" + pw + ")"
			}
		}
	}
}

// identifyTargets scans arbitrary values and maps each recognized hash to the
// cracker targets it could be, expanding ambiguous shapes (32-hex MD5 values
// are also valid NTLM hashes) so both digest families get a chance.
func identifyTargets(values []string) []hash.Target {
	var targets []hash.Target
	seen := make(map[string]bool)
	for _, v := range values {
		m := hash.Identify(v)
		if m == nil {
			continue
		}
		for _, a := range m.Candidates {
			key := string(a) + "\x00" + m.Hash
			if seen[key] {
				continue
			}
			seen[key] = true
			targets = append(targets, hash.Target{Hash: m.Hash, Algorithm: a})
		}
	}
	return targets
}

// identifyCredentials is identifyTargets with account context: PostgreSQL
// hashes carry their username as the salt.
func identifyCredentials(creds []Credential) []hash.Target {
	var targets []hash.Target
	seen := make(map[string]bool)
	for _, c := range creds {
		m := hash.Identify(c.Hash)
		if m == nil {
			continue
		}
		user := c.User
		if at := strings.IndexByte(user, '@'); at >= 0 {
			user = user[:at]
		}
		for _, a := range m.Candidates {
			key := string(a) + "\x00" + m.Hash
			if seen[key] {
				continue
			}
			seen[key] = true
			targets = append(targets, hash.Target{Hash: m.Hash, Algorithm: a, Username: user})
		}
	}
	return targets
}

// crackTargets is the shared prompt -> wordlist -> cracker pipeline. The
// dictionary is streamed straight from disk into a bounded worker pool, so
// even a multi-hundred-MB SecLists file never has to fit in memory.
func (e *Enumerator) crackTargets(ctx context.Context, targets []hash.Target) (map[string]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	switch e.opts.Crack {
	case CrackNever:
		return nil, nil
	case CrackPrompt:
		types := summarizeTypes(targets)
		ok := ui.AskYesNo(
			fmt.Sprintf("Recognized %d password hashes (Types: %s). Do you want to crack them via a dictionary-based attack?", len(targets), types),
			!ui.Batch(),
		)
		if !ok {
			return nil, nil
		}
	case CrackForce:
		// Suppress every prompt.
	}

	opts, label, err := e.chooseWordlist(ctx)
	if err != nil {
		return nil, err
	}

	m, err := wordlists.NewManager()
	if err != nil {
		return nil, fmt.Errorf("wordlist manager: %w", err)
	}
	sel := wordlists.NewSelector(m)
	words, werrs, err := sel.LoadStream(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Drain stream errors concurrently with cracking; surface the first hard
	// failure (open/read) if any after the run finishes.
	var drained sync.WaitGroup
	var streamErr error
	drained.Add(1)
	go func() {
		defer drained.Done()
		for werr := range werrs {
			if werr == nil {
				continue
			}
			e.progressf("[!] wordlist stream: %v", werr)
			if streamErr == nil {
				streamErr = werr
			}
		}
	}()

	e.progressf("[*] cracking %d hash(es) via %s", len(targets), label)

	rep := hash.New(targets, hash.Options{
		ProgressFn: func(p hash.Progress) {
			if p.Total <= 0 {
				return
			}
			pct := float64(p.Solved) / float64(p.Total) * 100
			e.progressf("[*] Cracking hashes: %d/%d solved (%.1f%%) | Speed: %s",
				p.Solved, p.Total, pct, hash.FormatRate(p.HashRate))
		},
	}).RunStream(ctx, words)
	drained.Wait()
	if streamErr != nil {
		return nil, streamErr
	}

	pct := 0.0
	if rep.Total > 0 {
		pct = float64(rep.Solved) / float64(rep.Total) * 100
	}
	e.progressf("[*] Cracking finished: %d/%d hashes solved (%.1f%%) in %s (%d attempts)",
		rep.Solved, rep.Total, pct, rep.Elapsed.Round(time.Millisecond), rep.Attempts)
	if len(rep.Skipped) > 0 {
		e.progressf("[!] %d hash(es) not attempted: %s", len(rep.Skipped), strings.Join(rep.Skipped, ", "))
	}

	out := make(map[string]string, len(rep.Results))
	for _, r := range rep.Results {
		if _, exists := out[r.Hash]; !exists {
			out[r.Hash] = r.Plaintext
		}
	}
	return out, nil
}

// chooseWordlist asks the user which dictionary to use, then resolves the
// selection into wordlist options. The default is the cached 10k
// common-passwords list; an alternative path is validated by the selector.
func (e *Enumerator) chooseWordlist(ctx context.Context) (wordlists.Options, string, error) {
	const (
		optDefault = "Default (10k passwords)"
		optCustom  = "Custom file path"
	)
	choice := ui.AskChoice("Which dictionary do you want to use?", []string{optDefault, optCustom}, optDefault)

	opts := wordlists.Options{Category: wordlists.CategoryFuzz, Size: wordlists.SizePasswords}
	label := "default 10k passwords"
	if choice == optCustom {
		path := strings.TrimSpace(ui.AskInput("Enter the path to your custom wordlist", ""))
		if path == "" {
			return opts, "", fmt.Errorf("no custom wordlist path given")
		}
		opts = wordlists.Options{CustomPath: path}
		label = path
	}
	return opts, label, nil
}

// summarizeTypes renders the distinct recognized algorithm names, e.g.
// "MD5, MySQL-41".
func summarizeTypes(targets []hash.Target) string {
	seen := make(map[string]bool)
	var names []string
	for _, t := range targets {
		name := t.Algorithm.String()
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}