// Package hash implements sqlmap-style hash identification and a high
// throughput concurrent dictionary cracker for the hashes most commonly found
// in dumped database user tables. Identification relies on length, character
// set and prefix signatures; cracking is backed purely by the Go standard
// library (crypto/md5, crypto/sha1, crypto/sha256, crypto/sha512) plus the
// custom MySQL 3.23 / MySQL 4.1 and NTLM (MD4) digests that vendors do not
// expose.
package hash

import "strings"

// Algorithm names a detected password-hash algorithm.
type Algorithm string

// Supported hash algorithms.
const (
	MD5        Algorithm = "MD5"
	SHA1       Algorithm = "SHA-1"
	SHA256     Algorithm = "SHA-256"
	SHA512     Algorithm = "SHA-512"
	MySQL323   Algorithm = "MySQL-323"
	MySQL41    Algorithm = "MySQL-41"
	NTLM       Algorithm = "NTLM"
	PostgreSQL Algorithm = "PostgreSQL-MD5"
	Bcrypt     Algorithm = "Bcrypt"
)

func (a Algorithm) String() string { return string(a) }

// Match is the result of identifying one extracted value.
type Match struct {
	// Algorithm is the best-match algorithm.
	Algorithm Algorithm
	// Candidates lists every algorithm the value could be, primary first.
	// 32-char MD5 hashes are indistinguishable from NTLM by shape alone, so
	// both are listed and both are attempted by the cracker.
	Candidates []Algorithm
	// Hash is the normalized form used as a lookup key. MySQL-41 is
	// uppercased, other hex hashes are lowercased, PostgreSQL keeps its
	// "md5" prefix.
	Hash string
	// NeedsUsername reports whether cracking requires the account name as a
	// salt (PostgreSQL MD5 uses md5(password || username)).
	NeedsUsername bool
	// ForceOnly reports an algorithm the cracker deliberately skips unless
	// explicitly enabled: Bcrypt work factors are far too slow for a
	// dictionary sweep and are not attempted by default.
	ForceOnly bool
}

// Identify inspects one extracted value and returns its hash signature, or
// nil when none of the known algorithms match. The value is trimmed of
// surrounding whitespace and one pair of wrapping quotes before inspection.
func Identify(raw string) *Match {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
			s = s[1 : len(s)-1]
		}
	}

	// Bcrypt: any variant prefix ($2a$, $2b$, $2y$), no length guarantee.
	if strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$") {
		if len(s) >= 20 {
			return &Match{
				Algorithm:  Bcrypt,
				Candidates: []Algorithm{Bcrypt},
				Hash:       s,
				ForceOnly:  true,
			}
		}
		return nil
	}

	// PostgreSQL: literal "md5" prefix + 32 hex digits = 35 characters.
	if len(s) == 35 && (strings.HasPrefix(s, "md5") || strings.HasPrefix(s, "MD5")) {
		if isHex(s[3:]) {
			return &Match{
				Algorithm:     PostgreSQL,
				Candidates:    []Algorithm{PostgreSQL},
				Hash:          strings.ToLower(s),
				NeedsUsername: true,
			}
		}
		return nil
	}

	// MySQL 4.1+: '*' + uppercase hex of SHA1(SHA1(password)) = 41 characters.
	if strings.HasPrefix(s, "*") && len(s) == 41 {
		if isHex(s[1:]) {
			return &Match{
				Algorithm:  MySQL41,
				Candidates: []Algorithm{MySQL41},
				Hash:       strings.ToUpper(s),
			}
		}
		return nil
	}

	// Everything else must be a plain fixed-length hex string.
	if !isHex(s) {
		return nil
	}
	lower := strings.ToLower(s)
	switch len(s) {
	case 16:
		return &Match{Algorithm: MySQL323, Candidates: []Algorithm{MySQL323}, Hash: lower}
	case 32:
		// Shape alone cannot tell MD5, NTLM and the pre-4.1 plain (unprefixed)
		// MySQL digest apart; list the realistic ones and let the cracker try
		// each in order.
		return &Match{Algorithm: MD5, Candidates: []Algorithm{MD5, NTLM}, Hash: lower}
	case 40:
		return &Match{Algorithm: SHA1, Candidates: []Algorithm{SHA1}, Hash: lower}
	case 64:
		return &Match{Algorithm: SHA256, Candidates: []Algorithm{SHA256}, Hash: lower}
	case 128:
		return &Match{Algorithm: SHA512, Candidates: []Algorithm{SHA512}, Hash: lower}
	}
	return nil
}

// Verify reports whether candidate plaintext p matches the identified hash t.
// For PostgreSQL targets the account username is used as the salt; callers
// must populate it (NeedsUsername) or the check is skipped.
func Verify(t Target, p string) bool {
	switch t.Algorithm {
	case MD5:
		return hashMD5(p) == t.Hash
	case SHA1:
		return hashSHA1(p) == t.Hash
	case SHA256:
		return hashSHA256(p) == t.Hash
	case SHA512:
		return hashSHA512(p) == t.Hash
	case MySQL323:
		return hashMySQL323(p) == t.Hash
	case MySQL41:
		return hashMySQL41(p) == t.Hash
	case NTLM:
		return hashNTLM(p) == t.Hash
	case PostgreSQL:
		if t.Username == "" {
			return false
		}
		return hashPostgreSQL(t.Username, p) == t.Hash
	}
	return false
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}