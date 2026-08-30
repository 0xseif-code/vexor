package hash

import "golang.org/x/crypto/bcrypt"

// bcryptCompare reports whether candidate matches the stored bcrypt hash.
// Bcrypt is deliberately excluded from the default cracker sweep (see
// Options.IncludeBcrypt): its adaptive work factor caps throughput at
// thousands of candidates per second, which a dictionary attack over the
// standard 10k list would otherwise take minutes to drain.
func bcryptCompare(stored, candidate string) bool {
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(candidate)) == nil
}