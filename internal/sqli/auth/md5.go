package auth

import (
	"crypto/md5"
	"encoding/hex"
)

// hexMD5 hashes the byte slice and returns its lowercase hex MD5 digest.
// MD5 is required for RFC 2617 digest authentication.
func hexMD5(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}
