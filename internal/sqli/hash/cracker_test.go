package hash

import (
	"context"
	"testing"
)

func TestIdentifyAndVerify(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		algo     Algorithm
		plain    string
		username string // only relevant for PostgreSQL
	}{
		{name: "md5", raw: "5f4dcc3b5aa765d61d8327deb882cf99", algo: MD5, plain: "password"},
		{name: "sha1", raw: "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", algo: SHA1, plain: "password"},
		{name: "mysql41", raw: "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", algo: MySQL41, plain: "password"},
		{name: "postgres", raw: "md532e12f215ba27cb750c9e093ce4b5127", algo: PostgreSQL, plain: "password", username: "postgres"},
		{name: "mysql323", raw: "5d2e19393cc5ef67", algo: MySQL323, plain: "password"},
		{name: "sha256", raw: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", algo: SHA256, plain: "password"},
		{name: "sha512", raw: "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", algo: SHA512, plain: "password"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Identify(tc.raw)
			if m == nil {
				t.Fatalf("Identify(%q) returned nil", tc.raw)
			}
			matched := false
			for _, c := range m.Candidates {
				if c == tc.algo {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("Identify(%q) candidates %v do not include %s", tc.raw, m.Candidates, tc.algo)
			}
			tgt := Target{Hash: m.Hash, Algorithm: tc.algo, Username: tc.username}
			if !Verify(tgt, tc.plain) {
				t.Fatalf("Verify(%q, %q) = false, want true", tc.raw, tc.plain)
			}
			if Verify(tgt, "wrongpass") {
				t.Fatalf("Verify(%q, %q) = true, want false", tc.raw, "wrongpass")
			}
		})
	}
}

func TestCrackerCracksAll(t *testing.T) {
	plain := "sup3rS3cret!"
	targets := []Target{
		{Hash: hashMD5(plain), Algorithm: MD5},
		{Hash: hashSHA1(plain), Algorithm: SHA1},
		{Hash: hashMySQL41(plain), Algorithm: MySQL41},
		{Hash: hashPostgreSQL("admin", plain), Algorithm: PostgreSQL, Username: "admin"},
	}

	c := New(targets, Options{Concurrency: 8})
	rep := c.Run(context.Background(), []string{"letmein", "password", plain, "123456"})

	if rep.Solved != 4 {
		t.Fatalf("Solved = %d, want 4 (results=%d)", rep.Solved, len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.Plaintext != plain {
			t.Errorf("result for %s: plaintext = %q, want %q", r.Algorithm, r.Plaintext, plain)
		}
	}
}

func TestCrackerEarlyExit(t *testing.T) {
	plain := "hunter2"
	c := New([]Target{{Hash: hashMD5(plain), Algorithm: MD5}}, Options{Concurrency: 4})
	words := make([]string, 200000)
	for i := range words {
		words[i] = "no-such-password-" + string(rune('a'+i%26))
	}
	words[150000] = plain
	rep := c.Run(context.Background(), words)
	if rep.Solved != 1 {
		t.Fatalf("Solved = %d, want 1", rep.Solved)
	}
}

func TestRunStream(t *testing.T) {
	plain := "streamed"
	c := New([]Target{{Hash: hashSHA1(plain), Algorithm: SHA1}}, Options{Concurrency: 4})
	words := make(chan string, 4)
	go func() {
		defer close(words)
		for _, w := range []string{"a", "b", plain, "c"} {
			words <- w
		}
	}()
	rep := c.RunStream(context.Background(), words)
	if rep.Solved != 1 {
		t.Fatalf("Solved = %d, want 1", rep.Solved)
	}
}
