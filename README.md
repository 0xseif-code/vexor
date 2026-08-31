```text
 ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗
 ██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
 ██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
 ╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

**High-Performance Recon & Fuzzing Toolkit written in Go**

[ English ] | [ العربية (Arabic) ](README.ar.md)

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows-brightgreen?style=flat-square)](https://github.com/0xseif-code/vexor/releases)
[![Release](https://img.shields.io/badge/Version-1.0.0-orange?style=flat-square)](https://github.com/0xseif-code/vexor/releases)

Vexor is a single-binary recon and fuzzing toolkit for web security.
No runtime dependencies, no bloat — just a binary, your wordlists, and a target.
SQL injection testing is delegated to sqlmap.

```bash
# Quick install
go install github.com/0xseif-code/vexor/cmd/vexor@latest
```

---

## Overview

| Module | Function | Core Technique / Engine |
|---|---|---|
| 🔍 **Subdomain** | Domain Reconnaissance | Active DNS Worker-Pool + Passive crt.sh |
| 📁 **Directory** | Endpoint Discovery | Recursive Scanning + Smart Baseline Filtering |
| 🎯 **Fuzzing** | Parameter Mining | Multi-position markers (`FUZZ`) + Response Analysis |
| 💉 **SQLi** | SQL Injection Testing | Wrapper for sqlmap (industry standard) |
| 💬 **Interactive UX** | Guided Operation | Batch-aware Prompt Engine, Live Progress, Instrumentation Summary |
| 📚 **Wordlists** | Cache Manager | Auto on-demand SecLists downloader (`~/.vexor/`) |

---

## Installation

### Method 1 — Go Install (Recommended)

Requires **Go 1.21+**:

```bash
go install github.com/0xseif-code/vexor/cmd/vexor@latest

# make sure $GOPATH/bin is on your PATH
export PATH="$PATH:$(go env GOPATH)/bin"    # Linux / macOS
```

### Method 2 — From Source

```bash
git clone https://github.com/0xseif-code/vexor.git
cd vexor

make build          # Linux/macOS → ./bin/vexor
# or: go build -o vexor ./cmd/vexor

# Windows
go build -o vexor.exe ./cmd/vexor
```

### Method 3 — Release Binary

Grab a prebuilt binary for your platform from the
[Releases](https://github.com/0xseif-code/vexor/releases) page. Assets follow
`vexor-<os>-<arch>[.exe]`:

```bash
curl -sL -o vexor https://github.com/0xseif-code/vexor/releases/download/v1.0.0/vexor-linux-amd64
chmod +x vexor && sudo mv vexor /usr/local/bin/
```

### Self-update

Already-installed binaries can upgrade themselves from the CLI (Linux/macOS):

```bash
vexor update --check     # compare the local version against the latest release
vexor update             # self-update in place
vexor update --force     # reinstall even when the versions already match
```

`vexor update` first tries `go install`, then a platform release-asset
download (`vexor-<os>-<arch>`), then a `git pull && go build` from a local
checkout of the repository.

First run — pull the wordlist cache once, then go:

```bash
vexor update-wordlists
vexor subdomain -d example.com
```

---

## Command Reference

All commands share the global flags below. Banner, logs, and progress go to
`stderr`; findings go to **stdout** (monochrome, pipe-friendly) — so
`vexor dir -u URL | tee results.txt` just works.

| Flag | Shorthand | Type | Description | Default |
|---|---|---|---|---|
| `--timeout` | | int | Global request timeout (seconds) | `8` |
| `--threads` | | int | Global concurrency threads | `10` |
| `--batch` | | bool | Never ask for input; use default answers | `false` |
| `--proxy` | | string | HTTP/SOCKS5 proxy, `http://127.0.0.1:8080` | |
| `--headers` | | stringarray | Custom header, repeatable | |
| `--format` | | string | Output: `plain`, `json`, `csv` | `plain` |
| `--output` | | string | Also write results to a file | |
| `--silent` | | bool | Suppress banner/progress/info logs | `false` |
| `--no-color` | | bool | Disable ANSI colors | `false` |

### `subdomain` — Enumerate subdomains

Active DNS brute-force + passive crt.sh lookups, deduplicated across sources.

| Flag | Shorthand | Type | Description | Default |
|---|---|---|---|---|
| `--domain` | `-d` | string | Target domain (required unless `-l`) | |
| `--list` | `-l` | string | File of target domains, one per line | |
| `--size` | `-s` | string | Wordlist size: `small`, `medium`, `large` | `medium` |
| `--wordlist` | `-w` | string | Custom wordlist path (overrides `-s`) | |
| `--resolvers` | | stringarray | Custom DNS resolvers, repeatable | |
| `--active-only` | | bool | Skip crt.sh, DNS brute-force only | `false` |
| `--passive-only` | | bool | Skip DNS, crt.sh only | `false` |

```bash
vexor subdomain -d example.com -s large --threads 150
vexor subdomain -l domains.txt -s medium
vexor subdomain -d example.com --resolvers 8.8.8.8:53 --resolvers 1.1.1.1:53 --active-only
vexor subdomain -d example.com -w my-subdomains.txt --format json | jq -r '.subdomain'
```

```text
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

### `dir` — Discover files and directories

Wordlist-driven endpoint probing with soft-404 calibration, recursion, and
extension presets.

| Flag | Shorthand | Type | Description | Default |
|---|---|---|---|---|
| `--url` | `-u` | string | Target URL, e.g. `https://example.com/` (required) | |
| `--size` | `-s` | string | Wordlist size | `medium` |
| `--wordlist` | `-w` | string | Custom wordlist path (overrides `-s`) | |
| `--ext` | `-x` | stringslice | Extensions/presets, e.g. `php,asp,all` | |
| `--recursion` | `-r` | bool | Recurse into discovered directories | `false` |
| `--depth` | | int | Max recursion depth (with `-r`) | `2` |
| `--match-status` | | string | Only report these codes | |
| `--filter-status` | | string | Exclude these codes | |
| `--filter-size` | | string | Exclude these byte sizes | |
| `--rate` | | int | Max requests/second (`0` = unlimited) | `0` |

```bash
vexor dir -u https://example.com -x php,js -r --depth 2
vexor dir -u https://example.com -x all --filter-status 404 --filter-size 4297
vexor dir -u https://example.com --match-status 200,301,302 --rate 100
```

```text
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

### `fuzz` — Fuzz request parameters

Mark injection points with `FUZZ` in the URL, headers, or body. Responses are
filtered by status, size, and regex.

| Flag | Shorthand | Type | Description | Default |
|---|---|---|---|---|
| `--url` | `-u` | string | Target URL with `FUZZ` marker (required) | |
| `--method` | `-X` | string | HTTP method | `GET` |
| `--data` | `-d` | string | Request body (FUZZ markers supported) | |
| `--wordlist` | `-w` | string | Fuzz preset or custom wordlist path | `parameters` |
| `--match-status` | | string | Only report these codes | |
| `--filter-status` | | string | Exclude these codes | |
| `--filter-size` | | string | Exclude these byte sizes | |
| `--match-regex` | | string | Only report bodies matching this regex | |
| `--filter-regex` | | string | Exclude bodies matching this regex | |
| `--delay` | | duration | Delay between requests, e.g. `100ms` | `0` |

Wordlist presets: `parameters`, `extensions`, `usernames`, `passwords`,
`passwords-large`, `endpoints` — or pass any file path as `-w`.

```bash
vexor fuzz -u "https://example.com/api/query?id=FUZZ" -w parameters --match-status 200,500
vexor fuzz -u "http://target/login" -d "user=FUZZ&pass=x" -X POST -w usernames
vexor fuzz -u "https://example.com/search?s=FUZZ" --filter-size 0 --filter-regex "no results"
vexor fuzz -u "https://example.com/page?q=FUZZ" --delay 100ms --match-regex "SQL syntax"
```

```text
$ vexor fuzz -u "https://example.com/api/query?id=FUZZ" -w parameters --match-status 200,500
[*] starting fuzzing GET https://example.com/api/query?id=FUZZ (threads=50, wordlist=parameters)
[200] https://example.com/api/query?id=admin (id=admin)
[200] https://example.com/api/query?id=debug (id=debug)
[500] https://example.com/api/query?id=__proto__ (id=__proto__)
...
[+] fuzzing complete: 3 hits, 1411/1411 checked, 0 errors in 41.7s
```

### `sqli` — SQL injection testing

`vexor sqli` is a wrapper around sqlmap — the industry-standard SQL injection
tool. Vexor does not ship its own SQLi engine.

**Why sqlmap:**
- Battle-tested across thousands of engagements
- Supports every DBMS, technique, and injection type
- Vexor focuses on what it does best: recon and fuzzing

**Requirements:** sqlmap must be installed and on PATH.

```bash
# Install sqlmap
sudo apt install sqlmap          # Debian/Kali
sudo pacman -S sqlmap            # Arch
pipx install sqlmap              # pipx
```

| Flag | Shorthand | Type | Description | Default |
|---|---|---|---|---|
| `--url` | `-u` | string | Target URL | |
| `--request` | `-r` | string | Burp-style raw HTTP request file | |
| `--param` | `-p` | string | Only test this parameter | |
| `--database` | `-D` | string | Database name | |
| `--table` | `-T` | string | Table name | |
| `--column` | `-C` | stringslice | Columns to dump (repeatable) | |
| `--data` | | string | POST data string | |
| `--cookie` | | string | HTTP cookie header | |
| `--headers` | | stringarray | Custom header (repeatable) | |
| `--proxy` | | string | HTTP/SOCKS5 proxy URL | |
| `--level` | | int | Test intensity (1-5) | `1` |
| `--risk` | | int | Payload risk (1-3) | `1` |
| `--threads` | | int | Concurrent requests | `5` |
| `--technique` | | string | Techniques: `BEUSTQ` | |
| `--dbms` | | string | Force DBMS type | |
| `--dbs` | | bool | Enumerate databases | `false` |
| `--tables` | | bool | Enumerate tables | `false` |
| `--columns` | | bool | Enumerate columns | `false` |
| `--dump` | | bool | Dump table entries | `false` |
| `--current-user` | | bool | Enumerate current DBMS user | `false` |
| `--current-db` | | bool | Enumerate current database | `false` |
| `--is-dba` | | bool | Check DBA privileges | `false` |
| `--passwords` | | bool | Enumerate password hashes | `false` |
| `--batch` | | bool | Non-interactive mode | `true` |
| `--random-agent` | | bool | Random HTTP User-Agent | `true` |
| `--tamper` | | string | Tamper script(s) | |
| `--forms` | | bool | Parse and test forms | `false` |
| `--crawl` | | int | Crawl depth | `0` |
| `--os-shell` | | bool | Interactive OS shell | `false` |
| `--sql-shell` | | bool | Interactive SQL shell | `false` |
| `--extra` | | stringslice | Extra args passed directly to sqlmap | |

```bash
# Basic scan
vexor sqli -u "https://target.com/page?id=1"

# Enumerate databases
vexor sqli -u "https://target.com/page?id=1" --dbs

# Dump a table
vexor sqli -u "https://target.com/page?id=1" -D shop -T users --dump

# From a raw request file
vexor sqli -r request.txt --dump --batch

# With tamper and higher level
vexor sqli -u "https://target.com/page?id=1" --tamper=space2comment --level 3
```

### `update` — Self-update the binary

```bash
vexor update --check     # only compare local vs latest release
vexor update             # install the latest release in place
vexor update --force     # reinstall even when versions match
```

Checks `https://api.github.com/repos/0xseif-code/vexor/releases/latest` (tags
API as a fallback), then installs via `go install`, a `vexor-<os>-<arch>`
release-asset download, or a source rebuild — first strategy to succeed wins.

```text
$ vexor update --check
[+] Vexor is up to date: v1.0.0

$ vexor update
[*] [update] tier 1: go install github.com/0xseif-code/vexor/cmd/vexor@latest
[+] updated v1.0.0 -> v1.0.1 via go install
[i] new binary: /home/user/go/bin/vexor
[!] restart Vexor to start using the new version
```

### `update-wordlists` — Manage the local cache

```bash
vexor update-wordlists
```

Downloads and integrity-checks the SecLists mirror into `~/.vexor/wordlists`.
Run once after installing, then any time you want fresh data.

```text
$ vexor update-wordlists
[*] re-downloading all wordlists into ~/.vexor/wordlists
[*] downloading...  65.30% (18.4 MB / 28.2 MB)
[+] wordlist cache updated: 3 files in 46.8s
[i]   directory/medium    8.2 MB  sha256=9f1e4c22a1b3
[i]   subdomain/large    14.3 MB  sha256=4c8d0e71f5a2
[i]   fuzz/parameters     5.7 MB  sha256=b2a9d0134e6e
```

---

## Wordlists & Advanced Configuration

- **Cache location:** `~/.vexor/wordlists/` — auto-downloaded on first use,
  re-fetched with `vexor update-wordlists`.
- **Size presets** (`-s`): `small`, `medium`, `large`. `subdomain`, `dir`,
  and `fuzz` pick sensible defaults per module.
- **Fuzz presets** (`-w`): `parameters`, `extensions`, `usernames`,
  `passwords`, `passwords-large`, `endpoints`.
- **Custom wordlists** (`-w /path/to/file.txt`): any local file, one word per
  line — overrides the size preset.

Output formats are per-scan:

```bash
vexor subdomain -d example.com --format json | jq -r '.subdomain'
vexor dir -u https://example.com --format csv -o results.csv
vexor sqli -u "https://example.com/page?id=1" | tee sqli.log
```

---

## Disclaimer

> **Use responsibly. Authorized testing only.**
>
> Vexor is an offensive security tool. Only use it against systems you own or
> have written permission to test. Unauthorized access to computer systems is
> illegal in most jurisdictions. The author assumes no liability for misuse.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 0xseif-code.