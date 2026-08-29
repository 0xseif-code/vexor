#!/usr/bin/env bash
set -euo pipefail

prefix="${PREFIX:-/usr/local/bin}"

if ! command -v go >/dev/null 2>&1; then
    echo "error: go is not installed" >&2
    exit 1
fi

echo "[*] building vexor"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
go build -ldflags "-s -w" -o "$tmp/vexor" ./cmd/vexor

echo "[*] installing to $prefix/vexor"
install -Dm755 "$tmp/vexor" "$prefix/vexor"

echo "[+] done, running --help"
vexor --help