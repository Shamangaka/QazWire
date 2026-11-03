#!/usr/bin/env bash
# Reproduce the R4.1 evidence against PR #11 without touching the owner's branch.
# Usage: run_r4_1_harness.sh <path-to-QazWire-checkout> [commit]
set -euo pipefail
REPO=${1:?path to QazWire checkout}
REF=${2:-f5e078c592a3e558912382d0805ec108e07c86f3}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mk() { # $1 = dir
  mkdir -p "$1"
  git -C "$REPO" archive "$REF" internal/qazwireexp | tar -x -C "$1"
  printf 'module harness\n\ngo 1.23\n' > "$1/go.mod"
}
echo "session.go blob: $(git -C "$REPO" rev-parse "$REF":internal/qazwireexp/sessionlab/session.go)"
# 1) defects on the UNMODIFIED code
mk "$W/orig"
cp "$HERE/sessionlab_blackbox/r41_blackbox_test.go" "$W/orig/internal/qazwireexp/sessionlab/"
(cd "$W/orig" && go vet -tags qazwire_exp ./... \
  && go test -race -count=1 -tags qazwire_exp -v ./internal/qazwireexp/sessionlab \
     | grep -E 'CONFIRMED|rounds|^--- FAIL|^ok|^FAIL')
# 2) minimal fix: owner tests + fix tests + stress on the PATCHED copy
mk "$W/fix"
(cd "$W/fix" && patch -s -p1 < "$HERE/sessionlab_fix/session_r41_minimal_fix.patch")
cp "$HERE/sessionlab_fix/r41_fixed_test.go" "$W/fix/internal/qazwireexp/sessionlab/"
(cd "$W/fix" && gofmt -l internal/qazwireexp/sessionlab && go vet -tags qazwire_exp ./... \
  && go test -race -count=1 -tags qazwire_exp -v ./internal/qazwireexp/sessionlab \
     | grep -E 'rounds|^--- |^ok|^FAIL')
# 3) model of the implementation (+ mutants)
python3 -I "$HERE/model/sessionlab_model.py" | grep -E '^###|states|VIOLATED|deadlock|final|REACHABLE'
python3 -I "$HERE/model/sessionlab_model.py" --mutants | grep -E '=> mutant'
# 4) race-detector blind spot for clear()
(cd "$HERE/racechk" && go test -race -count=1 -v . | grep -E '^--- |^ok') || true
(cd "$HERE/racechk" && RACECHK_CONTROL=1 go test -race -count=1 -run Indexed . 2>&1 | grep -m1 'DATA RACE') || true
