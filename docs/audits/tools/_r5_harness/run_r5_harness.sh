#!/usr/bin/env bash
# Reproduce the R5 evidence against PR #17 (M1.6.1) without touching any owner branch.
# Usage: run_r5_harness.sh <path-to-QazWire-checkout> [commit]
#   MODEL=1  additionally runs the klm16 state model and the mutation suite (minutes)
# Works on temporary `git archive` copies of internal/qazwireexp as a stand-alone
# module with the same import path; klm16 and staged16 use only the standard library.
set -euo pipefail
REPO=${1:?path to QazWire checkout}
REF=${2:-aa27727acbb700d622e562da350e684d4b8d11ee}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mk() { # $1 = dir
  mkdir -p "$1"
  git -C "$REPO" archive "$REF" internal/qazwireexp | tar -x -C "$1"
  printf 'module golang.zx2c4.com/wireguard\n\ngo 1.23\n' > "$1/go.mod"
}
show() { grep -E 'CONFIRMED|VERIFIED-in-test|^--- FAIL|^ok|^FAIL' || true; }
K=internal/qazwireexp/klm16
D=internal/qazwireexp/staged16
echo "PR #17 @ $REF"
echo "klm.go blob: $(git -C "$REPO" rev-parse "$REF:$K/klm.go") (expected 6274939...)"
echo "supervisor_linux.go blob: $(git -C "$REPO" rev-parse "$REF:$D/supervisor_linux.go") (expected 372b93a...)"

echo "== 1) UNMODIFIED code: owner tests + R5 demonstrations and interleavings (-race, 3 runs)"
mk "$W/orig"
cp "$HERE"/klm16/r5_blackbox_test.go "$HERE"/klm16/r5_external_test.go "$HERE"/klm16/r5_interleave_test.go "$W/orig/$K/"
cp "$HERE"/staged16/r5_staged_test.go "$W/orig/$D/"
(cd "$W/orig" && test -z "$(gofmt -l internal/qazwireexp)" && go vet -tags qazwire_exp ./internal/qazwireexp/... \
  && go test -race -count=3 -tags qazwire_exp -v ./$K ./$D | show)

echo "== 2) PATCHED copy: owner tests + R5 tests not affected by the patches + fix tests (-race, 10 runs)"
mk "$W/fix"
(cd "$W/fix" && for p in "$HERE"/patches/*.patch; do patch -s -p1 < "$p"; done)
cp "$HERE"/klm16/*.go "$W/fix/$K/"
cp "$HERE"/staged16/*.go "$W/fix/$D/"
SKIP='TestR5_01_|TestR5_03_|TestR5_04_|TestR5_07_|TestR5_08_'
(cd "$W/fix" && test -z "$(gofmt -l internal/qazwireexp)" && go vet -tags qazwire_exp ./internal/qazwireexp/... \
  && go test -race -count=10 -tags qazwire_exp -skip "$SKIP" ./$K ./$D | show)
echo "== 2b) the defect demonstrations on the PATCHED copy (expected: FAIL = not reproduced)"
(cd "$W/fix" && go test -count=1 -tags qazwire_exp -v -run "$SKIP" ./$K ./$D | show) || true

if [ "${MODEL:-0}" = 1 ]; then
  echo "== 3) independent klm16 model (aa27727 and patch) and mutation testing"
  python3 -I "$HERE/model/klm16_model.py" | grep -E '^###|states|VIOLATED|REACHABLE|final'
  python3 -I "$HERE/model/klm16_model.py" --patched | grep -E '^###|states|VIOLATED|REACHABLE|final'
  python3 -I "$HERE/model/klm16_model.py" --mutants | grep -E '=> mutant'
fi
