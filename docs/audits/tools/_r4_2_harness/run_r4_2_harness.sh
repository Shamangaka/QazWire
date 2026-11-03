#!/usr/bin/env bash
# Reproduce the R4.2 evidence against Draft PR #13 without touching the owner's branch.
# Usage: run_r4_2_harness.sh <path-to-QazWire-checkout> [commit]
#   MODEL=1  additionally runs the state model (hours on 2 vCPU; see model/README in the report)
# Every step works on temporary copies extracted with `git archive`.
set -euo pipefail
REPO=${1:?path to QazWire checkout}
REF=${2:-45984d70b46c86c87bad85d3825a736c75994f6a}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
PKG=internal/qazwireexp/sessionlab
mk() { # $1 = dir: copy of internal/qazwireexp at REF as a stand-alone module
  mkdir -p "$1"
  git -C "$REPO" archive "$REF" internal/qazwireexp | tar -x -C "$1"
  printf 'module harness\n\ngo 1.23\n' > "$1/go.mod"
}
instr() { # $1 = module dir: build the instrumented copy next to the package
  python3 -I "$HERE/sessionlab_instr/make_instrumented.py" "$1/$PKG/session.go" "$1/${PKG}_instr"
  cp "$1/$PKG/session_test.go" "$HERE/sessionlab_instr/r42_interleave_test.go" "$1/${PKG}_instr/"
}
show() { grep -E 'CONFIRMED|FIX R42|rounds|^--- FAIL|^ok|^FAIL' || true; }
echo "PR #13 @ $REF; session.go blob: $(git -C "$REPO" rev-parse "$REF:$PKG/session.go") (expected 0305fa2...)"

echo "== 1) defects on the UNMODIFIED code (black box, -race, 3 runs)"
mk "$W/orig"
cp "$HERE/sessionlab_blackbox/r42_blackbox_test.go" "$W/orig/$PKG/"
instr "$W/orig"
(cd "$W/orig" && go vet -tags qazwire_exp ./... \
  && go test -race -count=3 -tags qazwire_exp -v ./$PKG ./${PKG}_instr | show)

echo "== 1b) fix interleavings on the UNMODIFIED code (expected: FAIL)"
cp "$HERE/sessionlab_instr/r42_fix_interleave_test.go" "$W/orig/${PKG}_instr/"
(cd "$W/orig" && go test -count=1 -tags qazwire_exp -run 'TestR42IFix' -v ./${PKG}_instr | show) || true

echo "== 2) PATCHED copy: owner tests + R4.2 tests + fix tests (-race, 10 runs)"
mk "$W/fix"
(cd "$W/fix" && patch -s -p1 < "$HERE/sessionlab_fix/session_r42_minimal_fix.patch")
cp "$HERE/sessionlab_blackbox/r42_blackbox_test.go" "$HERE/sessionlab_fix/r42_fix_test.go" "$W/fix/$PKG/"
instr "$W/fix"
cp "$HERE/sessionlab_instr/r42_fix_interleave_test.go" "$W/fix/${PKG}_instr/"
(cd "$W/fix" && test -z "$(gofmt -l internal/qazwireexp)" && go vet -tags qazwire_exp ./... \
  && go test -race -count=10 -tags qazwire_exp \
       -skip 'TestR42_04_|TestR42_05_|TestR42_10_|TestR42I_07_|TestR42I_06b_' ./$PKG ./${PKG}_instr | show)
echo "== 2b) the five defect demonstrations on the PATCHED copy (expected: FAIL = not reproduced)"
(cd "$W/fix" && go test -count=1 -tags qazwire_exp -v \
   -run 'TestR42_04_|TestR42_05_|TestR42_10_|TestR42I_07_|TestR42I_06b_' ./$PKG ./${PKG}_instr | show) || true

if [ "${MODEL:-0}" = 1 ]; then
  echo "== 3) state model of 45984d7 and of the patch, mutation testing"
  M="$HERE/model/m152_model.py"
  for c in C3 C4 C6 C8 C5 C1r C2r C7s; do python3 -I "$M" --fast "$c"; done
  for c in C3 C4 C6 C5 C1r C7s; do python3 -I "$M" --patched --fast "$c"; done
  python3 -I "$M" --timeouts --fast C3
  python3 -I "$M" --traces C6 C4; python3 -I "$M" --patched --traces C4
  python3 -I "$M" --mutants | grep -E '=> mutant'
fi
