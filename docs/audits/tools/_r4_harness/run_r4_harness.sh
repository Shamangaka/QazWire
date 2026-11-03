#!/usr/bin/env bash
# Reproduce the R4 evidence against PR #8 (feature/m1-4-synthetic-key-lifecycle) without
# touching the owner's branch: everything runs on temporary copies.
# Usage: run_r4_harness.sh <path-to-QazWire-checkout> [git-ref]
set -euo pipefail
REPO=${1:?path to QazWire checkout}
REF=${2:-origin/feature/m1-4-synthetic-key-lifecycle}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
git -C "$REPO" archive "$REF" internal/qazwireexp | tar -x -C "$W"
printf 'module harness\n\ngo 1.23\n' > "$W/go.mod"
echo "slot.go blob: $(git -C "$REPO" rev-parse "$REF":internal/qazwireexp/keylab/slot.go)"
cp "$HERE/keylab_blackbox/r4_blackbox_test.go" "$W/internal/qazwireexp/keylab/"
python3 -I "$HERE/keylab_instrumented/make_instrumented.py" \
  "$W/internal/qazwireexp/keylab/slot.go" "$W/internal/qazwireexp/keylab_instr"
cp "$HERE/keylab_instrumented/r4_interleave_test.go" "$W/internal/qazwireexp/keylab_instr/"
(cd "$W" && go vet -tags qazwire_exp ./... \
  && go test -race -count=1 -tags qazwire_exp -v ./internal/qazwireexp/keylab ./internal/qazwireexp/keylab_instr \
     | grep -E 'CONFIRMED|rounds=|^--- |^ok|^FAIL')
python3 -I "$HERE/model/klm_model.py"
(cd "$HERE/klm15ref" && go vet ./... && go test -race -count=1 -v ./... | grep -E 'rounds|^--- |^ok|^FAIL')
