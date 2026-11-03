#!/usr/bin/env bash
# Independent R4.2 negative harness. Read-only for the provided repository.
set -euo pipefail
ROOT="$(cd "${1:?usage: run_r42.sh /path/to/QazWire}" && pwd)"
AUDIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET='45984d70b46c86c87bad85d3825a736c75994f6a'

if ! git -C "$ROOT" cat-file -e "$TARGET^{commit}" 2>/dev/null; then
  echo "ERROR: target SHA not available locally; fetch feature/m1-5-2-r41-owned-providers first" >&2
  exit 2
fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# Git archive avoids checkout changes and leaves all owner worktrees untouched.
git -C "$ROOT" archive "$TARGET" | tar -x -C "$TMP"
cd "$TMP"
printf 'Audit target: %s\n' "$TARGET"
printf 'Go version: %s\n' "$(go version)"
printf '\n[positive] unchanged tagged sessionlab (no audit tests)\n'
go test -tags qazwire_exp -race -count=1 ./internal/qazwireexp/sessionlab
cp "$AUDIT_DIR/r42_negative_test.go" internal/qazwireexp/sessionlab/r42_negative_test.go
for testcase in \
  TestR42_01_ProviderMaterialAliasMustNotBeAccepted \
  TestR42_01b_WipingOneProviderBreaksAnother \
  TestR42_02_PrunedKeysMustNotRemainInSliceCapacity; do
  printf '\n[negative] %s should FAIL on unmodified %s\n' "$testcase" "$TARGET"
  set +e
  go test -tags qazwire_exp -race -count=1 -run "^${testcase}$" -v \
    ./internal/qazwireexp/sessionlab >"$TMP/${testcase}.log" 2>&1
  status=$?
  set -e
  cat "$TMP/${testcase}.log"
  if [ "$status" -eq 0 ]; then
    echo "UNEXPECTED PASS: negative control did not reproduce" >&2
    exit 3
  fi
  case "$testcase" in
    TestR42_01b*) grep -q 'R42-01b first wipe invalidated second session' "$TMP/${testcase}.log" || exit 4;;
    TestR42_01*) grep -q 'R42-01 material alias accepted' "$TMP/${testcase}.log" || exit 4;;
    TestR42_02*) grep -q 'R42-02:' "$TMP/${testcase}.log" || exit 4;;
  esac
  echo "EXPECTED NEGATIVE REPRODUCED: $testcase"
done
printf '\nR4.2 NEGATIVE CONTROLS REPRODUCED (NOT product PASS)\n'
printf '\n[remediation] apply isolated R42-02 patch in TEMPORARY snapshot only\n'
patch -p1 < "$AUDIT_DIR/patches/r42_02_clear_retired_capacity.patch"
go test -tags qazwire_exp -race -count=1 \
  -run TestR42_02_PrunedKeysMustNotRemainInSliceCapacity -v \
  ./internal/qazwireexp/sessionlab
echo "R42-02 PATCHED CONTROL PASS; R42-01 remains a design blocker"
