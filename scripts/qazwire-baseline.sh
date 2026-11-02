#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Reproducible, non-privileged upstream compatibility check for research use.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  printf 'ERROR: git is required\n' >&2
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  printf 'ERROR: Go is required\n' >&2
  exit 1
fi
root="$(git rev-parse --show-toplevel)"
cd "$root"

if [ ! -f go.mod ]; then
  printf 'ERROR: no go.mod at repository root\n' >&2
  exit 1
fi

printf '=== QazWire M0 Baseline ===\n'
printf 'repository=%s\n' "$root"
printf 'commit=%s\n' "$(git rev-parse HEAD)"
printf 'branch=%s\n' "$(git branch --show-current)"
printf 'go=%s\n' "$(go version)"
printf 'os=%s\n' "$(uname -s)"
printf 'arch=%s\n' "$(uname -m)"
printf 'time_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if ! git diff --quiet || ! git diff --cached --quiet; then
  printf 'WARNING: worktree has uncommitted tracked changes; result is not an immutable baseline\n' >&2
fi

printf '\n=== Go test ===\n'
go test ./...

printf '\n=== Go vet ===\n'
go vet ./...

if [ "${QAZWIRE_RACE:-0}" = "1" ]; then
  printf '\n=== Go race tests (CGO required) ===\n'
  go test -race ./...
fi

printf '\nPASS: M0 static/unit baseline checks completed.\n'
printf 'NOTE: no network namespace, on-wire interoperability, tunnel, or cryptographic conformity test was run.\n'
