#!/usr/bin/env bash
# Unit tests for version classification. No PHP binary required.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT/bin/php2shell-hotfix.sh"

fail=0
check() {
  local ver="$1" want="$2" got
  got=$(classify_version "$ver")
  if [[ "$got" != "$want" ]]; then
    printf 'FAIL %s -> %s (want %s)\n' "$ver" "$got" "$want"
    fail=1
  else
    printf 'ok   %s -> %s\n' "$ver" "$got"
  fi
}

check "8.5.12" patched
check "8.5.11" vulnerable
check "8.5.0" vulnerable
check "8.4.27" patched
check "8.4.26" vulnerable
check "8.3.36" patched
check "8.3.35" vulnerable
check "8.2.35" patched
check "8.2.34" vulnerable
check "8.1.33" eol
check "8.0.30" eol
check "7.4.33" eol
check "5.6.40" eol
check "8.6.0" unknown
check "9.0.0" unknown
check "not-a-version" unknown

target=$(fixed_target_for "8.3.12")
[[ "$target" == "8.3.36" ]] || { printf 'FAIL target %s\n' "$target"; fail=1; }

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
printf 'all classification tests passed\n'
