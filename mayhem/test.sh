#!/usr/bin/env bash
# RUNS the tests built by mayhem/build.sh: upstream's network-free unit tests (test_simple,
# test_auth_keyboard_info_request) plus a known-answer probe whose output is diffed against golden values.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T=build/tests
for b in "$T/selftest" "$T/tests/test_simple" "$T/tests/test_auth_keyboard_info_request"; do
  [ -x "$b" ] || { echo "missing $b (mayhem/build.sh should have built it)" >&2; emit_ctrf libssh2-kat 0 1; exit 1; }
done

passed=0; failed=0

# Upstream unit tests: they print nothing on success, so only the exit status is checked here; the
# behavioral assertions are the golden-output probe below.
for t in test_simple test_auth_keyboard_info_request; do
  if (cd tests && srcdir="$SRC/tests" "$SRC/$T/tests/$t") >/dev/null 2>&1; then passed=$((passed+1)); else echo "FAIL $t"; failed=$((failed+1)); fi
done

EXPECTED='base64 rc=0 len=5 val=fnord
add rc=0
check-match rc=0
check-unknown rc=2
check-mismatch rc=1
write rc=0 len=29 line=example.com ssh-rsa AAAA cmt
readline rc=0
get rc=0 name=host2.org key=AAAA
kex-has-curve25519=1
pref-good rc=0
pref-bad rc=-33'
ACTUAL=$("$T/selftest" 2>&1)
while IFS= read -r line; do
  if grep -qxF -- "$line" <<<"$ACTUAL"; then passed=$((passed+1)); else echo "FAIL expected line: $line"; failed=$((failed+1)); fi
done <<<"$EXPECTED"

emit_ctrf libssh2-kat "$passed" "$failed"
