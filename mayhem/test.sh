#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

T="$SRC/build-tests"
[ -x "$T/dillo_kat" ] || { echo "build-tests/dillo_kat missing: run mayhem/build.sh" >&2; exit 2; }
passed=0; failed=0
# Upstream unit tests (test/unit/Makefile.am TESTS); each exits non-zero on a failed assertion.
for t in containers disposition identity liang notsosimplevector shapes unicode_test; do
  if [ ! -x "$T/test/unit/$t" ]; then echo "missing unit test $t" >&2; failed=$((failed+1)); continue; fi
  if (cd "$T/test/unit" && "$T/test/unit/$t") >/tmp/dillo-unit-$t.log 2>&1; then
    echo "ok unit/$t"; passed=$((passed+1))
  else
    echo "not ok unit/$t"; cat /tmp/dillo-unit-$t.log; failed=$((failed+1))
  fi
done
# Known-answer checks: every expected case must print "ok <name>".
KAT_CASES="url_relative url_dotsegments url_query url_netpath url_decode_hex hsts_subdomain hsts_other
  hsts_upgrade ctype_major ctype_minor ctype_charset sniff_gif sniff_html chunked_body chunked_finished
  charset_latin1"
out="$("$T/dillo_kat" 2>&1)"; echo "$out"
for c in $KAT_CASES; do
  if grep -qx "ok $c" <<<"$out"; then passed=$((passed+1)); else echo "FAILED kat/$c"; failed=$((failed+1)); fi
done
emit_ctrf "dillo-unit+kat" "$passed" "$failed" 0
