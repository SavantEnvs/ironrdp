#!/usr/bin/env bash
#
# ironrdp/mayhem/test.sh (mining layer, BASE def44ec) — RUN the project's own (scoped) cargo test suite AND the KAT probe, and
# emit a CTRF summary. exit 0 iff nothing failed.
#
# PATCH-grade oracle (SPEC §6.3). Two parts, and the SECOND is the load-bearing one:
#
#  1) `cargo test -p ironrdp-cliprdr-format -p ironrdp-cliprdr -p ironrdp-testsuite-core` — the
#     project's OWN known-answer suite for the clipboard crates (incl. the CF_DIB/CF_DIBV5/CF_HTML
#     format conversions and PDU encode/decode assertions). It asserts real behaviour.
#
#  2) The KAT probe /mayhem/kat — SPEC §6.3 forbids relying on `cargo test` ALONE as the oracle.
#     /mayhem/kat is a small, dynamically-linked probe (build.sh asserts `file` reports
#     "dynamically linked") that converts a real CF_DIB fixture to PNG and asserts the IHDR
#     width/height, and asserts a DIB header with an oversized biWidth is rejected, printing exact
#     `KAT_<NAME>=<value>` lines. A neutered binary (the sabotage shim `_exit(0)`s it before any of
#     this runs) prints nothing, so every `grep -qxF` below fails.
#
# This script only RUNS things; mayhem/build.sh did the building.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

export RUSTUP_HOME="${RUSTUP_HOME:-/opt/toolchains/rust/rustup}"
export CARGO_HOME="${CARGO_HOME:-/opt/toolchains/rust/cargo}"
export PATH="$CARGO_HOME/bin:$PATH"
: "${SRC:=/mayhem}"
cd "$SRC"

STABLE_TOOLCHAIN="1.94.1"   # pinned upstream: rust-toolchain.toml — matches the oracle build in build.sh

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

PASSED=0; FAILED=0; SKIPPED=0

# ── 1) the project's own (scoped) cargo test suite ─────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not available — cannot run the test suite" >&2
  emit_ctrf "cargo-test+kat" 0 1 0; exit 2
fi

echo "=== running: cargo +$STABLE_TOOLCHAIN test (scoped to the fuzzed crates) ==="
OUT="$SRC/mayhem-build-test.log"
mkdir -p "$(dirname "$OUT")"
rustup run "$STABLE_TOOLCHAIN" cargo test --no-fail-fast \
  -p ironrdp-cliprdr-format -p ironrdp-cliprdr -p ironrdp-testsuite-core \
  > "$OUT" 2>&1
rc=$?
tail -60 "$OUT" || true

# Every `test result: ok/FAILED. P passed; F failed; I ignored; ...` line (one per test binary)
# reports real counts; sum them.
while read -r p f i; do
  PASSED=$(( PASSED + p )); FAILED=$(( FAILED + f )); SKIPPED=$(( SKIPPED + i ))
done < <(grep -E '^test result:' "$OUT" | sed -E 's/^test result: [a-zA-Z]+\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;.*/\1 \2 \3/')

if [ "$(( PASSED + FAILED + SKIPPED ))" -eq 0 ]; then
  echo "FAIL: no 'test result:' lines parsed — the suite did not run (cargo exit $rc)" >&2
  emit_ctrf "cargo-test+kat" 0 1 0; exit 1
fi
# Upstream tests that already fail on this old commit under the current toolchain are counted as
# skipped, by exact name; any other failure still fails.
#   pcb::truncated — its expect! snapshot embeds the type name as printed by an older rustc
#   (`PduDecode>` vs `PduDecode<'_>>`).
SKIP_KNOWN_FAIL="pcb::truncated"
KNOWN=0
for t in $SKIP_KNOWN_FAIL; do
  if grep -qE "^test $t \.\.\. FAILED$" "$OUT"; then KNOWN=$(( KNOWN + 1 )); fi
done
FAILED=$(( FAILED - KNOWN )); SKIPPED=$(( SKIPPED + KNOWN ))
# A non-zero cargo exit with no failure beyond the known ones means a build/harness error: stay honest.
if [ "$rc" -ne 0 ] && [ "$KNOWN" -eq 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=$(( FAILED + 1 )); fi
if [ "$rc" -ne 0 ] && [ "$KNOWN" -gt 0 ] && [ "$FAILED" -eq 0 ] && grep -qE '^error: could not compile' "$OUT"; then FAILED=$(( FAILED + 1 )); fi

# ── 2) the KAT probe (sabotage-detecting; see header) ────────────────────────────────────────
# UNCONDITIONAL by design: a missing binary is a FAILURE, never a skip. A `[ -x ... ]` guard here
# is how a probe silently stops running and the oracle quietly degrades.
echo "=== KAT probe: /mayhem/kat (dynamically linked; asserts parsed VALUES) ==="
KAT_OUT="$(/mayhem/kat 2>&1)"; kat_rc=$?
echo "$KAT_OUT"

kat_expect() {
  local label="$1" line="$2"
  if printf '%s\n' "$KAT_OUT" | grep -qxF "$line"; then
    echo "KAT PASS: $label"
    PASSED=$(( PASSED + 1 ))
  else
    echo "KAT FAIL: $label — expected exact line: $line" >&2
    FAILED=$(( FAILED + 1 ))
  fi
}

if [ "$kat_rc" -ne 0 ]; then
  echo "KAT FAIL: /mayhem/kat exited $kat_rc (neutered, missing, or a check panicked)" >&2
  FAILED=$(( FAILED + 1 ))
fi

# Expected values, computed once (offline, by hand) from mayhem/kat/src/main.rs's fixed inputs —
# see that file's doc comment for what each check exercises.
kat_expect "CF_DIB->PNG width (from IHDR)"                      'KAT_CLIPRDR_DIB_TO_PNG_WIDTH=15'
kat_expect "CF_DIB->PNG height (from IHDR)"                     'KAT_CLIPRDR_DIB_TO_PNG_HEIGHT=5'
kat_expect "CF_DIB with biWidth=20000 is rejected"              'KAT_CLIPRDR_WIDE_DIB_REJECTED=1'

emit_ctrf "cargo-test+kat" "$PASSED" "$FAILED" "$SKIPPED"
