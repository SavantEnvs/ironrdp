#!/usr/bin/env bash
#
# ironrdp/mayhem/test.sh — RUN the project's own (scoped) cargo test suite AND the KAT probe, and
# emit a CTRF summary. exit 0 iff nothing failed.
#
# PATCH-grade oracle (SPEC §6.3). Two parts, and the SECOND is the load-bearing one:
#
#  1) `cargo test -p ironrdp-core -p ironrdp-pdu -p ironrdp-graphics -p ironrdp-bulk
#     -p ironrdp-cliprdr-format -p ironrdp-cliprdr -p ironrdp-egfx -p ironrdp-testsuite-core` — the
#     project's OWN known-answer/property suite for the crates behind the five fuzzed surfaces
#     (~2166 tests: PDU encode/decode assertions, RLE/RDP6 bitmap round trips, NCRUSH/XCRUSH/MPPC
#     bulk-compression round trips, clipboard format conversions, plus upstream's own
#     `fuzz_regression` suite replaying the exact fixtures this repo also ships as fuzz seeds). This
#     asserts real behaviour, not "exits 0".
#
#  2) The KAT probe /mayhem/kat — SPEC §6.3 forbids relying on `cargo test` ALONE as the oracle.
#     `cargo test`'s compiled test binaries ARE dynamically linked (unlike Go's static test
#     binaries), so the verify-repo LD_PRELOAD sabotage shim CAN in principle neuter them directly —
#     but we do not rely on that alone, because `cargo test`'s own harness re-links/re-discovers
#     tests in a way that isn't a stable, independently-verifiable target for the shim across
#     toolchain versions (the same reasoning the zeekstd/cel-rust integrations in this fleet use).
#     /mayhem/kat is a small, purpose-built, dynamically-linked probe (build.sh asserts `file`
#     reports "dynamically linked", failing the build otherwise) that runs four fixed-input checks
#     straight against the fuzzed library code — RLE-decompress a real 64x64 tile fixture and
#     compare byte-for-byte against the committed expected fixture, NCRUSH round-trip a fixed
#     buffer and assert the compressed size + digest, encode+decode a `ConnectionRequest` PDU and
#     assert the decoded fields, and convert a real CF_DIB clipboard fixture to PNG and assert the
#     PNG signature + IHDR width/height — panicking (nonzero exit) on any mismatch and printing
#     exact `KAT_<NAME>=<value>` lines. A neutered binary (the sabotage shim `_exit(0)`s it before
#     any of this runs) prints nothing, so every `grep -qxF` below fails.
#
#     This has been verified BY HAND, not just trusted from the gate's printed line: build the
#     image, run this script normally (passes), then re-run it under the same LD_PRELOAD shim
#     verify-repo.sh uses and confirm the KAT lines are ABSENT and this script now exits non-zero.
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
  -p ironrdp-core -p ironrdp-pdu -p ironrdp-graphics -p ironrdp-bulk \
  -p ironrdp-cliprdr-format -p ironrdp-cliprdr -p ironrdp-egfx -p ironrdp-testsuite-core \
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
# A non-zero cargo exit with zero counted failures means a build/harness error: stay honest.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=$(( FAILED + 1 )); fi

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
kat_expect "RLE tile decompressed length (64x64 16bpp fixture)" 'KAT_RLE_TILE_DECOMPRESSED_LEN=8192'
kat_expect "RLE tile decompressed digest (FNV-1a64)"            'KAT_RLE_TILE_FNV1A64=c2b1714e02eb81ea'
kat_expect "NCRUSH compressed length (fixed repetitive input)"  'KAT_BULK_NCRUSH_COMPRESSED_LEN=226'
kat_expect "NCRUSH round-trip digest (FNV-1a64)"                'KAT_BULK_NCRUSH_ROUNDTRIP_FNV1A64=1eb87197cfb5d6e1'
kat_expect "ConnectionRequest encoded length"                   'KAT_PDU_CONNECTION_REQUEST_ENCODED_LEN=19'
kat_expect "ConnectionRequest decoded protocol bits (HYBRID|SSL)" 'KAT_PDU_CONNECTION_REQUEST_PROTOCOL_BITS=0x00000003'
kat_expect "CF_DIB->PNG output length"                          'KAT_CLIPRDR_DIB_TO_PNG_LEN=137'
kat_expect "CF_DIB->PNG width (from IHDR)"                      'KAT_CLIPRDR_DIB_TO_PNG_WIDTH=15'
kat_expect "CF_DIB->PNG height (from IHDR)"                     'KAT_CLIPRDR_DIB_TO_PNG_HEIGHT=5'

emit_ctrf "cargo-test+kat" "$PASSED" "$FAILED" "$SKIPPED"
