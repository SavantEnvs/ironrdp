#!/usr/bin/env bash
#
# ironrdp/mayhem/build.sh — build five sanitized libFuzzer targets from upstream's OWN
# fuzz/fuzz_targets/ (unmodified), plus the project's own test suite (scoped) and the KAT probe
# used by mayhem/test.sh.
#
# Targets produced (one Mayhemfile each), all from upstream's unmodified fuzz/fuzz_targets/*.rs:
#   /mayhem/pdu_round_trip     — decode -> encode -> re-decode across ~30 core RDP PDU types
#                                (connection sequence, GCC, licensing, fast-path, surface commands,
#                                cliprdr, rdpdr, rdpsnd, autodetect, input). The highest-value
#                                target: exercises both the decoder AND encoder on the same
#                                attacker-controlled bytes.
#   /mayhem/rle_decompression  — the RLE bitmap decompressor (8/15/16/24 bpp) driven by an
#                                `arbitrary`-derived BitmapInput{src,width,height} struct rather
#                                than raw bytes (see mayhem/<target>/testsuite note below).
#   /mayhem/bitmap_stream      — the RDP6 bitmap-stream encoder+decoder, also BitmapInput-driven.
#   /mayhem/cliprdr_format     — clipboard format conversion: PNG<->CF_DIB/CF_DIBV5, CF_HTML<->
#                                plain HTML. Raw bytes, tried under every format interpretation.
#   /mayhem/bulk_ncrush        — the NCRUSH (RDP6) bulk-decompression codec. Raw bytes.
#   /mayhem/kat                — dynamically-linked known-answer probe used by mayhem/test.sh.
#
# Two Rust toolchains are involved (SPEC §6 Rust trap: the pinned nightly can build fuzz targets
# fine yet break the ORACLE build):
#   - The project's OWN pin, rust-toolchain.toml ("1.94.1", stable) — used for the oracle build
#     (the project's own test suite) and the KAT probe, so the oracle reflects the toolchain the
#     project actually develops/tests against.
#   - A separate NIGHTLY (pinned by upstream's own xtask/src/bin_version.rs, NIGHTLY_TOOLCHAIN =
#     "nightly-2026-03-05") — required for `-Zsanitizer=address` and `-Z dwarf-version=3`, which are
#     nightly-only rustc flags. We reuse upstream's own vetted pin rather than choosing our own, since
#     upstream's CI (.github/workflows/fuzz.yml) already proves this exact nightly builds this exact
#     fuzz/ crate. `rustup run <toolchain> ...` (matching upstream's own xtask/src/fuzz.rs pattern)
#     selects the toolchain explicitly, bypassing the repo-root rust-toolchain.toml pin for that one
#     invocation.
#
# `fuzz/` is upstream's own cargo-fuzz crate. Its Cargo.toml declares `[workspace] members = ["."]`
# — it is its OWN workspace root, NOT a member of the repo-root workspace (root Cargo.toml's
# `members = ["crates/*", "benches", "xtask", "ffi"]` does not list it) — so `cargo fuzz build`
# writes binaries under `fuzz/target/<triple>/release/`, not the repo-root `target/`. (Verified
# locally; see mayhem build notes.)
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs this script OFFLINE.
#   - This FIRST build (in CI, online) populates the cargo registry under $CARGO_HOME for BOTH
#     toolchains (they share the same CARGO_HOME).
#   - The PATCH re-run resolves crates from that cache. The rlenv runtime exports
#     CARGO_NET_OFFLINE=true for the re-run, so we do NOT hard-code `--offline` here (that would
#     break this first, online build).
set -euo pipefail

# clang/rustc reject SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

export RUSTUP_HOME="${RUSTUP_HOME:-/opt/toolchains/rust/rustup}"
export CARGO_HOME="${CARGO_HOME:-/opt/toolchains/rust/cargo}"
export PATH="$CARGO_HOME/bin:$PATH"

: "${SRC:=/mayhem}"
cd "$SRC"

NIGHTLY_TOOLCHAIN="nightly-2026-03-05"   # pinned upstream: xtask/src/bin_version.rs NIGHTLY_TOOLCHAIN
STABLE_TOOLCHAIN="1.94.1"                # pinned upstream: rust-toolchain.toml

TRIPLE="x86_64-unknown-linux-gnu"

# DWARF<4 gate workaround (SPEC §6.2 item 10; see mayhem/Dockerfile header for the full rationale):
# -Z dwarf-version=3 covers rustc's own CUs; -Clinker=<cc-wrapper> prepends a hand-built DWARF3
# anchor.o as the FIRST object in every link so it becomes the first CU verify-repo's `-m1` check
# reads, even though the precompiled ASan runtime stays DWARF5 deeper in the binary.
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -Z dwarf-version=3 -Clinker=/opt/toolchains/rust/dwarf3-anchor/cc-wrapper.sh}"
export RUST_DEBUG_FLAGS

# OSS-Fuzz Rust libFuzzer+ASan flags. cargo-fuzz sets the ASan flag itself, but we pin it
# explicitly. --cfg fuzzing matches libfuzzer-sys; force-frame-pointers aids ASan backtraces.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing $RUST_DEBUG_FLAGS -Zsanitizer=address -Cforce-frame-pointers"

# Rust instrumentation goes through RUSTFLAGS -Zsanitizer=address (rustc ignores the clang-style
# $SANITIZER_FLAGS/$CFLAGS the C/C++ path uses). $SANITIZER_FLAGS still flows through as a build ARG
# (see mayhem/Dockerfile) for parity with the org contract; cargo-fuzz itself doesn't consume it.
: "${SANITIZER_FLAGS:=}"

echo "=== cargo fuzz build (nightly $NIGHTLY_TOOLCHAIN, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"

# build_fuzz_target <target-name>
#
# All five targets come from upstream's OWN fuzz/ crate, which is its own cargo workspace (see
# header) — so cargo-fuzz always writes into fuzz/target/, never the repo-root target/. We still
# assert the binary exists at the expected path so a future upstream workspace-membership change
# (e.g. if fuzz/ is ever folded into the root workspace) fails LOUDLY here instead of silently
# shipping a stale/missing binary.
build_fuzz_target() {
  local target="$1"
  echo "--- building fuzz target: $target ---"
  rustup run "$NIGHTLY_TOOLCHAIN" cargo fuzz build --fuzz-dir fuzz -O --debug-assertions "$target"
  local bin="$SRC/fuzz/target/$TRIPLE/release/$target"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$target"
  echo "built /mayhem/$target"
}

build_fuzz_target "pdu_round_trip"
build_fuzz_target "rle_decompression"
build_fuzz_target "bitmap_stream"
build_fuzz_target "cliprdr_format"
build_fuzz_target "bulk_ncrush"

# ── The KAT probe used by mayhem/test.sh (project's OWN stable toolchain, NORMAL flags — it is a
#    functional oracle, not a triage artifact, so no sanitizer/fuzz instrumentation here). ────────
echo "=== building /mayhem/kat (KAT probe, stable $STABLE_TOOLCHAIN, normal flags) ==="
(
  unset RUSTFLAGS
  cd "$SRC/mayhem/kat"
  rustup run "$STABLE_TOOLCHAIN" cargo build --release
)
cp "$SRC/mayhem/kat/target/release/kat" /mayhem/kat
if ! file /mayhem/kat | grep -q 'dynamically linked'; then
  echo "FATAL: /mayhem/kat is not dynamically linked — the sabotage check could not" >&2
  echo "       neuter it, which would make mayhem/test.sh a reward-hackable oracle." >&2
  file /mayhem/kat >&2
  exit 1
fi
echo "built /mayhem/kat (dynamically linked)"

# ── The project's own test suite (project's OWN stable toolchain, NORMAL flags, no
#    RUSTFLAGS/sanitizer) — build only, so mayhem/test.sh just RUNS it. ─────────────────────────
#
# Scoped to the crates behind the five fuzzed surfaces above, rather than `--workspace` (~2672
# #[test]s across the full 40+ crate workspace, including web/ffi/client crates unrelated to the
# fuzzed decode/compression surface): ironrdp-core (decode/encode primitives), ironrdp-pdu (the
# pdu_round_trip surface), ironrdp-graphics (RLE + RDP6 bitmap stream: rle_decompression,
# bitmap_stream), ironrdp-bulk (bulk_ncrush), ironrdp-cliprdr-format (cliprdr_format),
# ironrdp-cliprdr (the wire PDU types cliprdr_format's siblings use), ironrdp-egfx (an
# `ironrdp-fuzzing` dependency, arbitrary-feature build), and ironrdp-testsuite-core, which holds
# BOTH the crate-level unit/property tests AND upstream's own `fuzz_regression` suite (the same
# fixtures used as this repo's fuzz seeds, asserted not to crash under each oracle).
echo "=== building the project's own test suite (stable $STABLE_TOOLCHAIN, normal flags, scoped) ==="
(
  unset RUSTFLAGS
  rustup run "$STABLE_TOOLCHAIN" cargo test --no-run \
    -p ironrdp-core -p ironrdp-pdu -p ironrdp-graphics -p ironrdp-bulk \
    -p ironrdp-cliprdr-format -p ironrdp-cliprdr -p ironrdp-egfx -p ironrdp-testsuite-core
)

echo "build.sh complete:"
ls -la /mayhem/pdu_round_trip /mayhem/rle_decompression /mayhem/bitmap_stream /mayhem/cliprdr_format /mayhem/bulk_ncrush /mayhem/kat
