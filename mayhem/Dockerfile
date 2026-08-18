# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — RUST target (cargo / cargo-fuzz). Builds ON TOP of the org base
# (ghcr.io/savantenvs/base), adding TWO pinned Rust toolchains + cargo-fuzz under
# /opt/toolchains/rust, then runs mayhem/build.sh.
#
# IronRDP is a pure-Rust implementation of the Microsoft RDP protocol (a large Cargo workspace
# under crates/). Upstream already ships its own fuzzing setup — crates/ironrdp-fuzzing/ (oracles +
# generators) and fuzz/fuzz_targets/ (~10 libFuzzer targets) — so this integration ports 5 of those
# unmodified targets rather than writing new harnesses. See mayhem/build.sh for the full target list
# and rationale.
#
# TWO TOOLCHAINS (SPEC §6 Rust trap: the pinned nightly can build fuzz targets fine yet break the
# ORACLE build): the project's own rust-toolchain.toml pins stable "1.94.1" (used for the project's
# own test suite + the KAT probe, so the oracle matches what the project actually tests against);
# a separate NIGHTLY, pinned to upstream's OWN vetted choice (xtask/src/bin_version.rs
# NIGHTLY_TOOLCHAIN = "nightly-2026-03-05", proven by upstream's own fuzz.yml CI to build this exact
# fuzz/ crate) is used only for `-Zsanitizer=address` / `-Z dwarf-version=3`, which are nightly-only
# rustc flags.
#
# `fuzz/` is upstream's own cargo-fuzz crate and is its OWN workspace (`[workspace] members =
# ["."]`) — not a member of the repo-root workspace — so `cargo fuzz build` writes binaries under
# `fuzz/target/<triple>/release/`, never the repo-root `target/`.
#
# DWARF<4 (SPEC §6.2 item 10): cargo-fuzz links Rust nightly's ASan runtime archive
# (librustc-nightly_rt.asan.a) via --whole-archive; those precompiled objects carry DWARF5 and land
# FIRST in .debug_info, so the `-Z dwarf-version=3` RUSTFLAG (which only affects rustc's OWN
# compilation units) can't lower them. Fix: prepend a hand-compiled `clang -gdwarf-3` anchor.o as the
# FIRST object in every link via a `-Clinker=<cc-wrapper>` RUSTFLAG — .debug_info CUs appear in
# linker-argument order, so the anchor's DWARF3 CU lands at offset 0, which is what verify-repo's
# `-m1` (first-CU) check reads.
#
# Build (from the repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] -t ironrdp-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (never an ENV — an empty ENV breaks clang). build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Undefaulted (no '=') so the base ENV default flows through unless --build-arg overrides it.
ARG SANITIZER_FLAGS

# ── Rust toolchains @ a FIXED, lockable, $HOME-independent prefix ──────────────────────────────
ARG NIGHTLY_TOOLCHAIN=nightly-2026-03-05
ARG STABLE_TOOLCHAIN=1.94.1
ARG CARGO_FUZZ_VERSION=0.13.2

ENV RUSTUP_HOME=/opt/toolchains/rust/rustup \
    CARGO_HOME=/opt/toolchains/rust/cargo \
    PATH=/opt/toolchains/rust/cargo/bin:${PATH}

USER root

RUN install -d /opt/toolchains/rust \
 && curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh \
 && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
        --default-toolchain "${STABLE_TOOLCHAIN}" \
 && rustup toolchain install "${NIGHTLY_TOOLCHAIN}" --profile minimal \
 && rustup component add rust-src --toolchain "${NIGHTLY_TOOLCHAIN}" \
 && cargo install cargo-fuzz --version "${CARGO_FUZZ_VERSION}" --locked \
 && rm -f /tmp/rustup-init.sh \
 # The commit build AND the air-gapped PATCH re-run run as `mayhem` (2000): it must read the
 # toolchains and read/refresh the cargo registry cache, so hand the whole prefix to 2000.
 && chown -R 2000:2000 /opt/toolchains/rust

# DWARF3 anchor object + cc-wrapper (see header). Lives under /opt/toolchains/rust alongside the
# rest of the Rust build tooling (it's a link-time helper for the Rust build, not a language
# toolchain cache, so it doesn't need the chown-2000 write access the registry needs).
RUN set -eux; \
    mkdir -p /opt/toolchains/rust/dwarf3-anchor; \
    printf 'void __mayhem_dwarf3_anchor(void) __attribute__((visibility("hidden"),used));\nvoid __mayhem_dwarf3_anchor(void) {}\n' \
      > /opt/toolchains/rust/dwarf3-anchor/anchor.c; \
    clang -g -gdwarf-3 -c /opt/toolchains/rust/dwarf3-anchor/anchor.c \
      -o /opt/toolchains/rust/dwarf3-anchor/anchor.o; \
    printf '#!/bin/bash\nexec cc /opt/toolchains/rust/dwarf3-anchor/anchor.o "$@"\n' \
      > /opt/toolchains/rust/dwarf3-anchor/cc-wrapper.sh; \
    chmod +x /opt/toolchains/rust/dwarf3-anchor/cc-wrapper.sh; \
    chmod a+rX /opt/toolchains/rust/dwarf3-anchor /opt/toolchains/rust/dwarf3-anchor/anchor.o \
               /opt/toolchains/rust/dwarf3-anchor/cc-wrapper.sh; \
    echo "DWARF3 anchor ready: $(readelf --debug-dump=info /opt/toolchains/rust/dwarf3-anchor/anchor.o | grep -m1 Version:)"

USER mayhem

# Source enters from the build CONTEXT (CI checkout): the FULL repo (incl. .git history) → /mayhem.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Populates $CARGO_HOME (online, this first build) and builds the sanitized fuzz targets + KAT probe.
RUN bash mayhem/build.sh

# Run the project's functional suite + the KAT probe at build time (a failing suite fails the build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
