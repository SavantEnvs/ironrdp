//! ironrdp-mayhem-kat — the known-answer probe used by mayhem/test.sh.
//!
//! Why this exists (SPEC §6.3 / the anti-reward-hacking oracle): `cargo test`'s compiled test
//! binaries are ordinary dynamically-linked Rust binaries, so the verify-repo LD_PRELOAD sabotage
//! shim CAN in principle neuter them -- but we do not rely on that alone, for the same reason the
//! zeekstd/cel-rust integrations don't: `cargo test`'s own harness re-links/re-discovers tests in a
//! way that isn't a stable, independently-verifiable target for the shim across toolchain versions,
//! and a test RUNNER that only checks a child's exit code (not this crate, but the general failure
//! mode) can be fooled by a neutered child that exits 0 having done nothing. This probe instead:
//!
//!   1. Runs each check directly against a FIXED input (an upstream-committed fixture or a
//!      hand-built PDU), through the real library code the fuzz targets exercise.
//!   2. Asserts EXACT parsed/computed VALUES (panics -- nonzero exit -- on any mismatch), not just
//!      "didn't crash" or "returned Ok".
//!   3. Prints `KAT_<NAME>=<value>` lines that `mayhem/test.sh` greps for with `grep -qxF`, so a
//!      neutered/no-op binary (the shim `_exit(0)`s it before any of this runs) prints nothing and
//!      every expected line fails to match.
//!
//! One check (cliprdr_format surface): see `check_cliprdr_dib_to_png`.

/// Real CF_DIB clipboard fixture from ironrdp-testsuite-core's own test data: a 15x5, 32bpp
/// uncompressed device-independent bitmap (confirmed via `file`: "Device independent bitmap
/// graphic, 15 x 5 x 32").
const CF_DIB_FIXTURE: &[u8] =
    include_bytes!("../../../crates/ironrdp-testsuite-core/test_data/pdu/clipboard/cf_dib.pdu");

fn check_cliprdr_dib_to_png() {
    let png = ironrdp_cliprdr_format::bitmap::dib_to_png(CF_DIB_FIXTURE)
        .expect("KAT: dib_to_png on a known-good CF_DIB fixture failed");

    const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    assert!(
        png.len() > 8 + 8 + 13,
        "KAT: produced PNG is too short to hold a signature + IHDR chunk"
    );
    assert_eq!(&png[0..8], &PNG_SIGNATURE, "KAT: output does not start with the PNG signature");

    // IHDR chunk: 4-byte length, 4-byte "IHDR" tag, then width(4) + height(4) big-endian.
    assert_eq!(&png[12..16], b"IHDR", "KAT: first PNG chunk is not IHDR");
    let width = u32::from_be_bytes(png[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(png[20..24].try_into().unwrap());

    // The CF_DIB fixture is a known 15x5 bitmap (confirmed independently via `file`).
    assert_eq!(width, 15, "KAT: PNG width does not match the source DIB's known width");
    assert_eq!(height, 5, "KAT: PNG height does not match the source DIB's known height");

    println!("KAT_CLIPRDR_DIB_TO_PNG_WIDTH={width}");
    println!("KAT_CLIPRDR_DIB_TO_PNG_HEIGHT={height}");
}

fn check_cliprdr_wide_dib_rejected() {
    // biWidth (LONG) is the second DWORD of the BITMAPINFOHEADER: patch the fixture to 20_000
    // (> the 10_000 invariant) and expect a clean error, not a conversion.
    let mut dib = CF_DIB_FIXTURE.to_vec();
    dib[4..8].copy_from_slice(&20_000_i32.to_le_bytes());
    assert!(
        ironrdp_cliprdr_format::bitmap::dib_to_png(&dib).is_err(),
        "KAT: dib_to_png accepted a DIB wider than 10_000"
    );
    println!("KAT_CLIPRDR_WIDE_DIB_REJECTED=1");
}

fn main() {
    check_cliprdr_dib_to_png();
    check_cliprdr_wide_dib_rejected();
}
