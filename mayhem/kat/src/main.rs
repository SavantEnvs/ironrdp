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
//! Four checks, one per fuzzed surface:
//!   - RLE      (rle_decompression / bitmap_stream target surface): decompress a real 64x64 16bpp
//!     RLE-compressed tile fixture from ironrdp-testsuite-core's own test data and assert the
//!     decompressed bytes match the committed expected fixture exactly.
//!   - BULK     (bulk_ncrush target surface): NCRUSH round-trip a fixed text buffer and assert both
//!     the compressed size and the round-tripped digest.
//!   - PDU      (pdu_round_trip target surface): build a `ConnectionRequest`, encode it, decode it
//!     back, and assert the decoded fields equal what we built (protocol bits, flags, correlation).
//!   - CLIPRDR  (cliprdr_format target surface): convert a real CF_DIB clipboard fixture (also from
//!     ironrdp-testsuite-core's test data) to PNG and assert the PNG signature bytes and the
//!     width/height encoded in its IHDR chunk match the DIB's own known dimensions (15x5).

use ironrdp_bulk::{BulkCompressor, CompressionType, flags};
use ironrdp_core::{decode, encode_vec};
use ironrdp_pdu::nego::{ConnectionRequest, RequestFlags, SecurityProtocol};
use ironrdp_pdu::x224::X224;

/// FNV-1a 64-bit, hand-rolled (no extra dependency) -- deterministic digest of arbitrary bytes.
fn fnv1a64(data: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Real 64x64, 16bpp RLE-compressed tile + its expected decompression, straight from
/// ironrdp-testsuite-core's own committed test data (crates/ironrdp-testsuite-core/test_data/rle/).
/// Same fixture pair exercised by that crate's `decompress_bpp_16` rstest case.
const RLE_TILE_COMPRESSED: &[u8] = include_bytes!(
    "../../../crates/ironrdp-testsuite-core/test_data/rle/tile-27019fd9f222cebce9dfebcddb12bfa0-compressed.bin"
);
const RLE_TILE_DECOMPRESSED_EXPECTED: &[u8] = include_bytes!(
    "../../../crates/ironrdp-testsuite-core/test_data/rle/tile-27019fd9f222cebce9dfebcddb12bfa0-decompressed.bin"
);

/// Real CF_DIB clipboard fixture from ironrdp-testsuite-core's own test data: a 15x5, 32bpp
/// uncompressed device-independent bitmap (confirmed via `file`: "Device independent bitmap
/// graphic, 15 x 5 x 32").
const CF_DIB_FIXTURE: &[u8] =
    include_bytes!("../../../crates/ironrdp-testsuite-core/test_data/pdu/clipboard/cf_dib.pdu");

fn check_rle() {
    let mut out = Vec::new();
    ironrdp_graphics::rle::decompress_16_bpp(RLE_TILE_COMPRESSED, &mut out, 64, 64)
        .expect("KAT: RLE decompress of a known-good 64x64 tile failed");
    assert_eq!(
        out, RLE_TILE_DECOMPRESSED_EXPECTED,
        "KAT: RLE decompressed bytes do not match the committed expected fixture"
    );
    let digest = fnv1a64(&out);
    println!("KAT_RLE_TILE_DECOMPRESSED_LEN={}", out.len());
    println!("KAT_RLE_TILE_FNV1A64={digest:016x}");
}

fn check_bulk_ncrush() {
    let mut input = Vec::new();
    for i in 0..40 {
        input.extend_from_slice(
            format!("IronRDP bulk compression KAT line {i:03} - the quick brown fox jumps over the lazy dog.\n")
                .as_bytes(),
        );
    }

    let mut sender = BulkCompressor::new(CompressionType::Rdp6);
    let (size, compress_flags) = sender.compress(&input).expect("KAT: NCRUSH compress failed");
    assert_ne!(
        compress_flags & flags::PACKET_COMPRESSED,
        0,
        "KAT: NCRUSH failed to compress a highly-repetitive fixed input"
    );
    let compressed = sender.compressed_data(size).to_vec();

    let mut receiver = BulkCompressor::new(CompressionType::Rdp6);
    let decompressed = receiver
        .decompress(&compressed, compress_flags)
        .expect("KAT: NCRUSH decompress of our own compressed output failed");
    assert_eq!(
        decompressed, input.as_slice(),
        "KAT: NCRUSH round-trip byte-equality failed"
    );

    println!("KAT_BULK_NCRUSH_COMPRESSED_LEN={}", compressed.len());
    println!("KAT_BULK_NCRUSH_ROUNDTRIP_FNV1A64={:016x}", fnv1a64(&decompressed));
}

fn check_pdu_round_trip() {
    let request = X224(ConnectionRequest {
        nego_data: None,
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::HYBRID | SecurityProtocol::SSL,
        correlation_info: None,
    });

    let encoded = encode_vec(&request).expect("KAT: ConnectionRequest encode failed");
    let X224(decoded) =
        decode::<X224<ConnectionRequest>>(&encoded).expect("KAT: ConnectionRequest re-decode failed");

    assert_eq!(
        decoded.protocol,
        SecurityProtocol::HYBRID | SecurityProtocol::SSL,
        "KAT: decoded ConnectionRequest.protocol does not match what was encoded"
    );
    assert_eq!(
        decoded.flags,
        RequestFlags::empty(),
        "KAT: decoded ConnectionRequest.flags does not match what was encoded"
    );
    assert!(
        decoded.correlation_info.is_none(),
        "KAT: decoded ConnectionRequest.correlation_info should be None"
    );

    println!("KAT_PDU_CONNECTION_REQUEST_ENCODED_LEN={}", encoded.len());
    println!(
        "KAT_PDU_CONNECTION_REQUEST_PROTOCOL_BITS={:#010x}",
        decoded.protocol.bits()
    );
}

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

    println!("KAT_CLIPRDR_DIB_TO_PNG_LEN={}", png.len());
    println!("KAT_CLIPRDR_DIB_TO_PNG_WIDTH={width}");
    println!("KAT_CLIPRDR_DIB_TO_PNG_HEIGHT={height}");
}

fn main() {
    check_rle();
    check_bulk_ncrush();
    check_pdu_round_trip();
    check_cliprdr_dib_to_png();
}
