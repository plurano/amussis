// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The field encoding every schema shares.
//!
//! Bytes travel as lower-case hexadecimal and nothing else, and the bounded
//! inline types refuse an over-long field during decoding rather than after
//! it. The payload rules built on these fields are in `encoding_payload.rs`.

mod common;

use amussis_decision::{
    DIGEST_HEX_CHARS, DIGEST_LEN, Digest32, Identity, MAX_SIGNATURE_HEX_CHARS, MAX_TARGET_LEN,
    OversightSignature, RecordSigner, SignatureAlgorithm, SignatureBytes, SignerKeyId,
    TargetResource,
};

use common::{Fallible, FixtureSigner, seal};

// --- Positive -------------------------------------------------------------

/// Positive: a seal survives the trip out to the wire form and back into the
/// ledger's own signature type, key included.
#[test]
fn a_seal_round_trips_through_its_wire_form() -> Fallible<()> {
    let signer = FixtureSigner::new()?;
    let digest = Digest32::from_bytes([7u8; DIGEST_LEN]);
    let signature = signer.sign(&digest)?;
    let wire = OversightSignature::from_signature(&signature, SignatureAlgorithm::Tpm2RsaPss);

    assert_eq!(wire.key_id, *signer.key_id());
    assert_eq!(wire.algorithm, SignatureAlgorithm::Tpm2RsaPss);
    assert_eq!(wire.algorithm.tag(), "tpm2-rsa-pss");
    assert!(!wire.is_empty());
    assert_eq!(wire.bytes.len(), DIGEST_LEN);
    assert_eq!(wire.bytes.as_bytes(), signature.as_bytes());
    assert_eq!(wire.bytes.into_signature(wire.key_id)?, signature);

    let text = serde_json::to_string(&wire)?;
    assert_eq!(serde_json::from_str::<OversightSignature>(&text)?, wire);
    Ok(())
}

/// Positive: a digest travels as lower-case hexadecimal of the declared width.
#[test]
fn a_digest_travels_as_lower_case_hexadecimal() -> Fallible<()> {
    let digest = Digest32::from_bytes([0xabu8; DIGEST_LEN]);
    let text = serde_json::to_string(&digest)?;
    assert_eq!(text.len(), DIGEST_HEX_CHARS.saturating_add(2));
    assert!(text.contains("abababab"));
    assert_eq!(serde_json::from_str::<Digest32>(&text)?, digest);
    assert_eq!(
        serde_json::to_string(&Digest32::GENESIS)?,
        format!("\"{}\"", "0".repeat(DIGEST_HEX_CHARS))
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: upper-case hexadecimal, a truncated digest and a non-string are
/// all refused rather than coerced.
#[test]
fn a_malformed_digest_is_refused() {
    assert!(serde_json::from_str::<Digest32>(&format!("\"{}\"", "AB".repeat(32))).is_err());
    assert!(serde_json::from_str::<Digest32>("\"abcd\"").is_err());
    assert!(serde_json::from_str::<Digest32>("1234").is_err());
}

/// Negative: an identifier outside the permitted character set is refused
/// during decoding, so a malformed name never reaches a validated field.
#[test]
fn an_identifier_outside_the_charset_is_refused() {
    assert!(serde_json::from_str::<Identity>("\"has space\"").is_err());
    assert!(serde_json::from_str::<Identity>("\"\"").is_err());
    assert!(serde_json::from_str::<SignerKeyId>("\"key;drop\"").is_err());
    assert!(serde_json::from_str::<SignerKeyId>("\"fixture-key\"").is_ok());
}

/// Negative: a seal with a key it does not name, an algorithm the library does
/// not know or a key the schema does not have is refused.
#[test]
fn a_seal_with_a_missing_or_unknown_part_is_refused() -> Fallible<()> {
    let text = serde_json::to_string(&seal()?)?;
    assert!(serde_json::from_str::<OversightSignature>(&text).is_ok());
    let other_scheme = text.replace("tpm2-rsa-pss", "ed25519");
    assert_ne!(other_scheme, text);
    assert!(serde_json::from_str::<OversightSignature>(&other_scheme).is_err());
    let no_key = text.replace("\"key-id\":\"fixture-key\",", "");
    assert_ne!(no_key, text);
    assert!(serde_json::from_str::<OversightSignature>(&no_key).is_err());
    let extra = text.replacen('{', "{\"note\":1,", 1);
    assert!(serde_json::from_str::<OversightSignature>(&extra).is_err());
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: a target resource of exactly the admitted width round-trips, and
/// one byte more is refused during decoding.
#[test]
fn a_target_resource_sits_exactly_on_its_bound() -> Fallible<()> {
    let widest = format!("\"{}\"", "/".repeat(MAX_TARGET_LEN));
    let decoded: TargetResource = serde_json::from_str(&widest)?;
    assert_eq!(decoded.len(), MAX_TARGET_LEN);
    assert_eq!(serde_json::to_string(&decoded)?, widest);
    let over = format!("\"{}\"", "/".repeat(MAX_TARGET_LEN.saturating_add(1)));
    assert!(serde_json::from_str::<TargetResource>(&over).is_err());
    assert!(serde_json::from_str::<TargetResource>("\"\"").is_err());
    Ok(())
}

/// Boundary: a signature of exactly the admitted width round-trips, and one
/// byte more is refused.
#[test]
fn signature_bytes_sit_exactly_on_the_hexadecimal_bound() -> Fallible<()> {
    let widest = "ab".repeat(MAX_SIGNATURE_HEX_CHARS / 2);
    assert_eq!(widest.len(), MAX_SIGNATURE_HEX_CHARS);
    let decoded: SignatureBytes = serde_json::from_str(&format!("\"{widest}\""))?;
    assert_eq!(decoded.len(), MAX_SIGNATURE_HEX_CHARS / 2);
    assert_eq!(serde_json::to_string(&decoded)?, format!("\"{widest}\""));

    let over = format!("{widest}ab");
    assert!(serde_json::from_str::<SignatureBytes>(&format!("\"{over}\"")).is_err());

    let odd = format!("{widest}a");
    assert!(serde_json::from_str::<SignatureBytes>(&format!("\"{odd}\"")).is_err());
    Ok(())
}

/// Boundary: the empty signature is representable, distinguishable from a real
/// one, and refuses to be mistaken for a seal.
#[test]
fn the_empty_signature_is_representable_and_distinguishable() -> Fallible<()> {
    assert!(SignatureBytes::EMPTY.is_empty());
    assert_eq!(SignatureBytes::EMPTY.len(), 0);
    assert_eq!(serde_json::to_string(&SignatureBytes::EMPTY)?, "\"\"");
    assert_eq!(
        serde_json::from_str::<SignatureBytes>("\"\"")?,
        SignatureBytes::EMPTY
    );
    let real = seal()?;
    assert_ne!(real.bytes, SignatureBytes::EMPTY);
    let mut hollow = real;
    hollow.bytes = SignatureBytes::EMPTY;
    assert!(hollow.is_empty());
    Ok(())
}
