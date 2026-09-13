// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Epic E14-2: the signed audit record P06 Justitia hands to P16 Athena.
//!
//! The schema round-trips, refuses an unknown contract version and an excluded
//! hash algorithm, ties a refusal to its reason, and admits the all-zero
//! genesis link only at the head of a chain. Nothing here signs or verifies
//! anything: the seal is a field encoding, and TPM2 sealing is M20 work.

mod common;

use aegis_justitia::{
    ActionType, AuditRecordVersion, BlockReason, ContractError, Correlation, Digest32, EdgeId,
    HaltReason, HashAlgorithm, Identity, PLD_EFFECTIVE_AT, RecordStatus, SchemaId, Sequence,
    SignedAuditRecord, UnixSeconds,
};

use common::{CORRELATION, Fallible, audit_record, encoded, render, seal, tamper};

/// The exact payload the fixture record encodes to.
const GOLDEN: &str = r#"{"schema":"aegis.p06-p16.audit-record.v1","edge":"AUDIT_RECONSTRUCTIVE_CANDIDATE","correlation-id":"intent-0001","event-id":"event-0001","sequence":1,"algorithm":"sha-256","previous":"0000000000000000000000000000000000000000000000000000000000000000","digest":"0505050505050505050505050505050505050505050505050505050505050505","action-type":"file-deletion","status":"approved","block-reason":null,"actor-id":"agent-01","recorded-at":1000,"oversight-signature":{"key-id":"fixture-key","algorithm":"tpm2-rsa-pss","bytes":"0707070707070707070707070707070707070707070707070707070707070707"}}"#;

/// Returns the correlation a refusal of a fixture record must carry.
fn expected_correlation() -> Fallible<Correlation> {
    Ok(Correlation::new(
        SchemaId::SignedAuditRecord,
        Some(Identity::parse(CORRELATION)?),
    ))
}

// --- Positive -------------------------------------------------------------

/// Positive: a sealed record round-trips, and the encoding is stable.
#[test]
fn a_signed_audit_record_round_trips() -> Fallible<()> {
    let original = audit_record(1)?;
    let text = encoded(&original)?;
    assert_eq!(text, GOLDEN, "the field encoding is stable");
    let decoded = SignedAuditRecord::decode(&text)?;
    assert_eq!(decoded, original, "serialise then deserialise is identity");
    assert_eq!(encoded(&decoded)?, text, "and the second encoding matches");
    assert_eq!(decoded.validate(), Ok(()));
    Ok(())
}

/// Positive: the decoded record carries every field as a type, not as prose.
#[test]
fn a_decoded_record_carries_its_typed_fields() -> Fallible<()> {
    let decoded = SignedAuditRecord::decode(&encoded(&audit_record(1)?)?)?;
    assert_eq!(decoded.schema, AuditRecordVersion::V1);
    assert_eq!(decoded.edge, EdgeId::AuditReconstructiveCandidate);
    assert_eq!(decoded.algorithm, HashAlgorithm::Sha256);
    assert_eq!(decoded.action_type, ActionType::FileDeletion);
    assert_eq!(decoded.status, RecordStatus::Approved);
    assert_eq!(decoded.sequence, Sequence::FIRST);
    assert!(decoded.is_chain_head());
    assert_eq!(decoded.correlation(), expected_correlation()?);
    Ok(())
}

/// Positive: a refusal travels with the reason that produced it, halt reason
/// included, so a refused action is reconstructible from the record alone.
#[test]
fn a_refusal_travels_with_its_reason() -> Fallible<()> {
    let mut halted = audit_record(4)?;
    halted.status = RecordStatus::Halted;
    halted.block_reason = Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop));
    let text = encoded(&halted)?;
    assert!(text.contains("\"killswitch-engaged\":\"operator-stop\""));
    assert_eq!(SignedAuditRecord::decode(&text)?, halted);

    let mut blocked = audit_record(5)?;
    blocked.status = RecordStatus::Blocked;
    blocked.block_reason = Some(BlockReason::LedgerCompromised);
    assert_eq!(
        SignedAuditRecord::decode(&encoded(&blocked)?)?,
        blocked,
        "every refusal reason survives the round trip"
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a payload naming another contract version is refused as such.
#[test]
fn a_payload_naming_another_version_is_refused() -> Fallible<()> {
    let text = tamper(&encoded(&audit_record(1)?)?, |value| {
        value["schema"] = serde_json::json!("aegis.p06-p16.audit-record.v2");
    })?;
    assert_eq!(
        SignedAuditRecord::decode(&text),
        Err(ContractError::UnknownVersion {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

/// Negative: decision D02 excludes the reference daemon's hash algorithm, so a
/// record naming it has no variant to decode into.
#[test]
fn a_record_naming_the_excluded_hash_algorithm_is_refused() -> Fallible<()> {
    let text = tamper(&encoded(&audit_record(1)?)?, |value| {
        value["algorithm"] = serde_json::json!("md5");
    })?;
    assert_eq!(
        SignedAuditRecord::decode(&text),
        Err(ContractError::Malformed {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

/// Negative: an unsealed record is refused, and so is one whose seal is empty.
#[test]
fn an_unsealed_record_is_refused() -> Fallible<()> {
    let mut unsealed = audit_record(1)?;
    unsealed.oversight_signature = None;
    let refusal = ContractError::Unsigned {
        correlation: expected_correlation()?,
    };
    assert_eq!(unsealed.validate(), Err(refusal));
    assert_eq!(SignedAuditRecord::decode(&render(&unsealed)?), Err(refusal));

    let mut hollow = audit_record(1)?;
    let mut empty = seal()?;
    empty.bytes = aegis_justitia::SignatureBytes::EMPTY;
    hollow.oversight_signature = Some(empty);
    assert_eq!(hollow.validate(), Err(refusal));
    Ok(())
}

/// Negative: a refusal without its reason, and a decision that refused nothing
/// but carries a reason anyway, are both refused.
#[test]
fn a_reason_must_match_the_decision_it_belongs_to() -> Fallible<()> {
    let mut silent = audit_record(2)?;
    silent.status = RecordStatus::Blocked;
    silent.block_reason = None;
    assert_eq!(
        silent.validate(),
        Err(ContractError::RefusalWithoutReason {
            correlation: expected_correlation()?
        })
    );

    let mut noisy = audit_record(2)?;
    noisy.status = RecordStatus::Approved;
    noisy.block_reason = Some(BlockReason::AuditUnavailable);
    assert_eq!(
        SignedAuditRecord::decode(&render(&noisy)?),
        Err(ContractError::ReasonWithoutRefusal {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the all-zero genesis link is admissible at sequence one and
/// nowhere else, in both directions.
#[test]
fn the_genesis_link_is_admissible_only_at_the_head_of_the_chain() -> Fallible<()> {
    let head = audit_record(1)?;
    assert!(head.previous.is_genesis());
    assert!(head.is_chain_head());
    assert_eq!(SignedAuditRecord::decode(&encoded(&head)?)?, head);

    let second = audit_record(2)?;
    assert!(!second.previous.is_genesis());
    assert!(!second.is_chain_head());
    assert_eq!(SignedAuditRecord::decode(&encoded(&second)?)?, second);

    let mut forged = audit_record(2)?;
    forged.previous = Digest32::GENESIS;
    assert_eq!(
        SignedAuditRecord::decode(&render(&forged)?),
        Err(ContractError::GenesisLinkOutOfPlace {
            correlation: expected_correlation()?,
            sequence: 2
        })
    );

    let mut orphan = audit_record(1)?;
    orphan.previous = Digest32::from_bytes([1u8; 32]);
    assert_eq!(
        orphan.validate(),
        Err(ContractError::MissingGenesisLink {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

/// Boundary: the Product Liability Directive's effective date is tracked as an
/// external deadline and changes no behaviour when it passes.
#[test]
fn the_product_liability_deadline_is_tracked_and_gates_nothing() -> Fallible<()> {
    assert_eq!(
        PLD_EFFECTIVE_AT,
        UnixSeconds::new(1_796_774_400),
        "9 December 2026, 00:00:00 UTC"
    );
    let mut before = audit_record(1)?;
    before.recorded_at = UnixSeconds::new(PLD_EFFECTIVE_AT.get().saturating_sub(1));
    assert_eq!(SignedAuditRecord::decode(&encoded(&before)?)?, before);

    let mut after = audit_record(1)?;
    after.recorded_at = UnixSeconds::new(PLD_EFFECTIVE_AT.get().saturating_add(1));
    assert_eq!(
        SignedAuditRecord::decode(&encoded(&after)?)?,
        after,
        "the deadline is a roadmap deadline, not a gate in this crate"
    );
    Ok(())
}
