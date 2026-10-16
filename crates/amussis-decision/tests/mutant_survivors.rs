// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! Tests killing mutant survivors across amussis-decision modules.
//!
//! Each test pins exact values (tags, names, bounds, Display text, digest bytes).

mod common;

use amussis_decision::{
    ActionType, AgentId, AnchorError, ApprovalTicket, AuditLedger, CanonicalBuffer, ChainAnchor,
    CheckerId, CheckerSet, DIGEST_LEN, Deadline, Digest32, HaltReason, HashAlgorithm, Identity,
    InMemorySink, IntentId, KillswitchState, MAX_PREIMAGE_BYTES, MakerId, OversightClass,
    PendingRegistry, RecordBody, RecordDraft, RecordStatus, RecordSubject, RequestId, RiskLevel,
    RiskTier, Sequence, Sha256Hasher, Signature, SignerBinding, SignerKeyId, TargetResource, Ttl,
    UnixSeconds,
};

use common::{Fallible, FixtureError, FixtureSigner, io_deadline, named_for};

#[test]
fn identity_is_empty_and_equality_pin_false() -> Fallible<()> {
    let identity = Identity::parse("agent-01")?;
    assert!(!identity.is_empty());
    assert_eq!(identity.len(), 8);
    assert_eq!(identity.as_bytes(), b"agent-01");
    Ok(())
}

#[test]
fn target_resource_is_empty_equality_and_display_pin_exact_values() -> Fallible<()> {
    let raw = "target:system/node-1";
    let resource = TargetResource::parse(raw)?;
    assert!(!resource.is_empty());
    assert_eq!(resource.len(), 20);
    assert_eq!(format!("{resource}"), raw);
    assert_eq!(resource.to_string(), raw);
    Ok(())
}

#[test]
fn record_status_name_pins_published_identifiers() {
    assert_eq!(RecordStatus::PendingApproval.name(), "pending-approval");
    assert_eq!(RecordStatus::Approved.name(), "approved");
    assert_eq!(RecordStatus::Rejected.name(), "rejected");
    assert_eq!(RecordStatus::Blocked.name(), "blocked");
    assert_eq!(RecordStatus::Halted.name(), "halted");
    assert_eq!(RecordStatus::HaltEngaged.name(), "halt-engaged");
    assert_eq!(RecordStatus::HaltReleased.name(), "halt-released");
}

#[test]
fn action_type_tag_pins_stable_numeric_values() {
    assert_eq!(ActionType::FileModification.tag(), 1);
    assert_eq!(ActionType::FileDeletion.tag(), 2);
    assert_eq!(ActionType::ExternalNetworkRequest.tag(), 3);
    assert_eq!(ActionType::PermissionEscalation.tag(), 4);
    assert_eq!(ActionType::SystemConfigChange.tag(), 5);
}

#[test]
fn action_tag_in_canonical_preimage_pins_exact_byte() -> Fallible<()> {
    const ACTION_TAG_OFFSET: usize = amussis_decision::AUDIT_DOMAIN.len()
        + 4
        + amussis_decision::CONTRACT_VERSION.len()
        + 1
        + 8
        + 32
        + 8
        + 1;

    let action_draft = RecordDraft {
        subject: Some(RecordSubject {
            intent_id: IntentId::parse("intent-1")?,
            agent: AgentId::parse("agent-1")?,
            action_type: ActionType::ExternalNetworkRequest,
        }),
        principals: named_for(RecordStatus::Approved)?,
        status: RecordStatus::Approved,
        block_reason: None,
        killswitch: KillswitchState::Armed,
        at: UnixSeconds::new(100),
    };
    let action_body = RecordBody::from_parts(
        Sequence::FIRST,
        Digest32::GENESIS,
        HashAlgorithm::Sha256,
        action_draft,
    );
    let action_preimage = action_body.canonical_preimage()?;
    assert_eq!(ACTION_TAG_OFFSET, 99);
    assert_eq!(
        action_preimage.as_slice().get(ACTION_TAG_OFFSET).copied(),
        Some(3)
    );

    let engaged = KillswitchState::Engaged {
        at: UnixSeconds::new(50),
        reason: HaltReason::OperatorStop,
        level: RiskLevel::HIGHEST,
    };
    let halt_draft = RecordDraft::of_halt(engaged, UnixSeconds::new(50));
    let halt_body = RecordBody::from_parts(
        Sequence::FIRST,
        Digest32::GENESIS,
        HashAlgorithm::Sha256,
        halt_draft,
    );
    let halt_preimage = halt_body.canonical_preimage()?;
    assert_eq!(
        halt_preimage.as_slice().get(ACTION_TAG_OFFSET).copied(),
        Some(0)
    );
    Ok(())
}

#[test]
fn in_memory_sink_bound_pins_exact_value() {
    let sink = InMemorySink::with_bound(42);
    assert_eq!(sink.bound(), 42);
}

#[test]
fn audit_ledger_bound_and_is_empty_pin_exact_values() -> Fallible<()> {
    let mut ledger: AuditLedger<Sha256Hasher, FixtureSigner, InMemorySink> =
        AuditLedger::with_bound(
            SignerBinding::Bound(FixtureSigner::new()?),
            InMemorySink::with_bound(10),
            io_deadline(),
            10,
        );
    assert_eq!(ledger.bound(), 10);
    assert!(ledger.is_empty());

    let draft = RecordDraft {
        subject: Some(RecordSubject {
            intent_id: IntentId::parse("intent-1")?,
            agent: AgentId::parse("agent-01")?,
            action_type: ActionType::FileModification,
        }),
        principals: named_for(RecordStatus::Approved)?,
        status: RecordStatus::Approved,
        block_reason: None,
        killswitch: KillswitchState::Armed,
        at: UnixSeconds::new(100),
    };
    ledger.append(draft)?;
    assert!(!ledger.is_empty());
    assert_eq!(ledger.len(), 1);
    Ok(())
}

#[test]
fn checker_set_is_empty_pins_false() -> Fallible<()> {
    let panel = CheckerSet::single(CheckerId::parse("checker-bob")?);
    assert!(!panel.is_empty());
    assert_eq!(panel.len(), 1);
    Ok(())
}

#[test]
fn pending_registry_bound_len_and_is_empty_pin_exact_values() -> Fallible<()> {
    let mut registry = PendingRegistry::with_bound(5);
    assert_eq!(registry.bound(), 5);
    assert_eq!(registry.len(), 0);
    assert!(registry.is_empty());

    let now = UnixSeconds::new(1_000);
    let ttl = Ttl::from_secs(60).ok_or(FixtureError::BadConstant("ttl"))?;
    let ticket = ApprovalTicket::new(
        RequestId::parse("request-1")?,
        MakerId::parse("maker-a")?,
        AgentId::parse("agent-01")?,
        ActionType::PermissionEscalation,
        RiskLevel::new(RiskTier::TierAConsequential, OversightClass::Standard),
        Deadline::open(now, ttl)?,
    );
    registry.insert(ticket, now)?;
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());
    Ok(())
}

#[test]
fn unix_seconds_display_pins_exact_decimal_string() {
    let time = UnixSeconds::new(1_700_000_123);
    assert_eq!(format!("{time}"), "1700000123");
    assert_eq!(time.to_string(), "1700000123");
}

#[test]
fn parsed_visitor_expecting_pins_exact_label() -> Fallible<()> {
    let err = match serde_json::from_str::<Identity>("\"invalid with whitespace\"") {
        Err(err) => err,
        Ok(parsed) => {
            return Err(Box::new(std::io::Error::other(format!(
                "expected decode error, got {parsed}"
            ))));
        }
    };
    let message = err.to_string();
    assert!(
        message.contains("expected a bounded identifier"),
        "error message must describe expected format: {message}"
    );
    Ok(())
}

#[test]
fn chain_anchor_from_preimage_bounds_pin_exact_comparisons() {
    let at_bound = vec![0u8; MAX_PREIMAGE_BYTES];
    let res_at_bound = ChainAnchor::from_preimage::<Sha256Hasher>(&at_bound, &Digest32::GENESIS);
    assert_eq!(res_at_bound, Err(AnchorError::DigestMismatch));

    let past_bound = vec![0u8; MAX_PREIMAGE_BYTES + 1];
    let res_past_bound =
        ChainAnchor::from_preimage::<Sha256Hasher>(&past_bound, &Digest32::GENESIS);
    assert_eq!(res_past_bound, Err(AnchorError::Malformed));
}

#[test]
fn digest32_to_bytes_and_is_genesis_pin_exact_values() {
    let bytes = [42u8; DIGEST_LEN];
    let digest = Digest32::from_bytes(bytes);
    assert_eq!(digest.to_bytes(), bytes);
    assert!(!digest.is_genesis());

    assert_eq!(Digest32::GENESIS.to_bytes(), [0u8; DIGEST_LEN]);
    assert!(Digest32::GENESIS.is_genesis());
}

#[test]
fn canonical_buffer_is_empty_pins_buffer_state() -> Fallible<()> {
    let mut buffer = CanonicalBuffer::new();
    assert!(buffer.is_empty());
    buffer.write_u8(1)?;
    assert!(!buffer.is_empty());
    Ok(())
}

#[test]
fn signature_is_empty_pins_byte_length() -> Fallible<()> {
    let key = SignerKeyId::parse("key-01")?;
    let empty_sig = Signature::new(key, &[])?;
    assert!(empty_sig.is_empty());

    let non_empty_sig = Signature::new(key, &[0x42])?;
    assert!(!non_empty_sig.is_empty());
    Ok(())
}
