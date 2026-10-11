// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Epic E02-3: the audit-ledger algorithm decision and trait boundary.

mod common;

use aegis_justitia::{
    ActionType, AgentId, AuditLedger, AuditRecord, BlockReason, Digest32, HaltReason,
    HashAlgorithm, InMemorySink, IntentId, JustitiaError, KillswitchState, LedgerError,
    LedgerHasher, MAX_SIGNATURE_BYTES, OversightClass, RecordDraft, RecordStatus, RiskTier,
    Sha256Hasher, SignError, SignerBinding, UnavailableSink, UnixSeconds, verify_chain,
};

use common::{
    FIXTURE_AUDIT_BOUND, Fallible, FixtureError, FixtureSigner, OversizedSigner, engine, intent,
    io_deadline, unsigned_engine,
};

/// The FIPS 180-4 SHA-256 digest of `abc`, as a literal so no dev-dependency is
/// needed to state the known answer.
const ABC_DIGEST: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

/// The FIPS 180-4 SHA-256 digest of the empty message.
const EMPTY_DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

type Ledger = AuditLedger<Sha256Hasher, FixtureSigner, InMemorySink>;

/// Builds a fixture ledger with the fixture record bound.
fn ledger() -> Result<Ledger, JustitiaError> {
    Ok(AuditLedger::with_bound(
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FIXTURE_AUDIT_BOUND,
    ))
}

/// Builds a draft at `at` seconds with the given status.
fn draft(id: &str, status: RecordStatus, at: u64) -> Result<RecordDraft, JustitiaError> {
    Ok(RecordDraft {
        intent_id: IntentId::parse(id)?,
        agent: AgentId::parse("agent-01")?,
        action_type: ActionType::FileModification,
        status,
        block_reason: None,
        killswitch: KillswitchState::Armed,
        at: UnixSeconds::new(at),
    })
}

// --- Positive -------------------------------------------------------------

/// E02-3 positive: one algorithm is recorded and a chain re-walk verifies.
#[test]
fn one_algorithm_is_recorded_and_a_chain_re_walk_verifies() -> Fallible<()> {
    assert_eq!(Sha256Hasher::ALGORITHM, HashAlgorithm::Sha256);
    assert_eq!(
        Sha256Hasher::digest(b"abc")?,
        Digest32::from_bytes(ABC_DIGEST)
    );
    assert_eq!(Sha256Hasher::digest(b"")?.to_string(), EMPTY_DIGEST_HEX);

    let mut ledger = ledger()?;
    ledger.append(draft("intent-1", RecordStatus::Approved, 100)?)?;
    ledger.append(draft("intent-2", RecordStatus::PendingApproval, 101)?)?;
    ledger.append(draft("intent-3", RecordStatus::Rejected, 102)?)?;

    assert_eq!(ledger.len(), 3);
    for record in ledger.records() {
        assert_eq!(record.body().algorithm(), HashAlgorithm::Sha256);
    }
    let head = verify_chain::<Sha256Hasher>(ledger.records())?;
    assert_eq!(head, ledger.head());
    assert_eq!(ledger.sink().accepted().len(), 3);
    Ok(())
}

/// The hashed pre-image is the crate's own canonical encoding, so the digest of
/// a record is reproducible from its body alone.
#[test]
fn a_record_digest_is_reproducible_from_its_body() -> Fallible<()> {
    let mut ledger = ledger()?;
    ledger.append(draft("intent-1", RecordStatus::Approved, 100)?)?;
    let record = ledger.records().first().ok_or(FixtureError::NoRecord)?;
    assert_eq!(record.body().digest::<Sha256Hasher>()?, record.digest());
    assert_eq!(record.body().previous(), Digest32::GENESIS);
    Ok(())
}

/// The recorded refusal reason is inside the pre-image, so it cannot be edited
/// after the fact and it distinguishes two otherwise identical records.
#[test]
fn the_recorded_refusal_reason_is_bound_into_the_digest() -> Fallible<()> {
    let mut plain = ledger()?;
    plain.append(draft("intent-r", RecordStatus::Blocked, 100)?)?;

    let mut reasoned = ledger()?;
    let mut with_reason = draft("intent-r", RecordStatus::Blocked, 100)?;
    with_reason.block_reason = Some(BlockReason::RegistryFull);
    reasoned.append(with_reason)?;

    assert_ne!(
        plain.head(),
        reasoned.head(),
        "a refusal reason is part of the canonical pre-image, not a label beside it"
    );

    let mut other = ledger()?;
    let mut different = draft("intent-r", RecordStatus::Blocked, 100)?;
    different.block_reason = Some(BlockReason::DeadlineOverflow);
    other.append(different)?;
    assert_ne!(
        reasoned.head(),
        other.head(),
        "two distinct refusal reasons never share a digest"
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// E02-3 negative: a single flipped byte is detected, and a missing signer
/// returns an error.
#[test]
fn single_flipped_byte_is_detected_and_missing_signer_returns_an_error() -> Fallible<()> {
    let mut ledger = ledger()?;
    ledger.append(draft("intent-1", RecordStatus::Approved, 100)?)?;
    ledger.append(draft("intent-2", RecordStatus::Approved, 101)?)?;
    let original = *ledger.records().first().ok_or(FixtureError::NoRecord)?;

    // One byte of the stored digest is flipped.
    let mut bytes = original.digest().to_bytes();
    let first = bytes.first_mut().ok_or(FixtureError::NoRecord)?;
    *first ^= 0x01;
    let forged_digest = AuditRecord::from_parts(
        *original.body(),
        *original.signature(),
        Digest32::from_bytes(bytes),
    );
    let mut chain: Vec<AuditRecord> = ledger.records().to_vec();
    let slot = chain.first_mut().ok_or(FixtureError::NoRecord)?;
    *slot = forged_digest;
    assert_eq!(
        verify_chain::<Sha256Hasher>(&chain),
        Err(LedgerError::DigestMismatch { at: 1 })
    );

    // One field of the stored body is edited, keeping the original digest.
    let forged_body = AuditRecord::from_parts(
        original.body().with_status(RecordStatus::Rejected),
        *original.signature(),
        original.digest(),
    );
    let mut chain: Vec<AuditRecord> = ledger.records().to_vec();
    let slot = chain.first_mut().ok_or(FixtureError::NoRecord)?;
    *slot = forged_body;
    assert_eq!(
        verify_chain::<Sha256Hasher>(&chain),
        Err(LedgerError::DigestMismatch { at: 1 })
    );

    // No signer bound: the seal fails and nothing is committed.
    let mut unsigned: AuditLedger<Sha256Hasher, FixtureSigner, InMemorySink> =
        AuditLedger::with_bound(
            SignerBinding::unbound(),
            InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
            io_deadline(),
            FIXTURE_AUDIT_BOUND,
        );
    assert_eq!(
        unsigned.append(draft("intent-1", RecordStatus::Approved, 100)?),
        Err(LedgerError::Sign(SignError::Unavailable))
    );
    assert_eq!(unsigned.len(), 0);
    assert_eq!(unsigned.head(), Digest32::GENESIS);
    Ok(())
}

/// A seal failure on the decision path blocks the action rather than releasing
/// it unaudited, and halts the engine because the refusal itself is unrecordable.
#[test]
fn an_unsealable_decision_blocks_instead_of_releasing() -> Fallible<()> {
    let mut engine = unsigned_engine()?;
    let routine = intent(
        "intent-unsealable",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let outcome = engine.decide(&routine);
    assert_eq!(outcome.block_reason(), Some(BlockReason::AuditUnavailable));
    assert!(!outcome.permits_execution());
    assert_eq!(
        engine.killswitch().reason(),
        Some(HaltReason::AuditUnavailable),
        "a decision that cannot be audited halts the unit rather than passing silently"
    );

    let mut oversized: AuditLedger<Sha256Hasher, OversizedSigner, InMemorySink> =
        AuditLedger::with_bound(
            SignerBinding::Bound(OversizedSigner::new()?),
            InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
            io_deadline(),
            FIXTURE_AUDIT_BOUND,
        );
    assert_eq!(
        oversized.append(draft("intent-1", RecordStatus::Approved, 100)?),
        Err(LedgerError::Sign(SignError::TooLong {
            max: MAX_SIGNATURE_BYTES,
            actual: OversizedSigner::WIDTH,
        })),
        "a bound signer whose backend overruns the width bound still fails closed"
    );
    assert_eq!(oversized.len(), 0);
    Ok(())
}

/// A record dated before its predecessor is refused, so a backwards clock
/// cannot backdate the chain.
#[test]
fn a_backwards_timestamp_is_refused() -> Fallible<()> {
    let mut ledger = ledger()?;
    ledger.append(draft("intent-1", RecordStatus::Approved, 100)?)?;
    assert_eq!(
        ledger.append(draft("intent-2", RecordStatus::Approved, 99)?),
        Err(LedgerError::NonMonotonicTimestamp {
            last: 100,
            observed: 99
        })
    );
    assert_eq!(ledger.len(), 1);
    Ok(())
}

/// A chain re-walk detects a removed record through the sequence gap.
#[test]
fn a_removed_record_is_detected() -> Fallible<()> {
    let mut ledger = ledger()?;
    ledger.append(draft("intent-1", RecordStatus::Approved, 100)?)?;
    ledger.append(draft("intent-2", RecordStatus::Approved, 101)?)?;
    let mut chain: Vec<AuditRecord> = ledger.records().to_vec();
    let _removed = chain.remove(0);
    assert_eq!(
        verify_chain::<Sha256Hasher>(&chain),
        Err(LedgerError::SequenceGap {
            expected: 1,
            found: 2
        })
    );
    Ok(())
}

/// An unbound sink refuses every record, so the ledger commits nothing. It is
/// the sink dual of the unbound signer and the only producer of
/// `SinkError::Unavailable`.
#[test]
fn an_unavailable_sink_commits_nothing() -> Fallible<()> {
    let mut ledger: AuditLedger<Sha256Hasher, FixtureSigner, UnavailableSink> =
        AuditLedger::with_bound(
            SignerBinding::Bound(FixtureSigner::new()?),
            UnavailableSink::new(),
            io_deadline(),
            FIXTURE_AUDIT_BOUND,
        );
    assert_eq!(
        ledger.append(draft("intent-1", RecordStatus::Approved, 100)?),
        Err(LedgerError::Sink(aegis_justitia::SinkError::Unavailable))
    );
    assert_eq!(ledger.len(), 0);
    assert_eq!(ledger.head(), Digest32::GENESIS);
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// E02-3 boundary: an empty ledger verifies as the genesis state.
#[test]
fn empty_ledger_verifies_as_the_genesis_state() -> Fallible<()> {
    let ledger = ledger()?;
    assert!(ledger.is_empty());
    assert_eq!(ledger.head(), Digest32::GENESIS);
    assert!(ledger.head().is_genesis());
    assert_eq!(ledger.verify()?, Digest32::GENESIS);
    assert_eq!(verify_chain::<Sha256Hasher>(&[])?, Digest32::GENESIS);
    assert_eq!(
        Digest32::GENESIS.to_string(),
        "0".repeat(64),
        "the genesis link is 64 zero hexadecimal characters"
    );
    Ok(())
}

/// E02-3 boundary, second half: MD5 is absent from the crate, not merely from a
/// list written inside this test.
///
/// The assertions below are all about `aegis-justitia` itself: the algorithm
/// the shipped hasher records, the algorithm every record the shipped ledger
/// produces names, and the width of the digest the shipped hasher returns. MD5
/// would fail every one of them. The file-level exclusions -- no `md5` token in
/// the crate source, the manifest or the resolved lock -- are asserted in
/// `manifest_hygiene.rs`, and the wire-level exclusion -- a persisted `md5` tag
/// fails to parse -- in `jsonl_rendering.rs`.
#[test]
fn md5_is_absent_from_the_crate() -> Fallible<()> {
    assert_eq!(
        <Sha256Hasher as LedgerHasher>::ALGORITHM.name(),
        "sha-256",
        "the only hasher the crate ships records sha-256"
    );
    assert_eq!(
        Sha256Hasher::digest(b"abc")?.as_bytes().len(),
        32,
        "an MD5 digest would be 16 bytes; the crate's digest width is 32"
    );
    assert_eq!(
        Sha256Hasher::digest(b"abc")?,
        Digest32::from_bytes(ABC_DIGEST),
        "the digest is the FIPS 180-4 SHA-256 of the message, not another function's"
    );

    let mut ledger = ledger()?;
    ledger.append(draft("intent-1", RecordStatus::Approved, 100)?)?;
    for record in ledger.records() {
        assert_eq!(
            record.body().algorithm().name(),
            "sha-256",
            "every record the crate produces names sha-256"
        );
        assert_eq!(record.body().algorithm().tag(), 1);
    }
    Ok(())
}

/// A killswitch state is carried in every record, so a block is auditable.
#[test]
fn the_observed_killswitch_state_is_recorded() -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    engine.halt(HaltReason::OperatorStop);
    let routine = intent(
        "intent-recorded-halt",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let _blocked = engine.decide(&routine);
    let record = engine
        .ledger()
        .records()
        .first()
        .ok_or(FixtureError::NoRecord)?;
    assert_eq!(record.body().draft().status, RecordStatus::Halted);
    assert!(record.body().draft().killswitch.is_engaged());
    assert_eq!(
        record.body().draft().block_reason,
        Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop))
    );
    Ok(())
}
