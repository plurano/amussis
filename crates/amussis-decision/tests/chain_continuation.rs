// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! A chain longer than one audit window, and a chain a new engine continues.
//!
//! The ledger holds a bounded window of the chain. These tests run an engine
//! past that window by rotating it, continue a stored chain in a new engine
//! value from the anchor of its last record, and plant the cases that must be
//! refused: a head whose content was edited, a continuation from a record that
//! is not the head, stored bytes that are not a canonical pre-image, a window
//! that no longer verifies, and a halt latch that would be dropped on the way.

mod common;

use std::cell::Cell;

use amussis_decision::{
    AUDIT_DOMAIN, ActionIntent, ActionType, AgentId, AnchorError, AuditLedger, AuditRecord,
    BlockReason, CONTRACT_VERSION, ChainAnchor, CheckerId, CheckerSet, ClockError, DIGEST_LEN,
    DecisionEngine, DecisionError, Digest32, EngineConfig, FixedClock, HaltReason, HashAlgorithm,
    HashError, InMemorySink, IntentId, InterceptorOutcome, IoDeadline, Killswitch, KillswitchState,
    LedgerError, LedgerHasher, LedgerSink, MAX_LEDGER_RECORDS, MAX_PREIMAGE_BYTES, MonotonicGuard,
    OversightClass, OversightError, PreimageError, RecordBody, RecordDraft, RecordSigner,
    RecordStatus, RiskTier, Sequence, Sha256Hasher, SignerBinding, SinkError, UnixSeconds, Vote,
    verify_chain_bounded, verify_continuation,
};
use common::{
    Fallible, FixtureError, FixtureSigner, START, TestEngine, config, intent, io_deadline,
};

/// The audit window the fixtures use: small, so a test crosses it in a few
/// decisions.
const WINDOW: usize = 4;

/// Room in the store behind every fixture engine.
const STORE: usize = 32;

/// Offset of the hash-algorithm tag in a canonical pre-image: after the
/// domain tag and the length-prefixed contract version.
const ALGORITHM_AT: usize = AUDIT_DOMAIN.len() + 4 + CONTRACT_VERSION.len();

/// Offset of the last byte of the big-endian sequence number.
const SEQUENCE_LOW_AT: usize = ALGORITHM_AT + 8;

/// Offset of the halt-latch flag: after the sequence number, the previous
/// digest, the time and the four decision tag bytes.
const LATCH_AT: usize = ALGORITHM_AT + 1 + 8 + DIGEST_LEN + 8 + 4;

/// An engine over any hasher and sink, with the fixture signer and clock.
type EngineOver<H, K> = DecisionEngine<H, FixtureSigner, K, FixedClock>;

/// A routine action: the engine allows it and writes one record.
fn routine(id: &str) -> Fallible<ActionIntent> {
    Ok(intent(
        id,
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?)
}

/// The fixture configuration with an audit window of `window` records.
fn settings(window: usize) -> Fallible<EngineConfig> {
    let mut settings = config(600, 2)?;
    settings.max_audit_records = window;
    Ok(settings)
}

/// A new chain: an engine at genesis with an audit window of `window`.
fn fresh(window: usize) -> Fallible<TestEngine> {
    Ok(DecisionEngine::new(
        settings(window)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(STORE),
        io_deadline(),
        FixedClock::new(START),
    ))
}

/// An engine that continues the chain `anchor` names, with its own store and
/// a clock at `at`.
fn continued(anchor: &ChainAnchor, at: UnixSeconds) -> Fallible<TestEngine> {
    Ok(DecisionEngine::continue_from(
        settings(WINDOW)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(STORE),
        io_deadline(),
        FixedClock::new(at),
        anchor,
    ))
}

/// Decides `count` routine actions and requires each to be allowed.
fn allow<H: LedgerHasher, K: LedgerSink>(
    engine: &mut EngineOver<H, K>,
    prefix: &str,
    count: usize,
) -> Fallible<()> {
    for step in 0..count {
        let outcome = engine.decide(&routine(&format!("{prefix}-{step}"))?);
        assert_eq!(outcome, InterceptorOutcome::Allow, "{prefix} step {step}");
    }
    Ok(())
}

/// The last record the engine's store holds.
fn stored_head(engine: &TestEngine) -> Fallible<AuditRecord> {
    let stored = engine.ledger().sink().accepted();
    Ok(*stored.last().ok_or(FixtureError::NoRecord)?)
}

/// The anchor of the chain the engine's store holds.
fn anchor_of(engine: &TestEngine) -> Fallible<ChainAnchor> {
    Ok(ChainAnchor::from_record::<Sha256Hasher>(&stored_head(
        engine,
    )?)?)
}

/// The stores of several engines, in order, as one chain.
fn joined(parts: &[&TestEngine]) -> Vec<AuditRecord> {
    parts
        .iter()
        .flat_map(|engine| engine.ledger().sink().accepted().iter().copied())
        .collect()
}

/// A sealed record at an arbitrary sequence number, linked to genesis.
fn record_at(sequence: u64) -> Fallible<AuditRecord> {
    let draft = draft_at(START)?;
    let body = RecordBody::from_parts(
        Sequence::new(sequence),
        Digest32::GENESIS,
        HashAlgorithm::Sha256,
        draft,
    );
    let digest = body.digest::<Sha256Hasher>()?;
    let signature = FixtureSigner::new()?.sign(&digest)?;
    Ok(AuditRecord::from_parts(body, signature, digest))
}

/// The draft of an approved routine action at `at`.
fn draft_at(at: UnixSeconds) -> Fallible<RecordDraft> {
    Ok(RecordDraft {
        intent_id: IntentId::parse("intent-drafted")?,
        agent: AgentId::parse("agent-01")?,
        action_type: ActionType::FileModification,
        status: RecordStatus::Approved,
        block_reason: None,
        killswitch: KillswitchState::Armed,
        at,
    })
}

/// A sink that stores every record and cannot flush.
#[derive(Debug)]
struct NoFlushSink {
    inner: InMemorySink,
}

impl LedgerSink for NoFlushSink {
    fn append_record(
        &mut self,
        record: &AuditRecord,
        deadline: IoDeadline,
    ) -> Result<(), SinkError> {
        self.inner.append_record(record, deadline)
    }

    fn sync(&mut self, _deadline: IoDeadline) -> Result<(), SinkError> {
        Err(SinkError::Unavailable)
    }
}

thread_local! {
    /// Whether [`SkewHasher`] answers with a wrong digest on this thread.
    static SKEWED: Cell<bool> = const { Cell::new(false) };
}

/// SHA-256 that can be told to answer wrongly: the fault injector for a
/// window whose records no longer hash to their stored digests.
#[derive(Debug)]
struct SkewHasher;

impl LedgerHasher for SkewHasher {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;

    fn digest(preimage: &[u8]) -> Result<Digest32, HashError> {
        let mut bytes = Sha256Hasher::digest(preimage)?.to_bytes();
        if SKEWED.get()
            && let Some(first) = bytes.first_mut()
        {
            *first ^= 1;
        }
        Ok(Digest32::from_bytes(bytes))
    }
}

/// A hash backend that cannot produce a digest at all.
#[derive(Debug)]
struct NarrowHasher;

impl LedgerHasher for NarrowHasher {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;

    fn digest(_preimage: &[u8]) -> Result<Digest32, HashError> {
        Err(HashError::Width {
            expected: DIGEST_LEN,
            actual: 0,
        })
    }
}

// --- Positive -------------------------------------------------------------

/// Positive: the default engine answers more decisions than its window holds,
/// and the store holds one chain across the rotation.
#[test]
fn a_default_engine_runs_past_the_window_and_the_chain_stays_one_chain() -> Fallible<()> {
    let past = MAX_LEDGER_RECORDS.saturating_add(4);
    let mut engine: TestEngine = DecisionEngine::new(
        EngineConfig::default(),
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(past),
        io_deadline(),
        FixedClock::new(START),
    );
    allow(&mut engine, "first", MAX_LEDGER_RECORDS)?;
    assert_eq!(engine.audit_room(), 0, "the window is full");
    assert_eq!(engine.rotate_ledger()?, MAX_LEDGER_RECORDS);
    assert_eq!(engine.audit_room(), MAX_LEDGER_RECORDS);
    allow(&mut engine, "second", 4)?;
    assert_eq!(engine.killswitch(), KillswitchState::Armed);

    let stored = engine.ledger().sink().accepted();
    assert_eq!(stored.len(), past);
    assert_eq!(
        verify_chain_bounded::<Sha256Hasher>(stored, past)?,
        engine.ledger().head(),
        "the walk from genesis crosses the rotation and ends on the head"
    );
    let before = stored
        .get(MAX_LEDGER_RECORDS.saturating_sub(1))
        .ok_or(FixtureError::NoRecord)?;
    let after = stored
        .get(MAX_LEDGER_RECORDS)
        .ok_or(FixtureError::NoRecord)?;
    assert_eq!(after.body().previous(), before.digest());
    assert_eq!(
        after.body().sequence().get(),
        before.body().sequence().get().saturating_add(1)
    );
    engine.verify_ledger()?;
    Ok(())
}

/// Positive: the room counts down by one per decision.
#[test]
fn the_room_counts_down_by_one_per_decision() -> Fallible<()> {
    let mut engine = fresh(WINDOW)?;
    assert_eq!(engine.audit_room(), WINDOW);
    assert_eq!(engine.ledger().next_sequence(), Sequence::FIRST);
    allow(&mut engine, "one", 1)?;
    assert_eq!(engine.audit_room(), WINDOW.saturating_sub(1));
    assert_eq!(engine.ledger().remaining(), engine.audit_room());
    assert_eq!(engine.ledger().next_sequence(), Sequence::new(2));
    allow(&mut engine, "rest", WINDOW.saturating_sub(1))?;
    assert_eq!(engine.audit_room(), 0);
    Ok(())
}

/// Positive: a rotation restores the room, keeps the position in the chain
/// and reallocates nothing.
#[test]
fn a_rotation_restores_the_room_and_keeps_the_position() -> Fallible<()> {
    let mut engine = fresh(WINDOW)?;
    let reserved = engine.ledger().reserved();
    allow(&mut engine, "one", 1)?;
    let head = engine.ledger().head();
    assert_eq!(engine.rotate_ledger()?, 1, "one record dropped");
    assert_eq!(engine.audit_room(), WINDOW);
    assert!(engine.ledger().is_empty());
    assert_eq!(engine.ledger().head(), head, "the position did not move");
    assert_eq!(engine.ledger().next_sequence(), Sequence::new(2));
    assert_eq!(engine.ledger().verify()?, head, "an empty window verifies");
    assert_eq!(engine.ledger().reserved(), reserved);
    assert_eq!(engine.ledger().sink().syncs(), 1, "the sink was flushed");
    Ok(())
}

/// Positive: a new engine value continues a stored chain, and both stores
/// together are one chain.
#[test]
fn a_new_engine_continues_the_chain_from_its_stored_head() -> Fallible<()> {
    let mut first = fresh(WINDOW)?;
    allow(&mut first, "first", 3)?;
    let anchor = anchor_of(&first)?;
    let mut second = continued(&anchor, START)?;
    assert_eq!(second.last_reading(), Some(START));
    assert_eq!(second.ledger().head(), anchor.head());
    allow(&mut second, "second", 2)?;

    let chain = joined(&[&first, &second]);
    assert_eq!(
        verify_chain_bounded::<Sha256Hasher>(&chain, STORE)?,
        second.ledger().head()
    );
    let tail = second.ledger().sink().accepted();
    assert_eq!(
        verify_continuation::<Sha256Hasher>(&anchor, tail, STORE)?,
        second.ledger().head()
    );
    let link = tail.first().ok_or(FixtureError::NoRecord)?;
    assert_eq!(link.body().previous(), anchor.head());
    assert_eq!(link.body().sequence(), Sequence::new(4));
    second.verify_ledger()?;
    Ok(())
}

/// Positive: the anchor of an unhalted chain names its head record.
#[test]
fn the_anchor_names_the_head_record() -> Fallible<()> {
    let mut engine = fresh(WINDOW)?;
    allow(&mut engine, "first", 3)?;
    let anchor = anchor_of(&engine)?;
    assert_eq!(anchor.head(), engine.ledger().head());
    assert_eq!(anchor.sequence(), Sequence::new(3));
    assert_eq!(anchor.at(), START);
    assert_eq!(anchor.killswitch(), KillswitchState::Armed);
    Ok(())
}

/// Positive: the anchor read from stored bytes is the anchor of the record.
#[test]
fn the_anchor_of_stored_bytes_is_the_anchor_of_the_record() -> Fallible<()> {
    let mut engine = fresh(WINDOW)?;
    engine.halt(HaltReason::OperatorStop);
    let _refused = engine.decide(&routine("intent-halted")?);
    let record = stored_head(&engine)?;
    let preimage = record.body().canonical_preimage()?;

    let from_bytes =
        ChainAnchor::from_preimage::<Sha256Hasher>(preimage.as_slice(), &record.digest())?;
    assert_eq!(
        from_bytes,
        ChainAnchor::from_record::<Sha256Hasher>(&record)?
    );
    assert_eq!(from_bytes.head(), record.digest());
    assert_eq!(from_bytes.sequence(), record.body().sequence());
    assert_eq!(from_bytes.at(), record.body().draft().at);
    assert_eq!(from_bytes.killswitch(), record.body().draft().killswitch);
    assert_eq!(
        from_bytes.killswitch().reason(),
        Some(HaltReason::OperatorStop)
    );
    Ok(())
}

/// Positive and negative: a chain that ends halted continues halted, with the
/// first reason and time, until the latch is released on the anchor; the
/// chain then shows the step from engaged to armed.
#[test]
fn a_chain_that_ends_halted_continues_halted_until_released() -> Fallible<()> {
    let mut first = fresh(WINDOW)?;
    allow(&mut first, "first", 1)?;
    first.halt(HaltReason::OperatorStop);
    let refused = first.decide(&routine("intent-stopped")?);
    let halted = BlockReason::KillswitchEngaged(HaltReason::OperatorStop);
    assert_eq!(refused.block_reason(), Some(halted));
    let anchor = anchor_of(&first)?;
    assert_eq!(anchor.killswitch(), first.killswitch());

    let mut carried = continued(&anchor, START)?;
    assert_eq!(carried.killswitch(), first.killswitch());
    let outcome = carried.decide(&routine("intent-carried")?);
    assert_eq!(
        outcome.block_reason(),
        Some(halted),
        "a continuation does not drop the latch"
    );

    let released = anchor.release_latch()?;
    assert_eq!(released.head(), anchor.head());
    let mut resumed = continued(&released, START)?;
    allow(&mut resumed, "resumed", 1)?;
    let chain = joined(&[&first, &resumed]);
    verify_chain_bounded::<Sha256Hasher>(&chain, STORE)?;
    let step: Vec<bool> = chain
        .iter()
        .map(|record| record.body().draft().killswitch.is_engaged())
        .collect();
    assert_eq!(step, [false, true, false], "the release is in the chain");
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: an action held in the earlier engine is not released in the
/// engine that continues its chain. The hold is in the chain as a record and
/// in no registry: the new engine knows no such request and cannot approve it.
#[test]
fn a_held_action_stays_unreleased_after_a_continuation() -> Fallible<()> {
    let mut first = fresh(WINDOW)?;
    let held = first.decide(&intent(
        "intent-held",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    assert!(!held.permits_execution());
    assert_eq!(first.registry().len(), 1, "the hold is open in the first");

    let mut second = continued(&anchor_of(&first)?, START)?;
    assert!(second.registry().is_empty(), "no hold is carried over");
    let panel = CheckerSet::single(CheckerId::parse("checker-bob")?);
    let before = second.ledger().head();
    assert_eq!(
        second.adjudicate(ticket.request_id(), panel, Vote::Approve),
        Err(DecisionError::Oversight(OversightError::UnknownRequest))
    );
    assert_eq!(second.ledger().head(), before, "nothing was recorded");
    assert!(first.registry().pending(ticket.request_id()).is_ok());
    Ok(())
}

/// Negative, planted: a head whose content or digest was edited is refused as
/// an anchor.
#[test]
fn a_head_whose_content_was_edited_is_refused() -> Fallible<()> {
    let mut engine = fresh(WINDOW)?;
    allow(&mut engine, "first", 2)?;
    let record = stored_head(&engine)?;

    let restated = AuditRecord::from_parts(
        record.body().with_status(RecordStatus::Rejected),
        *record.signature(),
        record.digest(),
    );
    assert_eq!(
        ChainAnchor::from_record::<Sha256Hasher>(&restated),
        Err(AnchorError::DigestMismatch),
        "an edited body under the old digest"
    );

    let other = record_at(2)?.digest();
    let refiled = AuditRecord::from_parts(*record.body(), *record.signature(), other);
    assert_eq!(
        ChainAnchor::from_record::<Sha256Hasher>(&refiled),
        Err(AnchorError::DigestMismatch),
        "the true body under another digest"
    );
    let preimage = record.body().canonical_preimage()?;
    assert_eq!(
        ChainAnchor::from_preimage::<Sha256Hasher>(preimage.as_slice(), &other),
        Err(AnchorError::DigestMismatch)
    );
    Ok(())
}

/// Negative, planted: a continuation from a record that is not the head, or
/// from the head of another chain, is refused by the walk over the store.
#[test]
fn a_continuation_from_the_wrong_head_is_refused_by_the_walk() -> Fallible<()> {
    let mut first = fresh(WINDOW)?;
    allow(&mut first, "first", 3)?;
    let true_anchor = anchor_of(&first)?;
    let stale = first
        .ledger()
        .sink()
        .accepted()
        .get(1)
        .ok_or(FixtureError::NoRecord)?;
    let stale_anchor = ChainAnchor::from_record::<Sha256Hasher>(stale)?;

    let mut forked = continued(&stale_anchor, START)?;
    allow(&mut forked, "forked", 1)?;
    let gap = LedgerError::SequenceGap {
        expected: 4,
        found: 3,
    };
    let chain = joined(&[&first, &forked]);
    assert_eq!(
        verify_chain_bounded::<Sha256Hasher>(&chain, STORE),
        Err(gap)
    );
    let tail = forked.ledger().sink().accepted();
    assert_eq!(
        verify_continuation::<Sha256Hasher>(&true_anchor, tail, STORE),
        Err(gap)
    );

    let mut other = fresh(WINDOW)?;
    allow(&mut other, "other", 3)?;
    let mut grafted = continued(&anchor_of(&other)?, START)?;
    allow(&mut grafted, "grafted", 1)?;
    assert_eq!(
        verify_chain_bounded::<Sha256Hasher>(&joined(&[&first, &grafted]), STORE),
        Err(LedgerError::PreviousHashMismatch { at: 4 }),
        "the head of another chain at the same sequence number"
    );
    Ok(())
}

/// Reads `bytes` as an anchor under the digest they really have, so that a
/// refusal is about the content and never about the digest.
fn read_under_own_digest(bytes: &[u8]) -> Fallible<Result<ChainAnchor, AnchorError>> {
    let digest = Sha256Hasher::digest(bytes)?;
    Ok(ChainAnchor::from_preimage::<Sha256Hasher>(bytes, &digest))
}

/// `bytes` with the byte at `at` replaced.
fn with_byte(bytes: &[u8], at: usize, to: u8) -> Vec<u8> {
    let mut edited = bytes.to_vec();
    if let Some(slot) = edited.get_mut(at) {
        *slot = to;
    }
    edited
}

/// Negative, planted: stored bytes that are not a canonical pre-image of this
/// contract are refused, each for its one edit; the unedited bytes are read.
#[test]
fn stored_bytes_that_are_not_a_canonical_pre_image_are_refused() -> Fallible<()> {
    let record = record_at(1)?;
    let canonical = record.body().canonical_preimage()?;
    let bytes = canonical.as_slice();
    assert!(read_under_own_digest(bytes)?.is_ok(), "the control is read");

    let edits: [(&str, usize, u8); 7] = [
        ("domain tag", 0, b'x'),
        (
            "contract version",
            AUDIT_DOMAIN.len().saturating_add(4),
            b'x',
        ),
        ("hash algorithm", ALGORITHM_AT, 2),
        ("sequence zero", SEQUENCE_LOW_AT, 0),
        ("latch flag", LATCH_AT, 2),
        ("armed with a time", LATCH_AT.saturating_add(8), 1),
        ("armed with a reason", LATCH_AT.saturating_add(9), 1),
    ];
    for (name, at, to) in edits {
        assert_eq!(
            read_under_own_digest(&with_byte(bytes, at, to))?,
            Err(AnchorError::Malformed),
            "{name}"
        );
    }
    let short = bytes.get(..bytes.len().saturating_sub(1)).unwrap_or(&[]);
    assert_eq!(read_under_own_digest(short)?, Err(AnchorError::Malformed));
    let mut long = bytes.to_vec();
    long.push(0);
    assert_eq!(read_under_own_digest(&long)?, Err(AnchorError::Malformed));
    let oversized = vec![0u8; MAX_PREIMAGE_BYTES.saturating_add(1)];
    assert_eq!(
        read_under_own_digest(&oversized)?,
        Err(AnchorError::Malformed)
    );
    assert_eq!(read_under_own_digest(&[])?, Err(AnchorError::Malformed));
    Ok(())
}

/// Negative: an engaged latch with a reason tag no reason has is refused, and
/// a hash backend that fails is an error and never an anchor.
#[test]
fn an_unknown_halt_reason_and_a_failed_hash_are_refused() -> Fallible<()> {
    let mut engine = fresh(WINDOW)?;
    engine.halt(HaltReason::ClockUnavailable);
    let _refused = engine.decide(&routine("intent-halted")?);
    let record = stored_head(&engine)?;
    let canonical = record.body().canonical_preimage()?;
    let bytes = canonical.as_slice();
    assert!(read_under_own_digest(bytes)?.is_ok(), "the control is read");
    assert_eq!(
        read_under_own_digest(&with_byte(bytes, LATCH_AT.saturating_add(9), 9))?,
        Err(AnchorError::Malformed)
    );

    let width = HashError::Width {
        expected: DIGEST_LEN,
        actual: 0,
    };
    assert_eq!(
        ChainAnchor::from_record::<NarrowHasher>(&record),
        Err(AnchorError::Hash(width))
    );
    let overflow = PreimageError::Overflow {
        max: MAX_PREIMAGE_BYTES,
    };
    assert_eq!(AnchorError::from(overflow), AnchorError::Preimage(overflow));
    Ok(())
}

/// Negative: a chain halted as compromised is not released, and continues
/// halted. Boundary: releasing an armed anchor changes nothing.
#[test]
fn a_compromised_chain_is_not_released() -> Fallible<()> {
    let mut engine = fresh(WINDOW)?;
    allow(&mut engine, "first", 1)?;
    let armed = anchor_of(&engine)?;
    assert_eq!(armed.release_latch(), Ok(armed));

    engine.halt(HaltReason::LedgerCompromised);
    let _refused = engine.decide(&routine("intent-compromised")?);
    let anchor = anchor_of(&engine)?;
    assert_eq!(anchor.release_latch(), Err(AnchorError::Compromised));

    let mut carried = continued(&anchor, START)?;
    assert_eq!(
        carried.decide(&routine("intent-carried")?).block_reason(),
        Some(BlockReason::KillswitchEngaged(
            HaltReason::LedgerCompromised
        ))
    );
    Ok(())
}

/// Negative: when the sink cannot flush, the window is kept and the engine is
/// not halted; a decision that then finds the window full halts as before.
#[test]
fn a_rotation_the_sink_cannot_flush_keeps_the_window() -> Fallible<()> {
    let sink = NoFlushSink {
        inner: InMemorySink::with_bound(STORE),
    };
    let mut engine: EngineOver<Sha256Hasher, NoFlushSink> = DecisionEngine::new(
        settings(WINDOW)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        sink,
        io_deadline(),
        FixedClock::new(START),
    );
    allow(&mut engine, "first", 2)?;
    assert_eq!(
        engine.rotate_ledger(),
        Err(LedgerError::Sink(SinkError::Unavailable))
    );
    assert_eq!(engine.ledger().len(), 2, "nothing was dropped");
    assert_eq!(engine.audit_room(), WINDOW.saturating_sub(2));
    assert_eq!(engine.killswitch(), KillswitchState::Armed);

    allow(&mut engine, "second", 2)?;
    let outcome = engine.decide(&routine("intent-over")?);
    assert_eq!(outcome.block_reason(), Some(BlockReason::AuditUnavailable));
    assert_eq!(
        engine.killswitch().reason(),
        Some(HaltReason::AuditUnavailable)
    );
    Ok(())
}

/// Negative, planted: a window whose records no longer hash to their digests
/// is not dropped, and the engine halts as compromised.
#[test]
fn a_window_that_no_longer_verifies_is_not_dropped() -> Fallible<()> {
    let mut engine: EngineOver<SkewHasher, InMemorySink> = DecisionEngine::new(
        settings(WINDOW)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(STORE),
        io_deadline(),
        FixedClock::new(START),
    );
    allow(&mut engine, "first", 2)?;
    SKEWED.set(true);
    let rotated = engine.rotate_ledger();
    SKEWED.set(false);

    assert_eq!(rotated, Err(LedgerError::DigestMismatch { at: 1 }));
    assert_eq!(engine.ledger().len(), 2, "the window is kept");
    assert_eq!(engine.ledger().sink().syncs(), 0, "nothing was flushed");
    assert_eq!(
        engine.killswitch().reason(),
        Some(HaltReason::LedgerCompromised)
    );
    Ok(())
}

/// Negative: rotating a halted engine frees the window and releases nothing.
/// The refusals written afterwards put the halt in the chain, so its anchor
/// carries the latch.
#[test]
fn rotating_a_halted_engine_does_not_release_it() -> Fallible<()> {
    let mut engine = fresh(WINDOW)?;
    allow(&mut engine, "first", WINDOW)?;
    let over = engine.decide(&routine("intent-over")?);
    assert_eq!(over.block_reason(), Some(BlockReason::AuditUnavailable));
    assert_eq!(
        anchor_of(&engine)?.killswitch(),
        KillswitchState::Armed,
        "the refusal at the full window left no record"
    );

    assert_eq!(engine.rotate_ledger()?, WINDOW);
    let halted = BlockReason::KillswitchEngaged(HaltReason::AuditUnavailable);
    let after = engine.decide(&routine("intent-after")?);
    assert_eq!(after.block_reason(), Some(halted));
    assert_eq!(engine.audit_room(), WINDOW.saturating_sub(1));

    let anchor = anchor_of(&engine)?;
    assert_eq!(anchor.killswitch(), engine.killswitch());
    let mut carried = continued(&anchor, START)?;
    assert_eq!(
        carried.decide(&routine("intent-carried")?).block_reason(),
        Some(halted)
    );
    Ok(())
}

/// Negative: a clock that reads earlier than the head record is a clock fault
/// in the continuing engine, from the first reading on.
#[test]
fn a_clock_behind_the_head_record_is_a_fault() -> Fallible<()> {
    let mut first = fresh(WINDOW)?;
    allow(&mut first, "first", 1)?;
    let anchor = anchor_of(&first)?;
    let behind = UnixSeconds::new(START.get().saturating_sub(1));

    let mut second = continued(&anchor, behind)?;
    assert_eq!(
        second.now(),
        Err(ClockError::NonMonotonic {
            last: START.get(),
            observed: behind.get(),
        })
    );
    let outcome = second.decide(&routine("intent-backdated")?);
    assert_eq!(outcome.block_reason(), Some(BlockReason::ClockUnavailable));
    assert_eq!(
        second.killswitch().reason(),
        Some(HaltReason::ClockUnavailable)
    );
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// A ledger over the fixture signer and an in-memory store.
type FixtureLedger = AuditLedger<Sha256Hasher, FixtureSigner, InMemorySink>;

/// Boundary: a window of zero takes nothing and rotates nothing.
#[test]
fn a_window_of_zero_takes_nothing() -> Fallible<()> {
    let mut empty: FixtureLedger = AuditLedger::with_bound(
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(STORE),
        io_deadline(),
        0,
    );
    assert_eq!(empty.remaining(), 0);
    assert_eq!(empty.rotate()?, 0);
    assert_eq!(empty.verify()?, Digest32::GENESIS);
    assert_eq!(
        empty.append(draft_at(START)?),
        Err(LedgerError::LengthBoundExceeded { max: 0 })
    );
    Ok(())
}

/// A ledger that continues the chain `anchor` names with a window of
/// `window` records.
fn ledger_after(anchor: &ChainAnchor, window: usize) -> Fallible<FixtureLedger> {
    Ok(AuditLedger::continue_from(
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(STORE),
        io_deadline(),
        window,
        anchor,
    ))
}

/// Boundary: a continuing ledger starts on the head record: its digest, the
/// next sequence number, and no time before it. A time equal to it is taken.
#[test]
fn a_continuing_ledger_starts_on_the_head_record() -> Fallible<()> {
    let anchor = ChainAnchor::from_record::<Sha256Hasher>(&record_at(7)?)?;
    let mut ledger = ledger_after(&anchor, 1)?;
    assert_eq!(ledger.head(), anchor.head());
    assert_eq!(ledger.next_sequence(), Sequence::new(8));
    assert_eq!(ledger.verify()?, anchor.head());
    let earlier = UnixSeconds::new(START.get().saturating_sub(1));
    assert_eq!(
        ledger.append(draft_at(earlier)?),
        Err(LedgerError::NonMonotonicTimestamp {
            last: START.get(),
            observed: earlier.get(),
        })
    );
    ledger.append(draft_at(START)?)?;
    assert_eq!(ledger.next_sequence(), Sequence::new(9));
    Ok(())
}

/// Boundary: a window of one that continues a chain takes exactly one record
/// per rotation, and the store holds one chain behind the anchor.
#[test]
fn a_window_of_one_takes_one_record_per_rotation() -> Fallible<()> {
    let anchor = ChainAnchor::from_record::<Sha256Hasher>(&record_at(7)?)?;
    let mut ledger = ledger_after(&anchor, 1)?;
    for round in 0..3 {
        assert_eq!(ledger.remaining(), 1, "round {round}");
        ledger.append(draft_at(START)?)?;
        assert_eq!(ledger.remaining(), 0, "round {round}");
        assert_eq!(ledger.rotate()?, 1, "round {round}");
    }
    assert_eq!(ledger.next_sequence(), Sequence::new(11));
    let stored = ledger.sink().accepted();
    verify_continuation::<Sha256Hasher>(&anchor, stored, STORE)?;
    Ok(())
}

/// Boundary: at the sequence ceiling a continuation does not restart at one,
/// and the walk refuses what follows.
#[test]
fn the_sequence_ceiling_is_not_wrapped() -> Fallible<()> {
    let anchor = ChainAnchor::from_record::<Sha256Hasher>(&record_at(u64::MAX)?)?;
    assert_eq!(anchor.sequence(), Sequence::new(u64::MAX));
    let mut ledger = ledger_after(&anchor, WINDOW)?;
    assert_eq!(ledger.next_sequence(), Sequence::new(u64::MAX));
    ledger.append(draft_at(START)?)?;
    let refused = LedgerError::LengthBoundExceeded { max: WINDOW };
    assert_eq!(ledger.verify(), Err(refused));
    assert_eq!(
        verify_continuation::<Sha256Hasher>(&anchor, ledger.records(), WINDOW),
        Err(refused)
    );
    assert_eq!(
        ledger.rotate(),
        Err(refused),
        "such a window is not dropped"
    );
    Ok(())
}

/// The tag of a halt reason reads back as the reason; no other tag does.
#[test]
fn halt_reason_tags_read_back() {
    let reasons = [
        HaltReason::OperatorStop,
        HaltReason::AuditUnavailable,
        HaltReason::LedgerCompromised,
        HaltReason::ClockUnavailable,
    ];
    for reason in reasons {
        assert_eq!(HaltReason::from_tag(reason.tag()), Some(reason));
    }
    assert_eq!(HaltReason::from_tag(0), None, "zero is the armed latch");
    assert_eq!(HaltReason::from_tag(5), None, "one past the last reason");
    assert_eq!(HaltReason::from_tag(u8::MAX), None);
}

/// A latch built from a state is in that state and stays one-way; a guard
/// built after a time refuses an earlier reading and accepts an equal one.
#[test]
fn the_latch_and_the_guard_start_where_the_chain_stopped() {
    let engaged = KillswitchState::Engaged {
        at: UnixSeconds::new(10),
        reason: HaltReason::OperatorStop,
    };
    let mut latch = Killswitch::from_state(engaged);
    assert_eq!(latch.state(), engaged);
    latch.engage(UnixSeconds::new(20), HaltReason::AuditUnavailable);
    assert_eq!(latch.state(), engaged, "the first reason and time stay");
    assert_eq!(
        Killswitch::from_state(KillswitchState::Armed),
        Killswitch::new()
    );

    let mut guard = MonotonicGuard::after(UnixSeconds::new(10));
    assert_eq!(guard.last(), Some(UnixSeconds::new(10)));
    assert_eq!(
        guard.observe(UnixSeconds::new(9)),
        Err(ClockError::NonMonotonic {
            last: 10,
            observed: 9,
        })
    );
    assert_eq!(
        guard.observe(UnixSeconds::new(10)),
        Ok(UnixSeconds::new(10))
    );
}
