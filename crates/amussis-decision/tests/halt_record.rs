// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The halt as a record of the chain, the risk level it stands at, and its
//! release.
//!
//! A halt writes one record that names no action. It stands at a risk level:
//! the one the caller names, the one of the action in hand for a fault the
//! engine found itself, and the highest where there is none. The release is
//! held to the approval rule actions are held to, asked for that level. The
//! planted cases are the ones that must be refused: a release without the
//! approval the level demands, a panel that names the releaser, a release of
//! a halt the engine did not take over, a release whose record cannot be
//! written, and a record whose status and fields do not belong together.

mod common;

use std::cell::Cell;

use amussis_decision::{
    ActionType, AgentId, AuditRecord, BlockReason, CheckerId, CheckerSet, Clock, ClockError,
    DecisionEngine, DecisionError, Digest32, FixedClock, HaltReason, HashAlgorithm, InMemorySink,
    IntentId, InterceptorOutcome, IoDeadline, KillswitchState, LedgerError, LedgerSink, MakerId,
    OversightClass, OversightError, PreimageError, RecordBody, RecordDraft, RecordStatus,
    RecordSubject, ReleaseError, RequestId, RequiredApproval, RiskLevel, RiskTier, Sequence,
    Sha256Hasher, SignerBinding, SinkError, UnavailableSink, UnixSeconds, Vote,
};
use common::{
    FIXTURE_AUDIT_BOUND, Fallible, FaultyClock, FixtureError, FixtureSigner, START, TestEngine,
    anchor_of, config, engine, faulty_clock_engine, intent, io_deadline, unsigned_engine,
};

/// A level whose actions pass with a notice and no checker.
const MONITORED: RiskLevel =
    RiskLevel::new(RiskTier::TierBMaterialReversible, OversightClass::Standard);

/// A level whose actions need one checker.
const SINGLE: RiskLevel = RiskLevel::new(RiskTier::TierAConsequential, OversightClass::Standard);

/// The lowest level that needs two checkers.
const DUAL: RiskLevel = RiskLevel::new(
    RiskTier::TierCRoutineBounded,
    OversightClass::AnnexIiiBiometric,
);

/// An engine over the fixture signer with any sink and clock.
type EngineWith<K, C> = DecisionEngine<Sha256Hasher, FixtureSigner, K, C>;

/// The person who asks for a release.
fn releaser() -> Fallible<MakerId> {
    Ok(MakerId::parse("olga")?)
}

/// A panel of one checker.
fn one(name: &str) -> Fallible<CheckerSet> {
    Ok(CheckerSet::single(CheckerId::parse(name)?))
}

/// A panel of two checkers.
fn two(first: &str, second: &str) -> Fallible<CheckerSet> {
    Ok(CheckerSet::dual(
        CheckerId::parse(first)?,
        CheckerId::parse(second)?,
    )?)
}

/// An engine an operator halted at `level`: its store ends on the halt record.
fn halted_at(level: RiskLevel) -> Fallible<TestEngine> {
    let mut halted = engine(600, 4)?;
    halted.halt(HaltReason::OperatorStop, level)?;
    Ok(halted)
}

/// An engine that continues a chain halted at `level`, over the given signer
/// binding, sink and clock.
fn carried_with<K: LedgerSink, C: Clock>(
    level: RiskLevel,
    signer: SignerBinding<FixtureSigner>,
    sink: K,
    clock: C,
) -> Fallible<EngineWith<K, C>> {
    let anchor = anchor_of(&halted_at(level)?)?;
    Ok(DecisionEngine::continue_from(
        config(600, 4)?,
        signer,
        sink,
        io_deadline(),
        clock,
        &anchor,
    ))
}

/// An engine that continues a chain halted at `level`, with working effects.
fn carried(level: RiskLevel) -> Fallible<TestEngine> {
    carried_with(
        level,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        FixedClock::new(START),
    )
}

/// The last record in the engine's window.
fn last_draft<K: LedgerSink, C: Clock>(engine: &EngineWith<K, C>) -> Fallible<RecordDraft> {
    let last = engine.ledger().records().last();
    Ok(*last.ok_or(FixtureError::NoRecord)?.body().draft())
}

/// An action of the fixture agent at the given tier, with standard oversight.
fn action(id: &str, tier: RiskTier) -> Fallible<amussis_decision::ActionIntent> {
    Ok(intent(
        id,
        "maker-alice",
        ActionType::FileModification,
        tier,
        OversightClass::Standard,
    )?)
}

thread_local! {
    /// Whether [`SwitchSink`] refuses records on this thread.
    static DOWN: Cell<bool> = const { Cell::new(false) };
}

/// A store that can be switched off and on: the fault injector for a halt
/// whose record cannot be written at first.
#[derive(Debug)]
struct SwitchSink {
    inner: InMemorySink,
}

impl LedgerSink for SwitchSink {
    fn append_record(
        &mut self,
        record: &AuditRecord,
        deadline: IoDeadline,
    ) -> Result<(), SinkError> {
        if DOWN.get() {
            return Err(SinkError::Unavailable);
        }
        self.inner.append_record(record, deadline)
    }

    fn sync(&mut self, deadline: IoDeadline) -> Result<(), SinkError> {
        self.inner.sync(deadline)
    }
}

// --- Positive -------------------------------------------------------------

/// Positive: a halt is one record that names no action and carries the time,
/// the reason and the level of the halt; a halt repeated writes nothing more.
#[test]
fn a_halt_is_one_record_that_names_no_action() -> Fallible<()> {
    let mut halted = halted_at(SINGLE)?;
    let engaged = KillswitchState::Engaged {
        at: START,
        reason: HaltReason::OperatorStop,
        level: SINGLE,
    };
    assert_eq!(halted.killswitch(), engaged);
    assert_eq!(halted.ledger().len(), 1);
    let draft = last_draft(&halted)?;
    assert_eq!(draft, RecordDraft::of_latch(engaged, START));
    assert_eq!(draft.status, RecordStatus::HaltEngaged);
    assert_eq!(draft.subject, None);
    assert!(draft.is_well_formed());

    halted.halt(HaltReason::OperatorStop, SINGLE)?;
    assert_eq!(
        halted.ledger().len(),
        1,
        "one halt record per state of the halt"
    );
    Ok(())
}

/// Positive: a halt with no decision after it is in the stored chain, so an
/// engine that continues the chain starts halted at the same level, and the
/// refusal it records carries that level.
#[test]
fn a_halt_with_no_later_decision_is_carried_over() -> Fallible<()> {
    let mut continued = carried(SINGLE)?;
    let engaged = KillswitchState::Engaged {
        at: START,
        reason: HaltReason::OperatorStop,
        level: SINGLE,
    };
    assert_eq!(continued.killswitch(), engaged);
    assert_eq!(continued.killswitch().level(), Some(SINGLE));
    let outcome = continued.decide(&action("intent-carried", RiskTier::TierCRoutineBounded)?);
    assert_eq!(
        outcome.block_reason(),
        Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop))
    );
    let refusal = last_draft(&continued)?;
    assert_eq!(refusal.status, RecordStatus::Halted);
    assert_eq!(refusal.killswitch, engaged);

    let mut armed = engine(600, 4)?;
    let allowed = armed.decide(&action("intent-armed", RiskTier::TierCRoutineBounded)?);
    assert_eq!(allowed, InterceptorOutcome::Allow);
    assert_eq!(anchor_of(&armed)?.killswitch(), KillswitchState::Armed);
    assert_eq!(anchor_of(&armed)?.killswitch().level(), None);
    Ok(())
}

/// Positive: a halt of the lowest level is released by one person, and so is
/// a level whose actions pass with a notice. The release is a record.
#[test]
fn the_lowest_level_is_released_by_one_person() -> Fallible<()> {
    for level in [RiskLevel::LOWEST, MONITORED] {
        assert!(!level.required_approval().needs_human());
        let mut continued = carried(level)?;
        let released = continued.release_halt(&releaser()?, None)?;
        assert_eq!(released, continued.ledger().head());
        assert_eq!(continued.killswitch(), KillswitchState::Armed);
        let draft = last_draft(&continued)?;
        assert_eq!(draft, RecordDraft::of_latch(KillswitchState::Armed, START));
        assert_eq!(draft.status, RecordStatus::HaltReleased);
        let outcome = continued.decide(&action("intent-resumed", RiskTier::TierCRoutineBounded)?);
        assert_eq!(outcome, InterceptorOutcome::Allow);
    }
    Ok(())
}

/// Positive: where the level needs checkers, the release passes with as many
/// as the level's actions need, none of them the releaser.
#[test]
fn a_release_passes_with_the_approval_the_level_demands() -> Fallible<()> {
    let mut single = carried(SINGLE)?;
    single.release_halt(&releaser()?, Some(one("checker-bob")?))?;
    assert_eq!(single.killswitch(), KillswitchState::Armed);

    for level in [DUAL, RiskLevel::HIGHEST] {
        let mut dual = carried(level)?;
        dual.release_halt(&releaser()?, Some(two("checker-bob", "checker-eve")?))?;
        assert_eq!(dual.killswitch(), KillswitchState::Armed);
        assert_eq!(last_draft(&dual)?.status, RecordStatus::HaltReleased);
    }
    Ok(())
}

/// Positive: a halt whose record could not be written is written by the next
/// call of `halt`, and by no call after that.
#[test]
fn a_halt_record_that_failed_is_written_by_the_next_halt() -> Fallible<()> {
    let mut flaky: EngineWith<SwitchSink, FixedClock> = DecisionEngine::new(
        config(600, 4)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        SwitchSink {
            inner: InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        },
        io_deadline(),
        FixedClock::new(START),
    );
    DOWN.set(true);
    let unwritten = flaky.halt(HaltReason::OperatorStop, SINGLE);
    DOWN.set(false);
    assert_eq!(
        unwritten,
        Err(LedgerError::Sink(SinkError::Unavailable)),
        "the caller is told the chain does not show the halt"
    );
    assert_eq!(
        flaky.killswitch().level(),
        Some(SINGLE),
        "halted all the same"
    );
    assert!(flaky.ledger().sink().inner.accepted().is_empty());

    flaky.halt(HaltReason::OperatorStop, SINGLE)?;
    flaky.halt(HaltReason::OperatorStop, SINGLE)?;
    let stored = flaky.ledger().sink().inner.accepted();
    assert_eq!(stored.len(), 1, "written once");
    assert_eq!(last_draft(&flaky)?.status, RecordStatus::HaltEngaged);
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative, planted: a release without the approval the level demands is
/// refused, writes nothing and leaves the engine halted.
#[test]
fn a_release_without_the_needed_approval_is_refused() -> Fallible<()> {
    let cases = [
        (SINGLE, RequiredApproval::SingleChecker),
        (DUAL, RequiredApproval::DualDistinctCheckers),
        (RiskLevel::HIGHEST, RequiredApproval::DualDistinctCheckers),
    ];
    for (level, required) in cases {
        let mut continued = carried(level)?;
        assert_eq!(
            continued.release_halt(&releaser()?, None),
            Err(ReleaseError::ApprovalMissing { required }),
            "{level:?}"
        );
        assert_eq!(continued.killswitch().level(), Some(level));
        assert_eq!(
            continued.ledger().len(),
            0,
            "a refused release writes nothing"
        );
    }
    Ok(())
}

/// Negative, planted: a panel smaller than the level demands is refused, and
/// so is two times the same checker.
#[test]
fn an_undersized_panel_does_not_release() -> Fallible<()> {
    for level in [DUAL, RiskLevel::HIGHEST] {
        let mut continued = carried(level)?;
        assert_eq!(
            continued.release_halt(&releaser()?, Some(one("checker-bob")?)),
            Err(ReleaseError::Approval(
                OversightError::AnnexIiiRequiresTwoCheckers
            ))
        );
        assert!(continued.killswitch().is_engaged());
        assert_eq!(continued.ledger().len(), 0);
    }
    assert_eq!(
        two("checker-bob", "checker-bob")
            .err()
            .map(|e| e.to_string()),
        Some(OversightError::DuplicateChecker.to_string())
    );
    Ok(())
}

/// Negative, planted: the releaser is no checker of the own release, at a
/// level that needs checkers and at one that needs none.
#[test]
fn a_panel_that_names_the_releaser_is_refused() -> Fallible<()> {
    let own = ReleaseError::Approval(OversightError::MakerIsChecker);
    for level in [RiskLevel::LOWEST, SINGLE] {
        let mut continued = carried(level)?;
        assert_eq!(
            continued.release_halt(&releaser()?, Some(one("olga")?)),
            Err(own),
            "{level:?}"
        );
        assert!(continued.killswitch().is_engaged());
    }
    let mut dual = carried(RiskLevel::HIGHEST)?;
    assert_eq!(
        dual.release_halt(&releaser()?, Some(two("checker-bob", "olga")?)),
        Err(own)
    );
    assert!(dual.killswitch().is_engaged());

    let mut lowest = carried(RiskLevel::LOWEST)?;
    lowest.release_halt(&releaser()?, Some(one("checker-bob")?))?;
    assert_eq!(lowest.killswitch(), KillswitchState::Armed);
    Ok(())
}

/// Negative: only a halt the engine took over is released. An armed engine,
/// an engine that halted itself, and an engine that halted again on top of
/// the halt it took over all refuse.
#[test]
fn a_release_is_refused_outside_an_inherited_halt() -> Fallible<()> {
    let mut armed = engine(600, 4)?;
    assert_eq!(
        armed.release_halt(&releaser()?, None),
        Err(ReleaseError::NotHalted)
    );

    let mut own = halted_at(RiskLevel::LOWEST)?;
    assert_eq!(
        own.release_halt(&releaser()?, None),
        Err(ReleaseError::NotInherited)
    );

    let mut again = carried(RiskLevel::LOWEST)?;
    again.halt(HaltReason::OperatorStop, RiskLevel::LOWEST)?;
    assert_eq!(
        again.release_halt(&releaser()?, None),
        Err(ReleaseError::NotInherited),
        "a halt of the engine's own is not undone with the one it took over"
    );

    let mut released = carried(RiskLevel::LOWEST)?;
    released.release_halt(&releaser()?, None)?;
    released.halt(HaltReason::OperatorStop, RiskLevel::LOWEST)?;
    assert_eq!(
        released.release_halt(&releaser()?, None),
        Err(ReleaseError::NotInherited)
    );
    assert!(released.killswitch().is_engaged());
    Ok(())
}

/// Negative: a refused release travels in the crate's one error type with its
/// reason, and reads as one.
#[test]
fn a_refused_release_is_a_decision_error() -> Fallible<()> {
    /// Releases through `?`, as a caller that returns the crate error does.
    fn release(engine: &mut TestEngine) -> Result<Digest32, DecisionError> {
        Ok(engine.release_halt(&MakerId::parse("olga")?, None)?)
    }
    let mut armed = engine(600, 4)?;
    let refused = release(&mut armed);
    assert_eq!(
        refused,
        Err(DecisionError::Release(ReleaseError::NotHalted))
    );
    assert_ne!(
        refused,
        Err(DecisionError::Release(ReleaseError::NotInherited))
    );
    let text = DecisionError::Release(ReleaseError::NotHalted).to_string();
    assert!(text.starts_with("release: "), "{text}");
    Ok(())
}

/// Negative, planted: the release record is the commit point. With a store
/// or a signer that cannot take the record, the engine stays halted.
#[test]
fn a_release_that_cannot_be_recorded_does_not_release() -> Fallible<()> {
    let mut no_store = carried_with(
        RiskLevel::LOWEST,
        SignerBinding::Bound(FixtureSigner::new()?),
        UnavailableSink::new(),
        FixedClock::new(START),
    )?;
    assert_eq!(
        no_store.release_halt(&releaser()?, None),
        Err(ReleaseError::Ledger(LedgerError::Sink(
            SinkError::Unavailable
        )))
    );
    assert_eq!(no_store.killswitch().level(), Some(RiskLevel::LOWEST));

    let mut no_signer = carried_with(
        RiskLevel::LOWEST,
        SignerBinding::unbound(),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        FixedClock::new(START),
    )?;
    let unsigned = no_signer.release_halt(&releaser()?, None);
    assert!(
        matches!(unsigned, Err(ReleaseError::Ledger(LedgerError::Sign(_)))),
        "{unsigned:?}"
    );
    assert!(no_signer.killswitch().is_engaged());
    assert!(no_signer.ledger().sink().accepted().is_empty());
    Ok(())
}

/// Negative: a release reads the clock, and a clock that fails or stands
/// before the head record releases nothing.
#[test]
fn a_release_under_a_clock_fault_does_not_release() -> Fallible<()> {
    let mut broken = carried_with(
        RiskLevel::LOWEST,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        FaultyClock,
    )?;
    assert_eq!(
        broken.release_halt(&releaser()?, None),
        Err(ReleaseError::Clock(ClockError::BeforeEpoch))
    );
    assert!(broken.killswitch().is_engaged());

    let mut early = carried_with(
        RiskLevel::LOWEST,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        FixedClock::new(UnixSeconds::new(999)),
    )?;
    assert_eq!(
        early.release_halt(&releaser()?, None),
        Err(ReleaseError::Clock(ClockError::NonMonotonic {
            last: 1_000,
            observed: 999,
        }))
    );
    assert!(early.killswitch().is_engaged());
    assert_eq!(early.ledger().len(), 0);
    Ok(())
}

/// Negative: a halt whose record cannot be written reports that, and halts
/// all the same.
#[test]
fn a_halt_that_cannot_be_recorded_still_halts() -> Fallible<()> {
    let mut unsigned = unsigned_engine()?;
    let unwritten = unsigned.halt(HaltReason::OperatorStop, SINGLE);
    assert!(
        matches!(unwritten, Err(LedgerError::Sign(_))),
        "{unwritten:?}"
    );
    assert_eq!(unsigned.killswitch().level(), Some(SINGLE));
    assert!(unsigned.ledger().sink().accepted().is_empty());
    let outcome = unsigned.decide(&action("intent-after", RiskTier::TierCRoutineBounded)?);
    assert_eq!(
        outcome.block_reason(),
        Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop))
    );
    Ok(())
}

/// Negative, planted: a record whose status and fields do not belong together
/// has no canonical pre-image, so it cannot enter a chain.
#[test]
fn a_record_of_the_wrong_shape_has_no_preimage() -> Fallible<()> {
    let engaged = KillswitchState::Engaged {
        at: START,
        reason: HaltReason::OperatorStop,
        level: RiskLevel::LOWEST,
    };
    let subject = RecordSubject {
        intent_id: IntentId::parse("intent-shaped")?,
        agent: AgentId::parse("agent-01")?,
        action_type: ActionType::FileModification,
    };
    let halt = RecordDraft::of_latch(engaged, START);
    let release = RecordDraft::of_latch(KillswitchState::Armed, START);
    let decided = RecordDraft {
        subject: Some(subject),
        status: RecordStatus::Approved,
        ..release
    };
    for sound in [halt, release, decided] {
        assert!(sound.is_well_formed(), "{sound:?}");
        assert!(preimage_refusal(sound).is_none(), "{sound:?}");
    }
    let unsound = [
        RecordDraft {
            subject: Some(subject),
            ..halt
        },
        RecordDraft {
            block_reason: Some(BlockReason::AuditUnavailable),
            ..halt
        },
        RecordDraft {
            killswitch: KillswitchState::Armed,
            ..halt
        },
        RecordDraft {
            subject: Some(subject),
            ..release
        },
        RecordDraft {
            killswitch: engaged,
            ..release
        },
        RecordDraft {
            subject: None,
            ..decided
        },
    ];
    for draft in unsound {
        assert!(!draft.is_well_formed(), "{draft:?}");
        assert_eq!(preimage_refusal(draft), Some(PreimageError::Shape));
    }
    Ok(())
}

/// Why `draft` has no canonical pre-image at the first chain position, if it
/// has none.
fn preimage_refusal(draft: RecordDraft) -> Option<PreimageError> {
    RecordBody::from_parts(
        Sequence::FIRST,
        Digest32::GENESIS,
        HashAlgorithm::Sha256,
        draft,
    )
    .canonical_preimage()
    .err()
}

// --- Boundary -------------------------------------------------------------

/// Boundary: a fault the engine finds with no action in hand halts at the
/// highest level, and one found on a held action halts at that action's.
#[test]
fn a_fault_with_no_action_in_hand_halts_at_the_highest_level() -> Fallible<()> {
    let mut broken = faulty_clock_engine()?;
    let unknown = broken.adjudicate(
        &RequestId::parse("request-unknown")?,
        one("checker-bob")?,
        Vote::Approve,
    );
    assert_eq!(unknown, Err(DecisionError::Clock(ClockError::BeforeEpoch)));
    assert_eq!(broken.killswitch().level(), Some(RiskLevel::HIGHEST));
    assert_eq!(last_draft(&broken)?.status, RecordStatus::HaltEngaged);

    let mut holding = engine(600, 4)?;
    let held = holding.decide(&action("intent-held", RiskTier::TierAConsequential)?);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    assert_eq!(ticket.level(), SINGLE);
    holding.clock_mut().set(UnixSeconds::new(999));
    let faulted = holding.adjudicate(ticket.request_id(), one("checker-bob")?, Vote::Approve);
    assert!(
        matches!(faulted, Err(DecisionError::Clock(_))),
        "{faulted:?}"
    );
    assert_eq!(
        holding.killswitch().level(),
        Some(SINGLE),
        "the level of the held action, not the highest"
    );
    assert_eq!(last_draft(&holding)?.killswitch.level(), Some(SINGLE));
    Ok(())
}

/// Boundary: a fault found while deciding halts at the level of the action
/// being decided, whether the clock or the audit path failed.
#[test]
fn a_fault_while_deciding_halts_at_the_level_of_the_action() -> Fallible<()> {
    let proposal = action("intent-faulted", RiskTier::TierBMaterialReversible)?;
    assert_eq!(proposal.level(), MONITORED);

    let mut broken = faulty_clock_engine()?;
    let outcome = broken.decide(&proposal);
    assert_eq!(outcome.block_reason(), Some(BlockReason::ClockUnavailable));
    assert_eq!(broken.killswitch().level(), Some(MONITORED));
    assert_eq!(broken.ledger().len(), 1, "the refusal is the halt's record");
    let refusal = last_draft(&broken)?;
    assert_eq!(refusal.status, RecordStatus::Blocked);
    assert_eq!(refusal.killswitch.level(), Some(MONITORED));

    let mut unsigned = unsigned_engine()?;
    let unrecorded = unsigned.decide(&proposal);
    assert_eq!(
        unrecorded.block_reason(),
        Some(BlockReason::AuditUnavailable)
    );
    assert_eq!(
        unsigned.killswitch().reason(),
        Some(HaltReason::AuditUnavailable)
    );
    assert_eq!(unsigned.killswitch().level(), Some(MONITORED));
    Ok(())
}

/// Boundary: the level of a halt only rises. A stricter halt is a record of
/// its own, a weaker one writes nothing, and a continuation takes the level
/// the chain ends on.
#[test]
fn the_level_of_a_halt_only_rises() -> Fallible<()> {
    let mut halted = halted_at(SINGLE)?;
    halted.halt(HaltReason::OperatorStop, RiskLevel::LOWEST)?;
    assert_eq!(halted.killswitch().level(), Some(SINGLE));
    assert_eq!(halted.ledger().len(), 1, "a weaker halt writes nothing");

    halted.halt(HaltReason::OperatorStop, RiskLevel::HIGHEST)?;
    assert_eq!(halted.killswitch().level(), Some(RiskLevel::HIGHEST));
    assert_eq!(
        halted.ledger().len(),
        2,
        "a stricter halt is a second record"
    );
    assert_eq!(last_draft(&halted)?.status, RecordStatus::HaltEngaged);
    assert_eq!(
        last_draft(&halted)?.killswitch.level(),
        Some(RiskLevel::HIGHEST)
    );
    assert_eq!(
        anchor_of(&halted)?.killswitch().level(),
        Some(RiskLevel::HIGHEST)
    );

    let mut continued = carried(SINGLE)?;
    let carried_over = continued.ledger().len();
    continued.halt(HaltReason::OperatorStop, RiskLevel::LOWEST)?;
    continued.halt(HaltReason::OperatorStop, SINGLE)?;
    assert_eq!(
        continued.killswitch().level(),
        Some(SINGLE),
        "a halt on top of an inherited one does not lower its level"
    );
    assert_eq!(
        continued.ledger().len(),
        carried_over,
        "the chain carries this halt already: it is not written again"
    );
    Ok(())
}

/// Boundary: a vote that cannot be recorded halts at the level of the action
/// it was cast on, as every fault on a held action does.
#[test]
fn a_vote_that_cannot_be_recorded_halts_at_the_level_of_the_action() -> Fallible<()> {
    let mut flaky: EngineWith<SwitchSink, FixedClock> = DecisionEngine::new(
        config(600, 4)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        SwitchSink {
            inner: InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        },
        io_deadline(),
        FixedClock::new(START),
    );
    let held = flaky.decide(&action("intent-held", RiskTier::TierAConsequential)?);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    DOWN.set(true);
    let unrecorded = flaky.adjudicate(ticket.request_id(), one("checker-bob")?, Vote::Approve);
    DOWN.set(false);

    assert_eq!(
        unrecorded,
        Err(DecisionError::Ledger(LedgerError::Sink(
            SinkError::Unavailable
        )))
    );
    assert_eq!(
        flaky.killswitch().reason(),
        Some(HaltReason::AuditUnavailable)
    );
    assert_eq!(
        flaky.killswitch().level(),
        Some(SINGLE),
        "the level of the held action, neither the lowest nor the highest"
    );
    Ok(())
}

/// Boundary: the order of levels, from the one that demands least.
#[test]
fn levels_are_ordered() {
    let rising = [
        RiskLevel::LOWEST,
        MONITORED,
        SINGLE,
        DUAL,
        RiskLevel::HIGHEST,
    ];
    for pair in rising.windows(2) {
        let [lower, higher] = *pair else { continue };
        assert_eq!(lower.stricter(higher), higher, "{lower:?} {higher:?}");
        assert_eq!(higher.stricter(lower), higher, "{lower:?} {higher:?}");
        assert_eq!(lower.stricter(lower), lower);
    }
}

/// Boundary: the tag each level is written as, and the tags no level has.
#[test]
fn levels_are_tagged() {
    assert_eq!(RiskLevel::LOWEST.tag(), 1);
    assert_eq!(RiskLevel::HIGHEST.tag(), 6);
    for tag in 1..=6u8 {
        assert_eq!(RiskLevel::from_tag(tag).map(RiskLevel::tag), Some(tag));
    }
    assert_eq!(RiskLevel::from_tag(0), None, "zero is no level");
    assert_eq!(RiskLevel::from_tag(7), None);
}

/// Boundary: the two records of the latch itself are told apart from every
/// record that decides an action, the refusal under a halt included. A schema
/// that carries decisions only refuses a latch record by this answer.
#[test]
fn only_the_two_latch_records_are_of_the_latch() {
    for of_latch in [RecordStatus::HaltEngaged, RecordStatus::HaltReleased] {
        assert!(of_latch.is_of_latch(), "{of_latch:?}");
    }
    for decides in [
        RecordStatus::PendingApproval,
        RecordStatus::Approved,
        RecordStatus::Rejected,
        RecordStatus::Blocked,
        RecordStatus::Halted,
    ] {
        assert!(!decides.is_of_latch(), "{decides:?}");
    }
}
