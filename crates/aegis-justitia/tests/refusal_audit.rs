// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Every refusal is audited, and the clock is load-bearing.
//!
//! `decide` writes exactly one record per call on every arm. A refusal that the
//! engine itself produced carries the reason that produced it; a refusal that
//! cannot be recorded at all halts the unit instead of passing quietly. The
//! clock the engine reads is its own, and both clock faults -- an unusable
//! source and a backwards step -- fail closed.

mod common;

use aegis_justitia::{
    ActionType, BlockReason, CheckerId, CheckerSet, ClockError, HaltReason, JustitiaError,
    LedgerError, OversightClass, RecordStatus, RegistryError, RiskTier, UnixSeconds, Vote,
};

use common::{
    Fallible, FixtureError, START, engine, engine_with_audit_bound, faulty_clock_engine, intent,
    unsigned_engine,
};

// --- Positive -------------------------------------------------------------

/// Positive: an engine refusal is recorded, with its reason, in the chain.
#[test]
fn an_engine_refusal_is_recorded_with_its_reason() -> Fallible<()> {
    let mut engine = engine(600, 1)?;
    let first = intent(
        "intent-audited-1",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    assert!(engine.decide(&first).ticket().is_some());
    assert_eq!(engine.ledger().len(), 1);

    let second = intent(
        "intent-audited-2",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let refused = engine.decide(&second);
    assert_eq!(refused.block_reason(), Some(BlockReason::RegistryFull));
    assert_eq!(
        engine.ledger().len(),
        2,
        "the refusal produced an audit record of its own"
    );
    let record = engine
        .ledger()
        .records()
        .get(1)
        .copied()
        .ok_or(FixtureError::NoRecord)?;
    assert_eq!(record.body().draft().status, RecordStatus::Blocked);
    assert_eq!(
        record.body().draft().block_reason,
        Some(BlockReason::RegistryFull),
        "the record names the reason the action was refused"
    );
    assert_eq!(
        record.body().draft().intent_id.to_string(),
        "intent-audited-2"
    );
    engine.verify_ledger()?;
    Ok(())
}

/// Positive, second half: the killswitch refusal is recorded with the halt
/// reason that produced it.
#[test]
fn a_halted_refusal_is_recorded_with_the_halt_reason() -> Fallible<()> {
    let mut engine = engine(600, 4)?;
    engine.halt(HaltReason::OperatorStop);
    let proposal = intent(
        "intent-halted",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let blocked = engine.decide(&proposal);
    assert_eq!(
        blocked.block_reason(),
        Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop))
    );
    let record = engine
        .ledger()
        .records()
        .first()
        .ok_or(FixtureError::NoRecord)?;
    assert_eq!(record.body().draft().status, RecordStatus::Halted);
    assert_eq!(
        record.body().draft().block_reason,
        Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop))
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a broken clock blocks the action, halts the unit with
/// `HaltReason::ClockUnavailable`, and records the refusal.
#[test]
fn a_clock_fault_fails_closed_and_halts_the_unit() -> Fallible<()> {
    let mut engine = faulty_clock_engine()?;
    assert_eq!(engine.now(), Err(ClockError::BeforeEpoch));
    assert!(!engine.killswitch().is_engaged());

    let proposal = intent(
        "intent-clock-fault",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let blocked = engine.decide(&proposal);
    assert_eq!(
        blocked.block_reason(),
        Some(BlockReason::ClockUnavailable),
        "a Tier C action that would otherwise be allowed is refused on a clock fault"
    );
    assert!(!blocked.permits_execution());
    assert_eq!(
        engine.killswitch().reason(),
        Some(HaltReason::ClockUnavailable),
        "the clock fault engages the halt latch"
    );
    let record = engine
        .ledger()
        .records()
        .first()
        .ok_or(FixtureError::NoRecord)?;
    assert_eq!(record.body().draft().status, RecordStatus::Blocked);
    assert_eq!(
        record.body().draft().block_reason,
        Some(BlockReason::ClockUnavailable)
    );
    Ok(())
}

/// Negative, second half: adjudication reads the same clock and refuses on the
/// same fault, so no decision is accepted against an unknown time.
#[test]
fn adjudication_refuses_on_a_clock_fault() -> Fallible<()> {
    let mut engine = faulty_clock_engine()?;
    let forged = aegis_justitia::RequestId::parse("intent-never-issued")?;
    let panel = CheckerSet::single(CheckerId::parse("checker-ada")?);
    let refused = engine.adjudicate(&forged, panel, Vote::Approve);
    assert_eq!(
        refused,
        Err(JustitiaError::Clock(ClockError::BeforeEpoch)),
        "the clock is read before the request is looked up, so no vote is timed by a caller"
    );
    assert_eq!(
        engine.killswitch().reason(),
        Some(HaltReason::ClockUnavailable)
    );
    Ok(())
}

/// Negative, third: a clock that steps backwards is a fault too, caught by the
/// monotonic guard rather than by the ledger's timestamp check.
#[test]
fn a_backwards_clock_step_fails_closed() -> Fallible<()> {
    let mut engine = engine(600, 4)?;
    let proposal = intent(
        "intent-step",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    assert!(engine.decide(&proposal).permits_execution());

    engine.clock_mut().set(UnixSeconds::new(999));
    let stepped = intent(
        "intent-step-2",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let blocked = engine.decide(&stepped);
    assert_eq!(
        blocked.block_reason(),
        Some(BlockReason::ClockUnavailable),
        "a backwards step is refused rather than backdating the chain"
    );
    assert_eq!(
        engine.killswitch().reason(),
        Some(HaltReason::ClockUnavailable)
    );
    Ok(())
}

/// Negative, fourth: a refusal that cannot itself be recorded escalates to
/// `HaltReason::AuditUnavailable` rather than passing silently.
#[test]
fn an_unrecordable_refusal_halts_the_unit() -> Fallible<()> {
    let mut engine = unsigned_engine()?;
    let proposal = intent(
        "intent-unrecordable",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let blocked = engine.decide(&proposal);
    assert_eq!(blocked.block_reason(), Some(BlockReason::AuditUnavailable));
    assert_eq!(
        engine.killswitch().reason(),
        Some(HaltReason::AuditUnavailable),
        "there is nowhere to record the refusal, so the unit halts visibly instead"
    );
    assert_eq!(engine.ledger().len(), 0, "nothing was committed");

    let next = engine.decide(&proposal);
    assert_eq!(
        next.block_reason(),
        Some(BlockReason::KillswitchEngaged(HaltReason::AuditUnavailable)),
        "every later action blocks on the latch the audit failure engaged"
    );
    Ok(())
}

/// Negative, fifth: a human decision that cannot be recorded is not silently
/// lost. `adjudicate` applies the same discipline `decide` does -- the vote is
/// either in the chain or the unit is visibly halted -- and it leaves no orphan
/// hold behind, so the registry never believes a lost decision was taken.
#[test]
fn an_unrecordable_adjudication_halts_the_unit_and_leaves_no_hold() -> Fallible<()> {
    // One audit slot: the hold consumes it, so the vote cannot be appended.
    let mut engine = engine_with_audit_bound(600, 4, 1)?;
    let proposal = intent(
        "intent-lost-vote",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let held = engine.decide(&proposal);
    let ticket = *held.ticket().ok_or(FixtureError::NoTicket)?;
    assert_eq!(
        engine.ledger().len(),
        1,
        "the hold used the only audit slot"
    );

    let panel = CheckerSet::single(CheckerId::parse("checker-bo")?);
    let refused = engine.adjudicate(ticket.request_id(), panel, Vote::Approve);
    assert_eq!(
        refused,
        Err(JustitiaError::Ledger(LedgerError::LengthBoundExceeded {
            max: 1
        })),
        "the overseer is told the decision could not be recorded"
    );
    assert!(
        !engine
            .ledger()
            .records()
            .iter()
            .any(|record| record.body().draft().status == RecordStatus::Approved),
        "the vote is not in the chain"
    );
    assert_eq!(
        engine.killswitch().reason(),
        Some(HaltReason::AuditUnavailable),
        "so the unit is visibly halted instead"
    );
    assert_eq!(
        engine.registry().get(ticket.request_id()),
        Err(RegistryError::Unknown),
        "no orphan hold survives, and the registry does not claim the request was decided"
    );
    assert_eq!(engine.registry().live(START), 0);
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: exactly one audit record is written per `decide`, on every arm,
/// and a held request that cannot be sealed leaves no hold behind.
#[test]
fn exactly_one_record_per_decision_and_no_orphan_hold() -> Fallible<()> {
    let mut engine = engine(600, 2)?;
    let allowed = intent(
        "intent-one-allow",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let warned = intent(
        "intent-one-warn",
        "maker-alice",
        ActionType::ExternalNetworkRequest,
        RiskTier::TierBMaterialReversible,
        OversightClass::Standard,
    )?;
    let held = intent(
        "intent-one-hold",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    for (index, proposal) in [&allowed, &warned, &held].into_iter().enumerate() {
        let _outcome = engine.decide(proposal);
        assert_eq!(
            engine.ledger().len(),
            index.saturating_add(1),
            "decision {index} wrote exactly one record"
        );
    }

    let mut unsealable = unsigned_engine()?;
    let orphan = intent(
        "intent-orphan-hold",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let blocked = unsealable.decide(&orphan);
    assert_eq!(blocked.block_reason(), Some(BlockReason::AuditUnavailable));
    assert!(
        unsealable.registry().is_empty(),
        "a hold whose decision could not be sealed is released, not left to consume the bound"
    );
    Ok(())
}
