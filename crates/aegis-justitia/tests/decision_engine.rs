// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Epic E02-2: the decision engine, positive, negative and boundary.
//!
//! The three test functions below are named for the three acceptance clauses of
//! E02-2 and assert exactly what those clauses state.

mod common;

use aegis_justitia::{
    ActionType, Adjudication, BlockReason, CheckerId, CheckerSet, HaltReason, InterceptorOutcome,
    JustitiaError, MakerId, OversightClass, OversightError, RequestId, RequiredApproval, RiskTier,
    UnixSeconds, Vote,
};

use common::{Fallible, FixtureError, engine, intent};

// --- Positive -------------------------------------------------------------

/// E02-2 positive: a Tier C action is allowed, and two distinct non-maker
/// checkers are accepted.
#[test]
fn tier_c_is_allowed_and_two_distinct_non_maker_checkers_are_accepted() -> Fallible<()> {
    let mut engine = engine(60, 8)?;

    let routine = intent(
        "intent-tier-c",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let outcome = engine.decide(&routine);
    assert_eq!(outcome, InterceptorOutcome::Allow);
    assert!(outcome.permits_execution());

    let escalation = intent(
        "intent-annex",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::AnnexIiiBiometric,
    )?;
    let held = engine.decide(&escalation);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    assert_eq!(ticket.required(), RequiredApproval::DualDistinctCheckers);
    assert!(
        !held.permits_execution(),
        "a held action must not execute before a checker decides"
    );

    let panel = CheckerSet::dual(
        CheckerId::parse("checker-bob")?,
        CheckerId::parse("checker-carol")?,
    )?;
    let decision = engine.adjudicate(ticket.request_id(), panel, Vote::Approve)?;
    assert!(matches!(decision, Adjudication::Approved { .. }));
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// E02-2 negative: maker as checker is rejected, and a duplicate checker is
/// rejected.
#[test]
fn maker_as_checker_is_rejected_and_duplicate_checker_is_rejected() -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    let escalation = intent(
        "intent-sep",
        "principal-dana",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let held = engine.decide(&escalation);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    assert_eq!(ticket.required(), RequiredApproval::SingleChecker);

    let self_panel = CheckerSet::single(CheckerId::parse("principal-dana")?);
    let refused = engine.adjudicate(ticket.request_id(), self_panel, Vote::Approve);
    assert_eq!(
        refused,
        Err(JustitiaError::Oversight(OversightError::MakerIsChecker))
    );

    let duplicate = CheckerSet::dual(
        CheckerId::parse("checker-erin")?,
        CheckerId::parse("checker-erin")?,
    );
    assert_eq!(duplicate, Err(OversightError::DuplicateChecker));

    let second_slot = CheckerSet::dual(
        CheckerId::parse("checker-erin")?,
        CheckerId::parse("principal-dana")?,
    )?;
    let refused_second = engine.adjudicate(ticket.request_id(), second_slot, Vote::Approve);
    assert_eq!(
        refused_second,
        Err(JustitiaError::Oversight(OversightError::MakerIsChecker)),
        "the maker must be refused in the second slot as well as the first"
    );
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// E02-2 boundary: due timestamps equal to now and to now-1 both fail closed,
/// and the killswitch blocks Tier C.
#[test]
fn due_equal_to_now_and_now_minus_one_fail_closed_and_killswitch_blocks_tier_c() -> Fallible<()> {
    let due_equals_now = adjudicate_at(1_001)?;
    assert_eq!(
        due_equals_now,
        Err(JustitiaError::Oversight(OversightError::ApprovalExpired)),
        "a window whose due time equals now is closed"
    );
    let due_one_before_now = adjudicate_at(1_002)?;
    assert_eq!(
        due_one_before_now,
        Err(JustitiaError::Oversight(OversightError::ApprovalExpired)),
        "a window whose due time is now-1 is closed"
    );
    let still_open = adjudicate_at(1_000)?;
    assert!(
        still_open.is_ok(),
        "a window whose due time is strictly after now is open"
    );

    let mut halted = engine(60, 8)?;
    halted.halt(HaltReason::OperatorStop);
    let routine = intent(
        "intent-tier-c-halted",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let blocked = halted.decide(&routine);
    assert_eq!(
        blocked.block_reason(),
        Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop)),
        "the killswitch is matched before any tier logic, so Tier C is blocked too"
    );
    assert!(!blocked.permits_execution());
    Ok(())
}

/// Opens a one-second approval window at 1000, so the due time is 1001, then
/// advances the engine's own clock to `at` and adjudicates.
fn adjudicate_at(at: u64) -> Fallible<Result<Adjudication, JustitiaError>> {
    let mut engine = engine(1, 8)?;
    let escalation = intent(
        "intent-window",
        "maker-frank",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let held = engine.decide(&escalation);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    assert_eq!(ticket.deadline().due_at().get(), 1_001);
    engine.clock_mut().set(UnixSeconds::new(at));
    let panel = CheckerSet::single(CheckerId::parse("checker-gina")?);
    Ok(engine.adjudicate(ticket.request_id(), panel, Vote::Approve))
}

/// A request identifier the engine never issued is refused, not trusted.
#[test]
fn an_unknown_request_identifier_is_refused() -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    let forged = RequestId::parse("intent-never-issued")?;
    let panel = CheckerSet::single(CheckerId::parse("checker-hal")?);
    let refused = engine.adjudicate(&forged, panel, Vote::Approve);
    assert_eq!(
        refused,
        Err(JustitiaError::Oversight(OversightError::UnknownRequest))
    );
    Ok(())
}

/// A decided request cannot be decided twice.
#[test]
fn a_decided_request_cannot_be_replayed() -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    let escalation = intent(
        "intent-replay",
        "maker-ines",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let held = engine.decide(&escalation);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    let panel = CheckerSet::single(CheckerId::parse("checker-jo")?);
    let first = engine.adjudicate(ticket.request_id(), panel, Vote::Reject)?;
    assert!(matches!(first, Adjudication::Rejected { .. }));
    let replay = engine.adjudicate(ticket.request_id(), panel, Vote::Approve);
    assert_eq!(
        replay,
        Err(JustitiaError::Oversight(OversightError::AlreadyDecided)),
        "a decided entry stays queryable until it is reclaimed, so the replay \
         is named rather than merely unknown"
    );
    Ok(())
}

/// A Tier B Annex III action demands two checkers, so a single-checker panel is
/// refused with no under-load fallback.
#[test]
fn a_single_checker_panel_is_refused_where_two_are_required() -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    let biometric = intent(
        "intent-biometric",
        "maker-kai",
        ActionType::ExternalNetworkRequest,
        RiskTier::TierBMaterialReversible,
        OversightClass::AnnexIiiBiometric,
    )?;
    let held = engine.decide(&biometric);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    assert_eq!(ticket.required(), RequiredApproval::DualDistinctCheckers);
    let panel = CheckerSet::single(CheckerId::parse("checker-lena")?);
    let refused = engine.adjudicate(ticket.request_id(), panel, Vote::Approve);
    assert_eq!(
        refused,
        Err(JustitiaError::Oversight(
            OversightError::AnnexIiiRequiresTwoCheckers
        ))
    );
    Ok(())
}

/// A maker identity is never taken from the caller: it is the one the engine
/// registered when it issued the ticket.
#[test]
fn the_maker_compared_against_is_the_one_the_engine_registered() -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    let escalation = intent(
        "intent-authority",
        "maker-mona",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let held = engine.decide(&escalation);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    assert_eq!(ticket.maker(), &MakerId::parse("maker-mona")?);
    Ok(())
}
