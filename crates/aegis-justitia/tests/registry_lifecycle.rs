// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The pending-request bound is a concurrency bound, driven through the engine.
//!
//! A `RequestId` is derived deterministically from the `IntentId`, so without
//! reclamation the bound would be a lifetime cap on distinct intents and a
//! legitimate retry would collide with its own finished attempt. These tests
//! drive the public engine API only, so they fail if reclamation is removed
//! from either the decision or the expiry path.

mod common;

use aegis_justitia::{
    ActionType, BlockReason, CheckerId, CheckerSet, OversightClass, RiskTier, UnixSeconds, Vote,
};

use common::{Fallible, FixtureError, engine, intent};

/// Builds the Tier A escalation used throughout, which always needs a checker.
fn held_intent(id: &str) -> Result<aegis_justitia::ActionIntent, aegis_justitia::JustitiaError> {
    intent(
        id,
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )
}

// --- Positive -------------------------------------------------------------

/// Positive: a decided request is reclaimed, so the same identifier can be
/// proposed again and the bound is freed.
#[test]
fn a_decided_request_is_reclaimed_and_the_identifier_is_reusable() -> Fallible<()> {
    let mut engine = engine(600, 1)?;
    let proposal = held_intent("intent-retry")?;

    let first = engine.decide(&proposal);
    let ticket = first.ticket().copied().ok_or(FixtureError::NoTicket)?;
    assert_eq!(engine.registry().live(common::START), 1);

    let panel = CheckerSet::single(CheckerId::parse("checker-bo")?);
    let _decision = engine.adjudicate(ticket.request_id(), panel, Vote::Approve)?;
    assert_eq!(
        engine.registry().live(common::START),
        0,
        "a decided request stops counting against the bound immediately"
    );

    let retry = engine.decide(&proposal);
    assert!(
        retry.ticket().is_some(),
        "a retry of a decided identifier is held again, not refused as a duplicate"
    );
    assert_eq!(
        engine.registry().len(),
        1,
        "the finished entry was reclaimed rather than accumulating"
    );
    Ok(())
}

/// Positive, second half: an expired request is reclaimed once its window
/// closes, so the bound recovers without any operator action.
#[test]
fn an_expired_request_is_reclaimed_once_its_window_closes() -> Fallible<()> {
    let mut engine = engine(10, 1)?;
    let first = held_intent("intent-expiring")?;
    assert!(engine.decide(&first).ticket().is_some());

    let second = held_intent("intent-after-expiry")?;
    engine.clock_mut().set(UnixSeconds::new(1_009));
    assert_eq!(
        engine.decide(&second).block_reason(),
        Some(BlockReason::RegistryFull),
        "one second before the due time the first request is still live"
    );

    let third = held_intent("intent-after-expiry-2")?;
    engine.clock_mut().set(UnixSeconds::new(1_010));
    assert!(
        engine.decide(&third).ticket().is_some(),
        "at the due time the closed window is reclaimed and the bound is free"
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a still-pending duplicate identifier is refused, and is named as a
/// duplicate rather than as a decided request.
#[test]
fn a_still_pending_duplicate_identifier_is_refused() -> Fallible<()> {
    let mut engine = engine(600, 4)?;
    let proposal = held_intent("intent-duplicate")?;
    assert!(engine.decide(&proposal).ticket().is_some());

    let again = engine.decide(&proposal);
    assert_eq!(
        again.block_reason(),
        Some(BlockReason::RequestAlreadyPending),
        "a live duplicate is refused as a duplicate, not mislabelled as decided"
    );
    assert!(!again.permits_execution());
    assert_eq!(
        engine.registry().live(common::START),
        1,
        "the refused duplicate did not consume a second slot"
    );
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: one under the bound is held, exactly at the bound is held, one
/// over is refused, and a retry after reclamation succeeds.
#[test]
fn the_bound_holds_at_exactly_max_pending_and_recovers() -> Fallible<()> {
    let max_pending = 3usize;
    let mut engine = engine(600, max_pending)?;
    let names = ["intent-b1", "intent-b2", "intent-b3"];

    let mut tickets = Vec::with_capacity(max_pending);
    for (index, name) in names.iter().enumerate() {
        let proposal = held_intent(name)?;
        let outcome = engine.decide(&proposal);
        let ticket = outcome.ticket().copied().ok_or(FixtureError::NoTicket)?;
        tickets.push(ticket);
        let live = index.saturating_add(1);
        assert_eq!(
            engine.registry().live(common::START),
            live,
            "{live} live requests are held, the last of them exactly at the bound"
        );
    }

    let over = held_intent("intent-b4")?;
    assert_eq!(
        engine.decide(&over).block_reason(),
        Some(BlockReason::RegistryFull),
        "one over the bound is refused"
    );

    let released = tickets.first().copied().ok_or(FixtureError::NoTicket)?;
    let panel = CheckerSet::single(CheckerId::parse("checker-zoe")?);
    let _decision = engine.adjudicate(released.request_id(), panel, Vote::Reject)?;
    assert_eq!(
        engine.registry().live(common::START),
        max_pending.saturating_sub(1),
        "one under the bound after the decision"
    );

    let retry = held_intent("intent-b4")?;
    assert!(
        engine.decide(&retry).ticket().is_some(),
        "the slot the decision freed is usable, so the engine does not wedge at the bound"
    );
    Ok(())
}
