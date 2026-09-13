// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! HISS-03 and the memory arithmetic behind the default bounds.
//!
//! The crate documentation claims that the decision path performs no heap
//! allocation after construction, and names the products that the default
//! bounds retain without writing a byte figure for either. Both claims are
//! executable here: if the engine reallocates any of its three retention
//! buffers, or if a bound is raised past [`MAX_RETAINED_AUDIT_BYTES`], a test in
//! this file fails. The widths are computed from `size_of` on the building
//! target, so this file, not the prose, is the authority for the numbers.

mod common;

use aegis_justitia::{
    ActionType, ApprovalTicket, AuditRecord, BlockReason, InterceptorOutcome, MAX_LEDGER_RECORDS,
    MAX_PENDING_REQUESTS, MAX_RETAINED_AUDIT_BYTES, MAX_SIGNATURE_BYTES, OversightClass,
    RequestState, RiskTier,
};

use common::{FIXTURE_AUDIT_BOUND, Fallible, engine, intent};

// --- Positive -------------------------------------------------------------

/// Fills `engine`'s registry to `holds` with distinct held requests.
fn fill_registry(engine: &mut common::TestEngine, holds: usize) -> Fallible<()> {
    for step in 0..holds {
        let proposal = intent(
            &format!("intent-hold-{step}"),
            "maker-alice",
            ActionType::PermissionEscalation,
            RiskTier::TierAConsequential,
            OversightClass::Standard,
        )?;
        assert!(engine.decide(&proposal).ticket().is_some());
    }
    Ok(())
}

/// Drives `engine` for `steps` further decisions, alternating an action that is
/// released with one that is refused, so both audit arms are exercised.
fn drive_mixed(engine: &mut common::TestEngine, steps: usize) -> Fallible<()> {
    let mut refuse_next = false;
    for step in 0..steps {
        let (action, tier) = if refuse_next {
            (
                ActionType::PermissionEscalation,
                RiskTier::TierAConsequential,
            )
        } else {
            (ActionType::FileModification, RiskTier::TierCRoutineBounded)
        };
        refuse_next = !refuse_next;
        let proposal = intent(
            &format!("intent-fill-{step}"),
            "maker-alice",
            action,
            tier,
            OversightClass::Standard,
        )?;
        let _outcome = engine.decide(&proposal);
    }
    Ok(())
}

/// Positive: driving the engine to both bounds changes no reserved capacity.
///
/// This is the falsifier for the no-allocation claim. `Vec::push` only
/// reallocates when `len == capacity`; every buffer here is reserved to its
/// bound at construction and refuses a push at that bound, so a changed
/// `reserved()` is proof that a reallocation happened on the decision path.
#[test]
fn the_decision_path_never_reallocates() -> Fallible<()> {
    let holds = 4usize;
    let mut engine = engine(600, holds)?;

    let registry_reserved = engine.registry().reserved();
    let ledger_reserved = engine.ledger().reserved();
    let sink_reserved = engine.ledger().sink().reserved();
    assert!(registry_reserved >= holds);
    assert!(ledger_reserved >= FIXTURE_AUDIT_BOUND);
    assert!(sink_reserved >= FIXTURE_AUDIT_BOUND);

    fill_registry(&mut engine, holds)?;
    drive_mixed(&mut engine, FIXTURE_AUDIT_BOUND.saturating_sub(holds))?;

    assert_eq!(
        engine.ledger().len(),
        FIXTURE_AUDIT_BOUND,
        "the ledger reached its bound exactly"
    );
    assert_eq!(
        engine.registry().reserved(),
        registry_reserved,
        "the registry reallocated on the decision path"
    );
    assert_eq!(
        engine.ledger().reserved(),
        ledger_reserved,
        "the ledger reallocated on the decision path"
    );
    assert_eq!(
        engine.ledger().sink().reserved(),
        sink_reserved,
        "the sink reallocated on the decision path"
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: one action past the ledger bound is refused, and the refusal still
/// does not reallocate.
#[test]
fn one_action_past_the_audit_bound_is_refused_without_growing() -> Fallible<()> {
    let mut engine = engine(600, 2)?;
    let ledger_reserved = engine.ledger().reserved();
    let sink_reserved = engine.ledger().sink().reserved();

    for step in 0..=FIXTURE_AUDIT_BOUND {
        let proposal = intent(
            &format!("intent-over-{step}"),
            "maker-alice",
            ActionType::FileModification,
            RiskTier::TierCRoutineBounded,
            OversightClass::Standard,
        )?;
        let outcome = engine.decide(&proposal);
        if step < FIXTURE_AUDIT_BOUND {
            assert_eq!(
                outcome,
                InterceptorOutcome::Allow,
                "step {step} is inside the bound"
            );
        } else {
            assert_eq!(
                outcome.block_reason(),
                Some(BlockReason::AuditUnavailable),
                "one past the audit bound is refused, never allowed unaudited"
            );
        }
    }
    assert_eq!(engine.ledger().len(), FIXTURE_AUDIT_BOUND);
    assert_eq!(engine.ledger().reserved(), ledger_reserved);
    assert_eq!(engine.ledger().sink().reserved(), sink_reserved);
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the retained and pending budgets, computed from `size_of`.
///
/// The crate documentation deliberately states no byte figure. This test is the
/// authority instead: it computes the record and entry widths on the target that
/// is building the crate, so raising a bound, widening the signature, growing a
/// record or changing the target's padding fails the gate rather than leaving a
/// hand-written number in the documentation quietly wrong.
#[test]
fn the_retained_and_pending_budgets_are_computed_from_size_of() {
    let record = core::mem::size_of::<AuditRecord>();
    let retained = record.saturating_mul(MAX_LEDGER_RECORDS).saturating_mul(2);
    assert!(
        record >= MAX_SIGNATURE_BYTES,
        "the record is dominated by its {MAX_SIGNATURE_BYTES}-byte inline \
         signature, but measures only {record} bytes"
    );
    assert!(
        retained <= MAX_RETAINED_AUDIT_BYTES,
        "the default bounds retain {retained} bytes ({record} per record, \
         {MAX_LEDGER_RECORDS} records, held twice), past the \
         {MAX_RETAINED_AUDIT_BYTES}-byte budget"
    );
    assert!(
        retained > 2 << 20,
        "the budget is not so slack that it would catch nothing"
    );

    let entry = core::mem::size_of::<(ApprovalTicket, RequestState)>();
    let pending = entry.saturating_mul(MAX_PENDING_REQUESTS);
    assert!(
        pending <= 1 << 20,
        "the pending registry reserves {pending} bytes ({entry} per entry, \
         {MAX_PENDING_REQUESTS} entries), which is no longer a rounding error \
         beside the audit budget"
    );

    assert_eq!(MAX_LEDGER_RECORDS, 4096);
    assert_eq!(MAX_PENDING_REQUESTS, 256);
}
