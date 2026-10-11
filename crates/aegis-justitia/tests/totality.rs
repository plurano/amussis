// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! `decide` is total: every tier, every oversight class and both halt states
//! yield exactly one outcome and nothing panics.

mod common;

use aegis_justitia::{
    ActionType, BlockReason, HaltReason, InterceptorOutcome, OversightClass, RiskTier, UnixSeconds,
    WarningCode,
};

use common::{Fallible, engine, intent};

/// The twelve-input table: three tiers by two oversight classes by two halt
/// states. Each input yields exactly one outcome.
#[test]
fn decide_is_total_over_tier_class_and_halt_state() -> Fallible<()> {
    let tiers = [
        RiskTier::TierCRoutineBounded,
        RiskTier::TierBMaterialReversible,
        RiskTier::TierAConsequential,
    ];
    let classes = [OversightClass::Standard, OversightClass::AnnexIiiBiometric];
    let halted_states = [false, true];

    let inputs = tiers.into_iter().flat_map(|tier| {
        classes
            .into_iter()
            .flat_map(move |class| halted_states.map(move |halted| (tier, class, halted)))
    });

    let mut seen = 0usize;
    for (tier, class, halted) in inputs.take(12) {
        exercise(tier, class, halted)?;
        seen = seen.saturating_add(1);
    }
    assert_eq!(seen, 12, "all twelve inputs were exercised");
    Ok(())
}

/// Runs one table row through a fresh engine.
fn exercise(tier: RiskTier, class: OversightClass, halted: bool) -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    if halted {
        engine.halt(HaltReason::OperatorStop);
    }
    let proposal = intent(
        "intent-total",
        "maker-alice",
        ActionType::ExternalNetworkRequest,
        tier,
        class,
    )?;
    let outcome = engine.decide(&proposal);
    check_outcome(outcome, tier, class, halted);
    assert_eq!(
        engine.ledger().len(),
        1,
        "every input writes exactly one audit record, refusals included"
    );
    Ok(())
}

/// Asserts the one outcome each input must produce.
fn check_outcome(outcome: InterceptorOutcome, tier: RiskTier, class: OversightClass, halted: bool) {
    if halted {
        assert_eq!(
            outcome.block_reason(),
            Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop)),
            "a halted engine blocks at every tier and class"
        );
        assert!(!outcome.permits_execution());
        return;
    }
    match (tier, class) {
        (RiskTier::TierCRoutineBounded, OversightClass::Standard) => {
            assert_eq!(outcome, InterceptorOutcome::Allow);
        }
        (RiskTier::TierBMaterialReversible, OversightClass::Standard) => {
            assert_eq!(
                outcome,
                InterceptorOutcome::Warn {
                    code: WarningCode::MonitoredTierB
                }
            );
        }
        (RiskTier::TierAConsequential, OversightClass::Standard)
        | (_, OversightClass::AnnexIiiBiometric) => {
            assert!(
                outcome.ticket().is_some(),
                "an action needing a checker is held, not allowed"
            );
            assert!(!outcome.permits_execution());
        }
    }
}

/// A held action never permits execution, and an allowed one never carries a
/// block reason.
#[test]
fn outcome_permissiveness_is_exhaustive() -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    let routine = intent(
        "intent-allow",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let allowed = engine.decide(&routine);
    assert!(allowed.permits_execution());
    assert_eq!(allowed.block_reason(), None);
    assert!(allowed.ticket().is_none());

    let held = intent(
        "intent-held",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let outcome = engine.decide(&held);
    assert!(!outcome.permits_execution());
    assert_eq!(outcome.block_reason(), None);
    assert!(outcome.ticket().is_some());
    Ok(())
}

/// A saturated registry blocks rather than degrading to an allow.
#[test]
fn a_saturated_registry_blocks() -> Fallible<()> {
    let mut engine = engine(60, 1)?;
    let first = intent(
        "intent-hold-1",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    assert!(engine.decide(&first).ticket().is_some());
    let second = intent(
        "intent-hold-2",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let blocked = engine.decide(&second);
    assert_eq!(blocked.block_reason(), Some(BlockReason::RegistryFull));
    assert!(!blocked.permits_execution());
    Ok(())
}

/// The engine seals every decision, so the audit chain verifies after a run.
#[test]
fn the_chain_verifies_after_a_mixed_run() -> Fallible<()> {
    let mut engine = engine(60, 8)?;
    for (index, tier) in [
        RiskTier::TierCRoutineBounded,
        RiskTier::TierBMaterialReversible,
        RiskTier::TierAConsequential,
    ]
    .into_iter()
    .enumerate()
    {
        let proposal = intent(
            "intent-mixed",
            "maker-alice",
            ActionType::ExternalNetworkRequest,
            tier,
            OversightClass::Standard,
        )?;
        let step = u64::try_from(index).unwrap_or(0);
        let at = UnixSeconds::new(common::START.get().saturating_add(step));
        engine.clock_mut().set(at);
        let _outcome = engine.decide(&proposal);
    }
    assert_eq!(engine.ledger().len(), 3);
    engine.verify_ledger()?;
    assert!(!engine.killswitch().is_engaged());
    Ok(())
}
