// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Epic E14-2: the decision request P06 Justitia sends to P05 Forum.
//!
//! The schema round-trips, refuses an unknown contract version, refuses an
//! approval weaker than the tier and oversight class demand, and sits exactly
//! on the declared approval-window bounds. No D-Bus connection and no socket
//! are opened; the Forum consumer itself is milestone M16 work.

mod common;

use aegis_justitia::{
    ContractError, Correlation, DecisionRequest, DecisionRequestVersion, EdgeId, Identity,
    MAX_DECISION_WINDOW_SECS, MIN_DECISION_WINDOW_SECS, OversightClass, RequiredApproval, RiskTier,
    SchemaId, UnixSeconds,
};

use common::{CORRELATION, Fallible, decision_request, encoded, render, tamper};

/// The exact payload the fixture request encodes to.
const GOLDEN: &str = r#"{"schema":"aegis.p06-p05.decision-request.v1","edge":"DISPATCH_DECISION_REQUEST","correlation-id":"intent-0001","request-id":"request-0001","agent-id":"agent-01","maker":"maker-alice","proposed-action":"file-deletion","target":"/var/lib/aegis/example","risk-tier":"tier-a-consequential","oversight":"standard","required-approval":"single-checker","created-at":1000,"due-at":1300}"#;

/// Returns the correlation a refusal of a fixture request must carry.
fn expected_correlation() -> Fallible<Correlation> {
    Ok(Correlation::new(
        SchemaId::DecisionRequest,
        Some(Identity::parse(CORRELATION)?),
    ))
}

// --- Positive -------------------------------------------------------------

/// Positive: a well-formed request round-trips, and the encoding is stable.
#[test]
fn a_decision_request_round_trips() -> Fallible<()> {
    let original = decision_request(RiskTier::TierAConsequential, OversightClass::Standard, 300)?;
    let text = encoded(&original)?;
    assert_eq!(text, GOLDEN, "the field encoding is stable");
    let decoded = DecisionRequest::decode(&text)?;
    assert_eq!(decoded, original, "serialise then deserialise is identity");
    assert_eq!(decoded.validate(), Ok(()));
    assert_eq!(decoded.window_secs(), 300);
    assert_eq!(decoded.correlation(), expected_correlation()?);
    assert_eq!(decoded.schema, DecisionRequestVersion::V1);
    assert_eq!(decoded.edge, EdgeId::DispatchDecisionRequest);
    assert_eq!(decoded.required_approval, RequiredApproval::SingleChecker);
    assert_eq!(decoded.created_at, UnixSeconds::new(1_000));
    Ok(())
}

/// Positive: an Annex III request carries the two-checker panel the class
/// demands, and it survives the round trip unweakened.
#[test]
fn an_annex_iii_request_carries_a_two_checker_panel() -> Fallible<()> {
    let original = decision_request(
        RiskTier::TierCRoutineBounded,
        OversightClass::AnnexIiiBiometric,
        60,
    )?;
    assert_eq!(
        original.required_approval,
        RequiredApproval::DualDistinctCheckers
    );
    let decoded = DecisionRequest::decode(&encoded(&original)?)?;
    assert_eq!(decoded, original);
    assert_eq!(
        decoded.required_approval,
        RequiredApproval::DualDistinctCheckers
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a payload naming another contract version is refused as such.
#[test]
fn a_payload_naming_another_version_is_refused() -> Fallible<()> {
    let request = decision_request(RiskTier::TierAConsequential, OversightClass::Standard, 300)?;
    let text = tamper(&encoded(&request)?, |value| {
        value["schema"] = serde_json::json!("aegis.p06-p05.decision-request.v0");
    })?;
    assert_eq!(
        DecisionRequest::decode(&text),
        Err(ContractError::UnknownVersion {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

/// Negative: an Annex III request cannot be weakened into a single checker on
/// its way to the shell.
#[test]
fn an_approval_weaker_than_the_class_demands_is_refused() -> Fallible<()> {
    let mut weakened = decision_request(
        RiskTier::TierAConsequential,
        OversightClass::AnnexIiiBiometric,
        300,
    )?;
    weakened.required_approval = RequiredApproval::SingleChecker;
    let refusal = ContractError::ApprovalMismatch {
        correlation: expected_correlation()?,
        declared: RequiredApproval::SingleChecker,
        demanded: RequiredApproval::DualDistinctCheckers,
    };
    assert_eq!(weakened.validate(), Err(refusal));
    assert_eq!(DecisionRequest::decode(&render(&weakened)?), Err(refusal));
    assert_eq!(refusal.correlation(), expected_correlation()?);
    Ok(())
}

/// Negative: a request for an action that needs no human decision is refused,
/// because there is nothing for the shell to ask.
#[test]
fn a_request_for_an_action_needing_no_human_is_refused() -> Fallible<()> {
    let pointless = decision_request(RiskTier::TierCRoutineBounded, OversightClass::Standard, 300)?;
    assert_eq!(pointless.required_approval, RequiredApproval::None);
    assert_eq!(
        pointless.validate(),
        Err(ContractError::NoApprovalRequired {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

/// Negative: a payload that travels on another edge is refused.
#[test]
fn a_payload_on_another_edge_is_refused() -> Fallible<()> {
    let request = decision_request(RiskTier::TierAConsequential, OversightClass::Standard, 300)?;
    let text = tamper(&encoded(&request)?, |value| {
        value["edge"] = serde_json::json!("ACTION_GATE_INTERCEPT");
    })?;
    assert_eq!(
        DecisionRequest::decode(&text),
        Err(ContractError::Malformed {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the shortest and longest admissible windows are accepted, and one
/// second outside either end is refused.
#[test]
fn the_approval_window_sits_exactly_on_its_declared_bounds() -> Fallible<()> {
    let tier = RiskTier::TierAConsequential;
    let class = OversightClass::Standard;
    let shortest = u64::from(MIN_DECISION_WINDOW_SECS);
    let longest = u64::from(MAX_DECISION_WINDOW_SECS);

    for window in [shortest, longest] {
        let request = decision_request(tier, class, window)?;
        assert_eq!(request.window_secs(), window);
        assert_eq!(DecisionRequest::decode(&encoded(&request)?)?, request);
    }

    let closed = decision_request(tier, class, 0)?;
    assert_eq!(closed.window_secs(), 0);
    assert_eq!(
        closed.validate(),
        Err(ContractError::WindowOutOfRange {
            correlation: expected_correlation()?,
            seconds: 0,
            min: MIN_DECISION_WINDOW_SECS,
            max: MAX_DECISION_WINDOW_SECS,
        })
    );

    let too_long = decision_request(tier, class, longest.saturating_add(1))?;
    assert_eq!(
        too_long.validate(),
        Err(ContractError::WindowOutOfRange {
            correlation: expected_correlation()?,
            seconds: longest.saturating_add(1),
            min: MIN_DECISION_WINDOW_SECS,
            max: MAX_DECISION_WINDOW_SECS,
        })
    );
    Ok(())
}

/// Boundary: a due time before the creation time reports a closed window
/// rather than wrapping, and is refused like any other closed window.
#[test]
fn a_due_time_before_the_creation_time_reports_a_closed_window() -> Fallible<()> {
    let mut backwards =
        decision_request(RiskTier::TierAConsequential, OversightClass::Standard, 300)?;
    backwards.due_at = UnixSeconds::new(1);
    assert_eq!(backwards.window_secs(), 0);
    assert_eq!(
        DecisionRequest::decode(&render(&backwards)?),
        Err(ContractError::WindowOutOfRange {
            correlation: expected_correlation()?,
            seconds: 0,
            min: MIN_DECISION_WINDOW_SECS,
            max: MAX_DECISION_WINDOW_SECS,
        })
    );
    Ok(())
}
