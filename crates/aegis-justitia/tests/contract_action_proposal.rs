// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Epic E14-1: the action proposal P09 Minerva sends to P06 Justitia.
//!
//! Positive, negative and boundary coverage of the schema: a signed proposal
//! round-trips, an unsigned or malformed one is refused with a correlated
//! error, and the boundary payloads sit exactly on the declared field bounds.
//! No transport is exercised, because none exists.

mod common;

use aegis_justitia::{
    ActionProposal, ActionProposalVersion, ActionType, AgentId, ContractError, Correlation,
    Digest32, EdgeId, GateDirection, Identity, MAX_CONTRACT_PAYLOAD_BYTES, MAX_IDENTITY_LEN,
    MAX_TARGET_LEN, MakerId, OversightClass, PayloadBuffer, RiskTier, SchemaId, SignatureBytes,
    TargetResource, UnixSeconds,
};

use common::{CORRELATION, Fallible, encoded, filler, proposal, render, seal, tamper};

/// The exact payload the fixture proposal encodes to.
///
/// A golden text is the strongest available statement that the field encoding
/// is stable: a renamed field, a reordered struct, a changed enum tag or a
/// different digest rendering all fail here rather than silently ship.
const GOLDEN: &str = r#"{"schema":"aegis.p09-p06.action-proposal.v1","edge":"ACTION_GATE_INTERCEPT","direction":"p09-proposes-p06-intercepts","correlation-id":"intent-0001","agent-id":"agent-01","maker":"maker-alice","action-type":"file-deletion","target":"/var/lib/aegis/example","declared-tier":"tier-a-consequential","oversight":"standard","payload-hash":"0303030303030303030303030303030303030303030303030303030303030303","proposed-at":1000,"signature":{"key-id":"fixture-key","algorithm":"tpm2-rsa-pss","bytes":"0707070707070707070707070707070707070707070707070707070707070707"}}"#;

/// Returns the correlation a refusal of the fixture proposal must carry.
fn expected_correlation() -> Fallible<Correlation> {
    Ok(Correlation::new(
        SchemaId::ActionProposal,
        Some(Identity::parse(CORRELATION)?),
    ))
}

// --- Positive -------------------------------------------------------------

/// Positive: a signed, well-formed proposal round-trips, and serialise then
/// deserialise is the identity.
#[test]
fn a_signed_proposal_round_trips() -> Fallible<()> {
    let original = proposal()?;
    let text = encoded(&original)?;
    let decoded = ActionProposal::decode(&text)?;
    assert_eq!(decoded, original, "serialise then deserialise is identity");
    assert_eq!(encoded(&decoded)?, text, "and the second encoding matches");
    assert_eq!(decoded.validate(), Ok(()));
    assert_eq!(decoded.correlation(), expected_correlation()?);
    Ok(())
}

/// Positive: the payload carries its contract version and the settled D03
/// direction as explicit, stable fields.
#[test]
fn the_payload_carries_its_version_and_direction() -> Fallible<()> {
    let text = encoded(&proposal()?)?;
    assert_eq!(text, GOLDEN, "the field encoding is stable");
    assert!(text.contains(SchemaId::ActionProposal.tag()));
    assert!(text.contains(GateDirection::SETTLED.tag()));
    assert!(text.contains(EdgeId::ActionGateIntercept.name()));
    Ok(())
}

/// Positive: the encoder writes into a bounded buffer and never allocates one.
#[test]
fn encoding_fills_a_bounded_buffer() -> Fallible<()> {
    let mut buffer = PayloadBuffer::new();
    assert!(buffer.is_empty());
    assert_eq!(buffer.len(), 0);
    let text = proposal()?.encode_into(&mut buffer)?.to_owned();
    assert_eq!(text, GOLDEN);
    assert!(!buffer.is_empty());
    assert_eq!(buffer.len(), GOLDEN.len());
    assert_eq!(buffer.as_bytes(), GOLDEN.as_bytes());
    assert_eq!(buffer.as_str(), Some(GOLDEN));
    assert!(buffer.len() <= MAX_CONTRACT_PAYLOAD_BYTES);
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a proposal with no seal is refused, and the refusal names the
/// payload it belongs to.
#[test]
fn an_unsigned_proposal_is_refused_with_a_correlated_error() -> Fallible<()> {
    let mut unsigned = proposal()?;
    unsigned.signature = None;
    let refusal = ContractError::Unsigned {
        correlation: expected_correlation()?,
    };
    assert_eq!(unsigned.validate(), Err(refusal));
    assert_eq!(refusal.correlation().schema(), SchemaId::ActionProposal);
    assert_eq!(
        refusal.correlation().id(),
        Some(Identity::parse(CORRELATION)?)
    );

    let text = render(&unsigned)?;
    assert_eq!(ActionProposal::decode(&text), Err(refusal));
    let mut buffer = PayloadBuffer::new();
    assert_eq!(unsigned.encode_into(&mut buffer), Err(refusal));
    Ok(())
}

/// Negative: a seal that carries no bytes is not a signature either.
#[test]
fn an_empty_seal_is_refused_as_unsigned() -> Fallible<()> {
    let mut hollow = proposal()?;
    let mut empty = seal()?;
    empty.bytes = SignatureBytes::EMPTY;
    assert!(empty.is_empty());
    assert!(empty.bytes.is_empty());
    assert_eq!(empty.bytes.len(), 0);
    assert_eq!(empty.bytes.as_bytes(), b"");
    hollow.signature = Some(empty);
    assert_eq!(
        ActionProposal::decode(&render(&hollow)?),
        Err(ContractError::Unsigned {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

/// Negative: a payload naming another contract version is refused as such, not
/// parsed leniently.
#[test]
fn a_payload_naming_another_version_is_refused() -> Fallible<()> {
    let text = tamper(&encoded(&proposal()?)?, |value| {
        value["schema"] = serde_json::json!("aegis.p09-p06.action-proposal.v2");
    })?;
    assert_eq!(
        ActionProposal::decode(&text),
        Err(ContractError::UnknownVersion {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

/// Negative: a payload asserting the direction decision D03 rejected does not
/// decode at all, so the closed decision is enforced by the type.
#[test]
fn a_payload_naming_the_opposite_gate_direction_is_refused() -> Fallible<()> {
    let text = tamper(&encoded(&proposal()?)?, |value| {
        value["direction"] = serde_json::json!("p06-proposes-p09-intercepts");
    })?;
    assert_eq!(
        ActionProposal::decode(&text),
        Err(ContractError::Malformed {
            correlation: expected_correlation()?
        })
    );
    Ok(())
}

/// Negative: a payload that travels on another edge, carries an unknown field
/// or is not JSON at all is refused, and only the last of those loses its
/// correlation.
#[test]
fn malformed_payloads_are_refused() -> Fallible<()> {
    let base = encoded(&proposal()?)?;
    let correlated = ContractError::Malformed {
        correlation: expected_correlation()?,
    };

    let wrong_edge = tamper(&base, |value| {
        value["edge"] = serde_json::json!("DISPATCH_DECISION_REQUEST");
    })?;
    assert_eq!(ActionProposal::decode(&wrong_edge), Err(correlated));

    let extra_field = tamper(&base, |value| {
        value["surprise"] = serde_json::json!(true);
    })?;
    assert_eq!(ActionProposal::decode(&extra_field), Err(correlated));

    let missing_field = tamper(&base, |value| {
        if let Some(map) = value.as_object_mut() {
            map.remove("maker");
        }
    })?;
    assert_eq!(ActionProposal::decode(&missing_field), Err(correlated));

    assert_eq!(
        ActionProposal::decode("not json at all"),
        Err(ContractError::Malformed {
            correlation: Correlation::new(SchemaId::ActionProposal, None)
        })
    );
    Ok(())
}

/// Negative: a `schema` value the identifier parser refuses does not take the
/// correlation identifier down with it.
///
/// This is the falsifier for the correlated-refusal guarantee. The peek reads
/// `schema` and `correlation-id` independently, so a payload whose version tag
/// is out of the identifier charset, longer than [`MAX_IDENTITY_LEN`] or not a
/// string at all is still refused *with* the conversation it belonged to. A
/// single view over both fields would lose the identifier to any of the three,
/// and one byte in the version tag would be enough to make every refusal
/// anonymous.
#[test]
fn a_malformed_schema_value_still_yields_a_correlated_refusal() -> Fallible<()> {
    let base = encoded(&proposal()?)?;
    let correlated = ContractError::Malformed {
        correlation: expected_correlation()?,
    };

    let out_of_charset = tamper(&base, |value| {
        value["schema"] = serde_json::json!("aegis.p09-p06.action proposal.v1");
    })?;
    assert_eq!(ActionProposal::decode(&out_of_charset), Err(correlated));

    let over_long = tamper(&base, |value| {
        value["schema"] = serde_json::json!("a".repeat(MAX_IDENTITY_LEN.saturating_add(1)));
    })?;
    assert_eq!(ActionProposal::decode(&over_long), Err(correlated));

    let not_a_string = tamper(&base, |value| {
        value["schema"] = serde_json::json!(42);
    })?;
    assert_eq!(ActionProposal::decode(&not_a_string), Err(correlated));

    assert!(
        correlated.to_string().contains(CORRELATION),
        "the refusal must render the conversation it belongs to"
    );
    assert!(!correlated.to_string().contains("uncorrelated"));
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: a `schema` value of exactly [`MAX_IDENTITY_LEN`] bytes is still a
/// readable version tag, so the refusal names the version rather than the
/// shape; one byte more is unreadable and the refusal falls back to malformed.
/// Both keep the correlation, and only input that is not JSON at all loses it.
#[test]
fn the_schema_peek_is_correlated_on_both_sides_of_the_identifier_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let base = encoded(&proposal()?)?;
    let at_bound = tamper(&base, |value| {
        value["schema"] = serde_json::json!("a".repeat(MAX_IDENTITY_LEN));
    })?;
    assert_eq!(
        ActionProposal::decode(&at_bound),
        Err(ContractError::UnknownVersion {
            correlation: expected_correlation()?
        }),
        "exactly at the bound the tag is read, and names a version this build refuses"
    );

    let over_bound = tamper(&base, |value| {
        value["schema"] = serde_json::json!("a".repeat(MAX_IDENTITY_LEN.saturating_add(1)));
    })?;
    assert_eq!(
        ActionProposal::decode(&over_bound),
        Err(ContractError::Malformed {
            correlation: expected_correlation()?
        })
    );

    let uncorrelatable = ContractError::Malformed {
        correlation: Correlation::new(SchemaId::ActionProposal, None),
    };
    assert_eq!(
        ActionProposal::decode("not json at all"),
        Err(uncorrelatable)
    );
    assert!(
        uncorrelatable.to_string().contains("uncorrelated"),
        "input that is not JSON genuinely carries nothing to correlate"
    );
    Ok(())
}

/// Boundary: a proposal whose fields sit exactly at their declared maximum
/// lengths round-trips unchanged.
#[test]
fn a_proposal_at_the_maximum_field_lengths_is_accepted() -> Fallible<()> {
    let widest = ActionProposal {
        schema: ActionProposalVersion::V1,
        edge: ActionProposal::EDGE,
        direction: ActionProposal::DIRECTION,
        correlation_id: Identity::parse(&filler(MAX_IDENTITY_LEN))?,
        agent_id: AgentId::parse(&filler(MAX_IDENTITY_LEN))?,
        maker: MakerId::parse(&filler(MAX_IDENTITY_LEN))?,
        action_type: ActionType::PermissionEscalation,
        target: TargetResource::parse(&filler(MAX_TARGET_LEN))?,
        declared_tier: RiskTier::TierAConsequential,
        oversight: OversightClass::AnnexIiiBiometric,
        payload_hash: Digest32::GENESIS,
        proposed_at: UnixSeconds::EPOCH,
        signature: Some(seal()?),
    };
    let text = encoded(&widest)?;
    assert_eq!(ActionProposal::decode(&text)?, widest);
    Ok(())
}

/// Boundary: one byte past a field bound is refused, for the identifier bound
/// and for the target bound alike.
#[test]
fn one_byte_over_a_field_bound_is_refused() -> Fallible<()> {
    let base = encoded(&proposal()?)?;
    let over_identity = tamper(&base, |value| {
        value["agent-id"] = serde_json::json!("a".repeat(MAX_IDENTITY_LEN.saturating_add(1)));
    })?;
    assert!(ActionProposal::decode(&over_identity).is_err());

    let over_target = tamper(&base, |value| {
        value["target"] = serde_json::json!("a".repeat(MAX_TARGET_LEN.saturating_add(1)));
    })?;
    assert_eq!(
        ActionProposal::decode(&over_target),
        Err(ContractError::Malformed {
            correlation: expected_correlation()?
        })
    );

    let at_identity = tamper(&base, |value| {
        value["agent-id"] = serde_json::json!("a".repeat(MAX_IDENTITY_LEN));
    })?;
    assert!(
        ActionProposal::decode(&at_identity).is_ok(),
        "exactly at the bound is accepted"
    );
    Ok(())
}

/// Boundary: a payload of exactly the contract byte bound is still parsed, and
/// one byte more is refused before it is parsed at all.
#[test]
fn one_byte_over_the_payload_bound_is_refused() {
    let at_bound = filler(MAX_CONTRACT_PAYLOAD_BYTES);
    assert_eq!(at_bound.len(), MAX_CONTRACT_PAYLOAD_BYTES);
    assert_eq!(
        ActionProposal::decode(&at_bound),
        Err(ContractError::Malformed {
            correlation: Correlation::new(SchemaId::ActionProposal, None)
        }),
        "at the bound the payload is parsed, and refused on its content"
    );

    let over_bound = filler(MAX_CONTRACT_PAYLOAD_BYTES.saturating_add(1));
    assert_eq!(
        ActionProposal::decode(&over_bound),
        Err(ContractError::PayloadTooLong {
            correlation: Correlation::new(SchemaId::ActionProposal, None),
            max: MAX_CONTRACT_PAYLOAD_BYTES
        })
    );
}
