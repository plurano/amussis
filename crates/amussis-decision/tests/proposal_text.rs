// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The library's own input schema, `amussis.decision.proposal.v1`.
//!
//! Positive, negative and boundary coverage: the golden text decodes to the
//! fields it names and encodes back to itself, every field is refused when it
//! is missing, over its bound or outside its value set, and a refusal names
//! its cause and keeps the identifier it could still read.

mod common;

use amussis_decision::{
    ActionType, AgentId, IntentError, IntentId, IntentSpec, InterceptorOutcome, MAX_IDENTITY_LEN,
    MAX_PROPOSAL_BYTES, MAX_TARGET_LEN, MakerId, OversightClass, PROPOSAL_SCHEMA, Proposal,
    ProposalError, ProposalVersion, RiskTier, TargetResource,
};

use common::{Fallible, engine};

/// The exact text the fixture proposal encodes to.
///
/// A renamed key, a reordered field or a changed enum tag fails here rather
/// than reaching a caller written in another language.
const GOLDEN: &str = r#"{"schema":"amussis.decision.proposal.v1","id":"intent-0001","agent":"agent-01","maker":"maker-alice","action":"file-modification","target":"/srv/data/report.txt","declared-tier":"tier-c-routine-bounded","oversight":"standard"}"#;

/// The eight keys of the schema, in the order the golden text writes them.
const KEYS: [&str; 8] = [
    "schema",
    "id",
    "agent",
    "maker",
    "action",
    "target",
    "declared-tier",
    "oversight",
];

/// The fields the golden text names.
fn spec() -> Fallible<IntentSpec> {
    Ok(IntentSpec {
        id: IntentId::parse("intent-0001")?,
        agent: AgentId::parse("agent-01")?,
        maker: MakerId::parse("maker-alice")?,
        action: ActionType::FileModification,
        declared_tier: RiskTier::TierCRoutineBounded,
        oversight: OversightClass::Standard,
        target: TargetResource::parse("/srv/data/report.txt")?,
    })
}

/// The golden text as a JSON object a test can damage.
fn golden_object() -> Fallible<serde_json::Map<String, serde_json::Value>> {
    match serde_json::from_str::<serde_json::Value>(GOLDEN)? {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err("the golden text is not an object".into()),
    }
}

/// The golden text with `key` set to `value`.
fn with(key: &str, value: serde_json::Value) -> Fallible<String> {
    let mut object = golden_object()?;
    object.insert(key.to_owned(), value);
    Ok(serde_json::to_string(&object)?)
}

/// The identifier a refusal of a damaged golden text must still carry.
fn golden_id() -> Fallible<Option<IntentId>> {
    Ok(Some(IntentId::parse("intent-0001")?))
}

// --- Positive -------------------------------------------------------------

/// Positive: the golden text decodes to the fields it names and encodes back
/// to itself.
#[test]
fn the_golden_text_round_trips() -> Fallible<()> {
    let decoded = Proposal::decode(GOLDEN)?;
    assert_eq!(decoded.schema, ProposalVersion::V1);
    assert_eq!(decoded.spec(), spec()?);
    assert_eq!(decoded, Proposal::from_spec(spec()?));
    assert_eq!(serde_json::to_string(&decoded)?, GOLDEN);
    assert!(GOLDEN.contains(PROPOSAL_SCHEMA));
    Ok(())
}

/// Positive: the golden text names exactly the eight keys of the schema.
#[test]
fn the_schema_has_exactly_eight_keys() -> Fallible<()> {
    let object = golden_object()?;
    let found: Vec<&str> = object.keys().map(String::as_str).collect();
    let mut expected = KEYS.to_vec();
    expected.sort_unstable();
    assert_eq!(found, expected);
    Ok(())
}

/// Positive: a decoded proposal becomes the intent the engine decides on, and
/// the engine's answer follows the declared tier and class.
#[test]
fn a_decoded_proposal_is_decided_by_the_engine() -> Fallible<()> {
    let mut routine = engine(60, 8)?;
    let allowed = routine.decide(&Proposal::decode(GOLDEN)?.intent()?);
    assert!(matches!(allowed, InterceptorOutcome::Allow));

    let annex = with("oversight", "annex-iii-biometric".into())?;
    let mut held = engine(60, 8)?;
    let outcome = held.decide(&Proposal::decode(&annex)?.intent()?);
    assert!(outcome.ticket().is_some(), "an Annex III action is held");
    Ok(())
}

/// Positive: a JSON escape is an admissible spelling of the same value.
#[test]
fn an_escaped_spelling_decodes_to_the_same_proposal() -> Fallible<()> {
    let escaped = GOLDEN.replace("/srv/data/report.txt", r"\/srv\/data\/report.txt");
    assert_ne!(escaped, GOLDEN);
    assert_eq!(Proposal::decode(&escaped)?, Proposal::decode(GOLDEN)?);
    Ok(())
}

// --- Negative: one refusal per field ----------------------------------------

/// Negative: a text that lacks any one key is refused, never completed with a
/// default.
#[test]
fn every_missing_key_is_refused() -> Fallible<()> {
    for key in KEYS {
        let mut object = golden_object()?;
        assert!(
            object.remove(key).is_some(),
            "the golden text carries {key}"
        );
        let text = serde_json::to_string(&object)?;
        let id = if key == "id" { None } else { golden_id()? };
        assert_eq!(
            Proposal::decode(&text),
            Err(ProposalError::Malformed { id }),
            "a text without {key} must be refused"
        );
    }
    Ok(())
}

/// Negative: a value outside the fixed set of its field is refused.
#[test]
fn every_unknown_value_is_refused() -> Fallible<()> {
    for key in ["action", "declared-tier", "oversight"] {
        for value in ["", "unknown", "FILE-MODIFICATION", "tier-d", "none"] {
            assert_eq!(
                Proposal::decode(&with(key, value.into())?),
                Err(ProposalError::Malformed { id: golden_id()? }),
                "{key} = {value:?} must be refused"
            );
        }
    }
    Ok(())
}

/// Negative: a value that is not text is refused in every field.
#[test]
fn every_value_of_the_wrong_type_is_refused() -> Fallible<()> {
    for key in KEYS {
        for value in [serde_json::Value::Null, 7.into(), true.into()] {
            let text = with(key, value)?;
            assert!(
                matches!(
                    Proposal::decode(&text),
                    Err(ProposalError::Malformed { .. })
                ),
                "{key} must be text, {text} was accepted"
            );
        }
    }
    Ok(())
}

/// Negative: a character outside the identifier set is refused, not removed.
#[test]
fn a_value_outside_the_character_set_is_refused() -> Fallible<()> {
    for key in ["id", "agent", "maker", "target"] {
        for value in ["with space", "semi;colon", "quote\"", "new\nline", "ümlaut"] {
            assert!(
                matches!(
                    Proposal::decode(&with(key, value.into())?),
                    Err(ProposalError::Malformed { .. })
                ),
                "{key} = {value:?} must be refused"
            );
        }
    }
    Ok(())
}

/// Negative: an unknown key is refused, whatever it holds.
#[test]
fn an_unknown_key_is_refused() -> Fallible<()> {
    for key in [
        "edge",
        "payload-hash",
        "signature",
        "declared_tier",
        "extra",
    ] {
        assert_eq!(
            Proposal::decode(&with(key, "value".into())?),
            Err(ProposalError::Malformed { id: golden_id()? }),
            "the unknown key {key} must be refused"
        );
    }
    Ok(())
}

/// Negative: a repeated key is refused; the second value does not win.
#[test]
fn a_repeated_key_is_refused() {
    let repeated = GOLDEN.replace(
        r#""oversight":"standard""#,
        r#""oversight":"annex-iii-biometric","oversight":"standard""#,
    );
    assert_ne!(repeated, GOLDEN);
    assert!(matches!(
        Proposal::decode(&repeated),
        Err(ProposalError::Malformed { .. })
    ));
}

/// Negative: text that is no JSON object is refused without an identifier.
#[test]
fn text_that_is_no_object_is_refused() {
    for text in ["", "{", "[]", "null", "\"text\"", "{}x", "not json"] {
        assert_eq!(
            Proposal::decode(text),
            Err(ProposalError::Malformed { id: None }),
            "{text:?} must be refused"
        );
    }
}

/// Negative: another version is named as the cause, and the identifier that
/// could still be read is kept.
#[test]
fn another_version_is_named_as_the_cause() -> Fallible<()> {
    for tag in [
        "amussis.decision.proposal.v2",
        "foreign.system.action-proposal.v1",
        "amussis.decision.proposal.v1.",
    ] {
        assert_eq!(
            Proposal::decode(&with("schema", tag.into())?),
            Err(ProposalError::UnknownVersion { id: golden_id()? }),
            "{tag} must be refused as another version"
        );
    }
    let no_id = GOLDEN
        .replace("proposal.v1", "proposal.v9")
        .replace(r#""id":"intent-0001","#, "");
    assert_eq!(
        Proposal::decode(&no_id),
        Err(ProposalError::UnknownVersion { id: None })
    );
    Ok(())
}

/// Negative: a version tag that cannot be read at all is malformed, and it
/// does not hide the identifier next to it.
#[test]
fn an_unreadable_version_keeps_the_identifier() -> Fallible<()> {
    assert_eq!(
        Proposal::decode(&with("schema", "not a tag".into())?),
        Err(ProposalError::Malformed { id: golden_id()? })
    );
    Ok(())
}

/// Negative: the declared tier may not sit below the floor of the action; the
/// text decodes, the intent is refused.
#[test]
fn a_tier_below_the_floor_is_refused_as_an_intent() -> Fallible<()> {
    let text = with("action", "file-deletion".into())?;
    assert_eq!(
        Proposal::decode(&text)?.intent(),
        Err(IntentError::TierDowngrade {
            declared: RiskTier::TierCRoutineBounded,
            minimum: RiskTier::TierAConsequential,
        })
    );
    Ok(())
}

// --- Boundary ---------------------------------------------------------------

/// Boundary: each bounded field is accepted exactly on its bound and refused
/// one byte past it.
#[test]
fn every_bounded_field_is_refused_one_byte_past_its_bound() -> Fallible<()> {
    for (key, bound) in [
        ("id", MAX_IDENTITY_LEN),
        ("agent", MAX_IDENTITY_LEN),
        ("maker", MAX_IDENTITY_LEN),
        ("target", MAX_TARGET_LEN),
    ] {
        let on = with(key, "a".repeat(bound).into())?;
        assert!(Proposal::decode(&on).is_ok(), "{key} on its bound is valid");
        let past = with(key, "a".repeat(bound.saturating_add(1)).into())?;
        assert!(
            matches!(
                Proposal::decode(&past),
                Err(ProposalError::Malformed { .. })
            ),
            "{key} one byte past its bound must be refused"
        );
        assert!(
            Proposal::decode(&with(key, "".into())?).is_err(),
            "an empty {key} must be refused"
        );
    }
    Ok(())
}

/// Boundary: a text on the byte bound is still parsed; one byte more is
/// refused unparsed, with the length it had.
#[test]
fn a_text_past_the_byte_bound_is_refused_unparsed() {
    let padding = MAX_PROPOSAL_BYTES.saturating_sub(GOLDEN.len());
    let on = format!("{GOLDEN}{}", " ".repeat(padding));
    assert_eq!(on.len(), MAX_PROPOSAL_BYTES);
    assert!(Proposal::decode(&on).is_ok(), "trailing blanks are JSON");
    let past = format!("{on} ");
    assert_eq!(
        Proposal::decode(&past),
        Err(ProposalError::TooLong {
            max: MAX_PROPOSAL_BYTES,
            actual: MAX_PROPOSAL_BYTES.saturating_add(1),
        })
    );
}

/// Boundary: the widest admissible proposal, written plainly, fits the byte
/// bound with room to spare.
#[test]
fn the_widest_plain_proposal_fits_the_bound() -> Fallible<()> {
    let widest = Proposal::from_spec(IntentSpec {
        id: IntentId::parse(&"i".repeat(MAX_IDENTITY_LEN))?,
        agent: AgentId::parse(&"a".repeat(MAX_IDENTITY_LEN))?,
        maker: MakerId::parse(&"m".repeat(MAX_IDENTITY_LEN))?,
        action: ActionType::ExternalNetworkRequest,
        declared_tier: RiskTier::TierBMaterialReversible,
        oversight: OversightClass::AnnexIiiBiometric,
        target: TargetResource::parse(&"t".repeat(MAX_TARGET_LEN))?,
    });
    let text = serde_json::to_string(&widest)?;
    assert!(text.len() < MAX_PROPOSAL_BYTES / 4, "{} bytes", text.len());
    assert_eq!(Proposal::decode(&text)?, widest);
    Ok(())
}
