// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The payload rules a schema is built from.
//!
//! The library declares no envelope schema; an adapter does. The fixture
//! schema in `common` plays that adapter through the public API only, which is
//! the proof that the rules are usable from another crate: the byte bound, the
//! version check, the correlated refusal and the wire form of every field type
//! the library gives one.

mod common;

use amussis_decision::{
    BlockReason, ContractError, Correlation, HaltReason, Identity, MAX_CONTRACT_PAYLOAD_BYTES,
    PayloadBuffer, RecordStatus, SchemaTag, decode_text, encode_into,
};

use common::{
    CORRELATION, ENVELOPE, Envelope, Fallible, correlation, decoded, encoded, envelope, filler,
    render, tamper,
};

/// The correlation of a refusal whose payload named [`CORRELATION`].
fn identified() -> Fallible<Correlation> {
    Ok(Correlation::new(
        ENVELOPE,
        Some(Identity::parse(CORRELATION)?),
    ))
}

/// The fixture envelope as the encoder must spell it, byte for byte.
const WIRE_FORM: &str = concat!(
    r#"{"schema":"example.envelope.v1","correlation-id":"intent-0001","#,
    r#""request-id":"request-0001","event-id":"event-0001","agent-id":"agent-01","#,
    r#""maker":"maker-alice","action-type":"file-deletion","#,
    r#""target":"/var/lib/example/file","risk-tier":"tier-a-consequential","#,
    r#""oversight":"standard","required-approval":"single-checker","sequence":1,"#,
    r#""algorithm":"sha-256","#,
    r#""previous":"0000000000000000000000000000000000000000000000000000000000000000","#,
    r#""status":"approved","block-reason":null,"recorded-at":1000,"#,
    r#""signature":{"key-id":"fixture-key","algorithm":"tpm2-rsa-pss","#,
    r#""bytes":"0707070707070707070707070707070707070707070707070707070707070707"}}"#,
);

// --- Positive -------------------------------------------------------------

/// Positive: an envelope survives the bounded encoder and decoder unchanged,
/// and the buffer holds exactly the payload.
#[test]
fn a_payload_round_trips_through_the_bounded_encoder() -> Fallible<()> {
    let value = envelope()?;
    let mut buffer = PayloadBuffer::new();
    let text = encode_into(&value, correlation(&value), &mut buffer)?.to_owned();
    assert_eq!(buffer.len(), text.len());
    assert!(!buffer.is_empty());
    assert_eq!(buffer.as_str(), Some(text.as_str()));
    assert_eq!(buffer.as_bytes(), text.as_bytes());
    assert_eq!(decoded(&text)?, value);
    assert_eq!(decode_text::<Envelope>(ENVELOPE, &text)?, value);
    Ok(())
}

/// Positive: the wire form of every field type is the pinned one. A renamed
/// variant, a reordered key or a changed byte encoding fails here.
#[test]
fn the_wire_form_of_every_field_type_is_pinned() -> Fallible<()> {
    assert_eq!(encoded(&envelope()?)?, WIRE_FORM);
    assert_eq!(decoded(WIRE_FORM)?, envelope()?);

    let mut refused = envelope()?;
    refused.status = RecordStatus::Halted;
    refused.block_reason = Some(BlockReason::KillswitchEngaged(HaltReason::OperatorStop));
    refused.signature = None;
    let text = encoded(&refused)?;
    assert!(text.contains(r#""status":"halted""#), "{text}");
    assert!(
        text.contains(r#""block-reason":{"killswitch-engaged":"operator-stop"}"#),
        "{text}"
    );
    assert!(text.ends_with(r#""signature":null}"#), "{text}");
    assert_eq!(decoded(&text)?, refused);
    Ok(())
}

/// Positive: a correlation names its schema and its payload, and says so when
/// it cannot name the payload.
#[test]
fn a_correlation_names_its_schema_and_payload() -> Fallible<()> {
    let named = identified()?;
    assert_eq!(named.schema(), ENVELOPE);
    assert_eq!(named.id(), Some(Identity::parse(CORRELATION)?));
    assert_eq!(
        named.to_string(),
        format!("example.envelope.v1 [{CORRELATION}]")
    );

    let anonymous = Correlation::new(ENVELOPE, None);
    assert_eq!(anonymous.id(), None);
    assert_eq!(anonymous.to_string(), "example.envelope.v1 [uncorrelated]");
    assert_ne!(anonymous, named);
    Ok(())
}

/// Positive: a schema tag is the text it was declared with, and two tags are
/// equal exactly when their texts are.
#[test]
fn a_schema_tag_is_the_text_it_was_declared_with() {
    assert_eq!(ENVELOPE.as_str(), "example.envelope.v1");
    assert_eq!(ENVELOPE.to_string(), "example.envelope.v1");
    assert_eq!(SchemaTag::new("example.envelope.v1"), ENVELOPE);
    assert_ne!(SchemaTag::new("example.envelope.v2"), ENVELOPE);
}

/// Positive: every refusal reports the correlation it was built with and
/// spells it at the head of its message.
#[test]
fn every_refusal_reports_its_correlation() -> Fallible<()> {
    let about = identified()?;
    let refusals = [
        ContractError::UnknownVersion { correlation: about },
        ContractError::Malformed { correlation: about },
        ContractError::PayloadTooLong {
            correlation: about,
            max: MAX_CONTRACT_PAYLOAD_BYTES,
        },
    ];
    for refusal in refusals {
        assert_eq!(refusal.correlation(), about);
        assert!(
            refusal.to_string().starts_with(&about.to_string()),
            "{refusal}"
        );
    }
    assert!(refusals[2].to_string().contains("4096-byte"));
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a payload naming another version is refused as an unknown
/// version, and the refusal still names the payload.
#[test]
fn another_version_is_refused_as_unknown() -> Fallible<()> {
    let text = encoded(&envelope()?)?;
    for other in ["example.envelope.v2", "another.system.v1", "v1"] {
        let renamed = tamper(&text, |value| value["schema"] = other.into())?;
        assert_eq!(
            decoded(&renamed),
            Err(ContractError::UnknownVersion {
                correlation: identified()?
            }),
            "{other}"
        );
    }
    Ok(())
}

/// Negative: a payload of the right version with a bad field is malformed, not
/// an unknown version: the tag it names is the one that was asked for.
#[test]
fn a_bad_field_under_the_right_tag_is_malformed() -> Fallible<()> {
    let text = encoded(&envelope()?)?;
    let malformed = Err(ContractError::Malformed {
        correlation: identified()?,
    });
    let unknown_key = tamper(&text, |value| value["note"] = 1.into())?;
    assert_eq!(decoded(&unknown_key), malformed);
    let bad_digest = tamper(&text, |value| value["previous"] = "abcd".into())?;
    assert_eq!(decoded(&bad_digest), malformed);
    let bad_tag = tamper(&text, |value| value["status"] = "undecided".into())?;
    assert_eq!(decoded(&bad_tag), malformed);
    let missing = tamper(&text, |value| {
        if let Some(object) = value.as_object_mut() {
            object.remove("target");
        }
    })?;
    assert_ne!(missing, text);
    assert_eq!(decoded(&missing), malformed);
    Ok(())
}

/// Negative: a version tag that cannot be read at all does not hide a
/// correlation identifier that can. The payload is malformed, and named.
#[test]
fn a_damaged_version_tag_does_not_hide_the_identifier() -> Fallible<()> {
    let text = encoded(&envelope()?)?;
    let malformed = Err(ContractError::Malformed {
        correlation: identified()?,
    });
    let numeric = tamper(&text, |value| value["schema"] = 7.into())?;
    assert_eq!(decoded(&numeric), malformed);
    let out_of_charset = tamper(&text, |value| value["schema"] = "has space".into())?;
    assert_eq!(decoded(&out_of_charset), malformed);
    let too_long = tamper(&text, |value| value["schema"] = filler(65).into())?;
    assert_eq!(decoded(&too_long), malformed);
    let absent = tamper(&text, |value| {
        if let Some(object) = value.as_object_mut() {
            object.remove("schema");
        }
    })?;
    assert_eq!(decoded(&absent), malformed);
    Ok(())
}

/// Negative: a payload whose identifier cannot be read is refused without one,
/// under the cause its version tag gives.
#[test]
fn an_unreadable_identifier_makes_the_refusal_anonymous() -> Fallible<()> {
    let anonymous = Correlation::new(ENVELOPE, None);
    for text in ["", "not json", "[]", "{}", "null"] {
        assert_eq!(
            decoded(text),
            Err(ContractError::Malformed {
                correlation: anonymous
            }),
            "{text:?}"
        );
    }
    let text = encoded(&envelope()?)?;
    let unnamed = tamper(&text, |value| value["correlation-id"] = "has space".into())?;
    assert_eq!(
        decoded(&unnamed),
        Err(ContractError::Malformed {
            correlation: anonymous
        })
    );
    let unnamed_other = tamper(&unnamed, |value| value["schema"] = "v2".into())?;
    assert_eq!(
        decoded(&unnamed_other),
        Err(ContractError::UnknownVersion {
            correlation: anonymous
        })
    );
    Ok(())
}

/// Negative: a value that does not fit the buffer is refused with the
/// correlation the caller gave, and the buffer is left empty.
#[test]
fn a_value_wider_than_the_buffer_is_refused_and_leaves_it_empty() -> Fallible<()> {
    let about = identified()?;
    let mut buffer = PayloadBuffer::new();
    assert!(!encode_into(&envelope()?, about, &mut buffer)?.is_empty());
    let wide = filler(MAX_CONTRACT_PAYLOAD_BYTES);
    assert_eq!(
        encode_into(&wide, about, &mut buffer),
        Err(ContractError::PayloadTooLong {
            correlation: about,
            max: MAX_CONTRACT_PAYLOAD_BYTES
        })
    );
    assert!(buffer.is_empty());
    assert_eq!(buffer.as_bytes(), b"");
    Ok(())
}

/// Negative: an untouched buffer yields an empty payload rather than stale
/// bytes.
#[test]
fn an_untouched_payload_buffer_holds_nothing() {
    let buffer = PayloadBuffer::default();
    assert!(buffer.is_empty());
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.as_bytes(), b"");
    assert_eq!(buffer.as_str(), Some(""));
    assert_eq!(PayloadBuffer::new().len(), buffer.len());
}

// --- Boundary -------------------------------------------------------------

/// Boundary: a payload of exactly the bound is parsed, and one byte more is
/// refused before it is parsed, so the refusal cannot name it.
#[test]
fn the_decoder_reads_a_payload_of_exactly_the_bound() -> Fallible<()> {
    let text = encoded(&envelope()?)?;
    let padding = MAX_CONTRACT_PAYLOAD_BYTES.saturating_sub(text.len());
    let at_bound = format!("{text}{}", " ".repeat(padding));
    assert_eq!(at_bound.len(), MAX_CONTRACT_PAYLOAD_BYTES);
    assert_eq!(decoded(&at_bound)?, envelope()?);

    let over_bound = format!("{at_bound} ");
    assert_eq!(
        decoded(&over_bound),
        Err(ContractError::PayloadTooLong {
            correlation: Correlation::new(ENVELOPE, None),
            max: MAX_CONTRACT_PAYLOAD_BYTES
        })
    );
    Ok(())
}

/// Boundary: the encoder fills the buffer to its last byte and not one past
/// it. A text of `n` bytes is `n + 2` bytes as a JSON string.
#[test]
fn the_encoder_fills_the_buffer_to_its_last_byte() -> Fallible<()> {
    let about = identified()?;
    let mut buffer = PayloadBuffer::new();
    let widest = filler(MAX_CONTRACT_PAYLOAD_BYTES.saturating_sub(2));
    let text = encode_into(&widest, about, &mut buffer)?;
    assert_eq!(text.len(), MAX_CONTRACT_PAYLOAD_BYTES);
    assert_eq!(decode_text::<String>(ENVELOPE, text)?, widest);
    assert_eq!(buffer.len(), MAX_CONTRACT_PAYLOAD_BYTES);

    let one_more = filler(MAX_CONTRACT_PAYLOAD_BYTES.saturating_sub(1));
    assert_eq!(
        encode_into(&one_more, about, &mut buffer),
        Err(ContractError::PayloadTooLong {
            correlation: about,
            max: MAX_CONTRACT_PAYLOAD_BYTES
        })
    );
    Ok(())
}

/// Boundary: a buffer that held a long payload holds only the short one
/// encoded after it.
#[test]
fn a_buffer_is_emptied_before_each_encoding() -> Fallible<()> {
    let about = identified()?;
    let mut buffer = PayloadBuffer::new();
    let long = encode_into(&filler(1_000), about, &mut buffer)?.len();
    assert_eq!(long, 1_002);
    assert_eq!(encode_into(&7u8, about, &mut buffer)?, "7");
    assert_eq!(buffer.len(), 1);
    assert_eq!(buffer.as_bytes(), b"7");
    Ok(())
}

/// Boundary: a tag no payload can carry (it is no identifier) is equal to no
/// payload's tag, so every refused payload that names a readable version is an
/// unknown version, the fixture's own included. A payload that names none
/// stays malformed.
#[test]
fn a_tag_no_payload_can_carry_matches_no_payload() -> Fallible<()> {
    let text = render(&envelope()?)?;
    let bad_field = tamper(&text, |value| value["previous"] = "abcd".into())?;
    for tag in ["", "has space"] {
        let schema = SchemaTag::new(tag);
        let named = Correlation::new(schema, Some(Identity::parse(CORRELATION)?));
        assert_eq!(decode_text::<Envelope>(schema, &text)?, envelope()?);
        assert_eq!(
            decode_text::<Envelope>(schema, &bad_field),
            Err(ContractError::UnknownVersion { correlation: named }),
            "{tag:?}"
        );
        assert_eq!(
            decode_text::<Envelope>(schema, "{}"),
            Err(ContractError::Malformed {
                correlation: Correlation::new(schema, None)
            })
        );
    }
    Ok(())
}
