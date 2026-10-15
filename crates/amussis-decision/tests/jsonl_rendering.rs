// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The optional JSON Lines renderer, behind the `jsonl` feature.
//!
//! The renderer is deliberately off the hashing path, so these tests assert the
//! rendered form only and never a digest.

#![cfg(feature = "jsonl")]

mod common;

use amussis_decision::ledger::jsonl::{self, LedgerLine, RenderError};
use amussis_decision::{
    ActionType, AgentId, AuditLedger, BlockReason, DecisionError, HaltReason, HashAlgorithm,
    InMemorySink, IntentId, KillswitchState, RecordDraft, RecordPrincipals, RecordStatus,
    RecordSubject, RiskLevel, Sha256Hasher, SignerBinding, UnixSeconds,
};

use common::{FIXTURE_AUDIT_BOUND, Fallible, FixtureError, FixtureSigner, io_deadline, named_for};

type Ledger = AuditLedger<Sha256Hasher, FixtureSigner, InMemorySink>;

/// Builds a fixture ledger holding the one record `draft` seals to.
fn ledger_of(draft: &RecordDraft) -> Result<Ledger, DecisionError> {
    let mut ledger: Ledger = AuditLedger::with_bound(
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FIXTURE_AUDIT_BOUND,
    );
    ledger.append(*draft)?;
    Ok(ledger)
}

/// Builds a fixture ledger holding one record with `status` and `reason`.
fn one_record(status: RecordStatus, reason: Option<BlockReason>) -> Result<Ledger, DecisionError> {
    ledger_of(&RecordDraft {
        subject: Some(RecordSubject {
            intent_id: IntentId::parse("intent-1")?,
            agent: AgentId::parse("agent-01")?,
            action_type: ActionType::FileModification,
        }),
        principals: named_for(status)?,
        status,
        block_reason: reason,
        killswitch: KillswitchState::Armed,
        at: UnixSeconds::new(100),
    })
}

/// The latch state of an operator halt at the highest risk level.
const HALTED: KillswitchState = KillswitchState::Engaged {
    at: UnixSeconds::new(100),
    reason: HaltReason::OperatorStop,
    level: RiskLevel::HIGHEST,
};

/// Positive: a sealed record renders and parses back unchanged.
#[test]
fn a_sealed_record_renders_and_parses_back() -> Fallible<()> {
    let ledger = one_record(RecordStatus::Approved, None)?;
    let record = ledger.records().first().ok_or(FixtureError::NoRecord)?;
    let text = jsonl::render_line(record).map_err(|_| FixtureError::Render)?;
    assert!(text.contains("\"algorithm\":\"sha-256\""));
    assert!(text.contains("\"status\":\"approved\""));
    let parsed = jsonl::parse_line(&text).map_err(|_| FixtureError::Render)?;
    assert_eq!(parsed.sequence, 1);
    assert_eq!(parsed.algorithm, HashAlgorithm::Sha256);
    assert!(jsonl::uses_sha256(&parsed));
    assert!(!parsed.killswitch_engaged);
    assert_eq!(parsed.block_reason, None);
    Ok(())
}

/// Positive, second half: a refusal renders with the reason that produced it.
#[test]
fn a_refusal_renders_with_its_reason() -> Fallible<()> {
    let ledger = one_record(RecordStatus::Blocked, Some(BlockReason::RegistryFull))?;
    let record = ledger.records().first().ok_or(FixtureError::NoRecord)?;
    let text = jsonl::render_line(record).map_err(|_| FixtureError::Render)?;
    let parsed = jsonl::parse_line(&text).map_err(|_| FixtureError::Render)?;
    assert_eq!(parsed.status, RecordStatus::Blocked);
    assert_eq!(parsed.block_reason.as_deref(), Some("registry-full"));
    Ok(())
}

/// Positive, third half: the projection is the rendering's own step, so a
/// caller that wants the fields without the JSON text takes the same values.
#[test]
fn a_record_projects_onto_the_line_it_renders_as() -> Fallible<()> {
    let ledger = one_record(RecordStatus::Approved, None)?;
    let record = ledger.records().first().ok_or(FixtureError::NoRecord)?;
    let line: LedgerLine = jsonl::project(record).map_err(|_| FixtureError::Render)?;
    assert_eq!(line.sequence, record.body().sequence().get());
    assert_eq!(line.status, RecordStatus::Approved);
    assert_eq!(line.algorithm, record.body().algorithm());
    assert_eq!(line.block_reason, None);
    assert!(!line.killswitch_engaged);
    assert_eq!(line.digest, record.digest().to_string());
    assert_eq!(line.previous, record.body().previous().to_string());

    let rendered = jsonl::render_line(record).map_err(|_| FixtureError::Render)?;
    assert_eq!(
        jsonl::parse_line(&rendered).map_err(|_| FixtureError::Render)?,
        line,
        "rendering and parsing round-trip to the projection itself"
    );
    Ok(())
}

/// Positive, fourth half: the two records of the halt latch render without an
/// intent and an agent, which they do not have, and parse back unchanged. The
/// halt no person engaged names nobody; the halt of a person names that
/// person at the level it stands at; the release names the person who
/// released it.
#[test]
fn a_record_of_the_halt_latch_renders_without_an_action() -> Fallible<()> {
    let at = UnixSeconds::new(100);
    let released = named_for(RecordStatus::HaltReleased)?.ok_or(FixtureError::NoRecord)?;
    let operator = RecordPrincipals {
        level: HALTED.level().ok_or(FixtureError::NoRecord)?,
        ..released
    };
    let halt = (RecordStatus::HaltEngaged, "halt-engaged");
    let release = (RecordStatus::HaltReleased, "halt-released");
    let cases = [
        (RecordDraft::of_halt(HALTED, at), halt, None),
        (
            RecordDraft::of_halt_by(HALTED, operator, at),
            halt,
            Some(operator),
        ),
        (
            RecordDraft::of_release(released, at),
            release,
            Some(released),
        ),
    ];
    for (draft, (status, spelling), named) in cases {
        let parsed = latch_line(&draft, spelling)?;
        assert_eq!(parsed.status, status);
        assert_eq!(parsed.intent_id, None);
        assert_eq!(parsed.agent, None);
        assert_eq!(
            parsed.killswitch_engaged,
            status == RecordStatus::HaltEngaged
        );
        assert_eq!(parsed.block_reason, None);
        assert_eq!(parsed.maker.as_deref(), named.map(|_| "maker-01"));
        assert_eq!(parsed.level, named.map(|who| who.level.tag()));
        assert_eq!(parsed.checkers, [] as [std::string::String; 0]);
    }
    Ok(())
}

/// Renders the one record `draft` seals to, requires the line to spell its
/// status as `spelling` and to name no action, and parses it back.
fn latch_line(draft: &RecordDraft, spelling: &str) -> Fallible<jsonl::LedgerLine> {
    let ledger = ledger_of(draft)?;
    let record = ledger.records().first().ok_or(FixtureError::NoRecord)?;
    let text = jsonl::render_line(record).map_err(|_| FixtureError::Render)?;
    assert!(text.contains(&format!("\"status\":\"{spelling}\"")));
    assert!(text.contains("\"intent-id\":null"));
    assert!(text.contains("\"agent\":null"));
    Ok(jsonl::parse_line(&text).map_err(|_| FixtureError::Render)?)
}

/// Positive, fifth half: a line names the maker, the level and the checkers
/// of its record, as the identities the caller passed in, and parses back.
#[test]
fn a_line_names_who_its_record_names() -> Fallible<()> {
    let ledger = one_record(RecordStatus::Rejected, None)?;
    let record = ledger.records().first().ok_or(FixtureError::NoRecord)?;
    let text = jsonl::render_line(record).map_err(|_| FixtureError::Render)?;
    assert!(text.contains("\"maker\":\"maker-01\""), "{text}");
    assert!(text.contains("\"checkers\":[\"checker-01\"]"), "{text}");
    assert!(text.contains("\"level\":3"), "{text}");
    let parsed = jsonl::parse_line(&text).map_err(|_| FixtureError::Render)?;
    assert_eq!(parsed.maker.as_deref(), Some("maker-01"));
    assert_eq!(parsed.checkers, ["checker-01"]);
    assert_eq!(parsed.level, Some(3));

    let unvoted = one_record(RecordStatus::Approved, None)?;
    let record = unvoted.records().first().ok_or(FixtureError::NoRecord)?;
    let line = jsonl::project(record).map_err(|_| FixtureError::Render)?;
    assert_eq!(line.maker.as_deref(), Some("maker-01"));
    assert_eq!(line.level, Some(1));
    assert_eq!(line.checkers, [] as [std::string::String; 0]);
    Ok(())
}

/// Boundary: a record that decides an action names its intent and its agent
/// in the line, so the two kinds of record cannot be read for one another.
#[test]
fn a_decision_record_names_its_intent_and_agent() -> Fallible<()> {
    let ledger = one_record(RecordStatus::Halted, Some(BlockReason::AuditUnavailable))?;
    let record = ledger.records().first().ok_or(FixtureError::NoRecord)?;
    let line = jsonl::project(record).map_err(|_| FixtureError::Render)?;
    assert_eq!(line.intent_id.as_deref(), Some("intent-1"));
    assert_eq!(line.agent.as_deref(), Some("agent-01"));
    Ok(())
}

/// Negative: text that is not one rendered line is a serialisation refusal,
/// distinct from any other rendering failure.
#[test]
fn text_that_is_not_a_rendered_line_is_refused() {
    assert_eq!(
        jsonl::parse_line("not json"),
        Err(RenderError::Serialisation)
    );
    assert_eq!(jsonl::parse_line(""), Err(RenderError::Serialisation));
    assert_eq!(jsonl::parse_line("{}"), Err(RenderError::Serialisation));
    assert_ne!(
        RenderError::Serialisation,
        RenderError::Encoding,
        "a malformed line and a non-UTF-8 identifier are different failures"
    );
}

/// Negative: a persisted line naming MD5 fails to parse. There is no alias.
#[test]
fn a_persisted_md5_line_is_refused() {
    let line = r#"{"sequence":1,"algorithm":"md5","status":"approved","at":100,
"previous":"00","digest":"00","intent-id":"i","agent":"a",
"killswitch-engaged":false}"#;
    assert!(
        jsonl::parse_line(line).is_err(),
        "a persisted md5 tag must fail to deserialise, not be accepted"
    );
}

/// Boundary: an unknown field is refused rather than silently dropped, so the
/// schema cannot drift unnoticed before a versioned consumer schema is built.
#[test]
fn an_unknown_field_is_refused() -> Fallible<()> {
    let ledger = one_record(RecordStatus::Blocked, Some(BlockReason::AuditUnavailable))?;
    let record = ledger.records().first().ok_or(FixtureError::NoRecord)?;
    let text = jsonl::render_line(record).map_err(|_| FixtureError::Render)?;
    let widened = text.replacen('{', "{\"unexpected\":1,", 1);
    assert!(jsonl::parse_line(&widened).is_err());
    assert!(jsonl::parse_line(&text).is_ok());
    Ok(())
}
