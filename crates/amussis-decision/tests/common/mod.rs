// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! Fixtures shared by the integration tests.
//!
//! Everything here reaches `amussis-decision` through its public API only. That
//! is the proof the milestone asks for: the risk-tier, maker-checker, Annex III,
//! timeout and killswitch logic is library code, not a `#[cfg(test)]` module.
//!
//! Fixture failures raise [`FixtureError`], never a library error borrowed as
//! filler. A test that cannot build its own inputs is a broken fixture, not a
//! refused signature or an expired window, and the two must not be confusable
//! in a failure report.

#![allow(dead_code)]

use amussis_decision::{
    ActionIntent, ActionType, AgentId, AuditRecord, BlockReason, ChainAnchor, CheckerId,
    CheckerSet, ClockError, ContractError, Correlation, DIGEST_LEN, DecisionEngine, DecisionError,
    Digest32, EngineConfig, EventId, FixedClock, HashAlgorithm, Identity, InMemorySink, IntentId,
    IntentSpec, IoDeadline, MAX_SIGNATURE_BYTES, MakerId, OversightClass, OversightSignature,
    PayloadBuffer, RecordPrincipals, RecordSigner, RecordStatus, RequestId, RequiredApproval,
    RiskLevel, RiskTier, SchemaTag, Sequence, Sha256Hasher, SignError, Signature,
    SignatureAlgorithm, SignerBinding, SignerKeyId, TargetResource, Ttl, UnixSeconds, decode_text,
    encode_into,
};

/// Anything that can go wrong building or reading a fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FixtureError {
    /// The engine returned no approval ticket where the test needs one.
    #[error("the engine returned no approval ticket")]
    NoTicket,
    /// The ledger held no record where the test needs one.
    #[error("the ledger held no record")]
    NoRecord,
    /// A fixture constant was rejected by a validating constructor.
    #[error("a fixture constant was rejected: {0}")]
    BadConstant(&'static str),
    /// A rendered line could not be produced or parsed.
    #[error("the jsonl fixture could not be rendered or parsed")]
    Render,
}

/// The result type every fixture and every test returns.
pub type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// A signer that seals a record with the digest itself. It exists only in the
/// test crate; the library deliberately ships no production signer, because
/// TPM2 sealing is deferred to milestone M20.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureSigner {
    key_id: SignerKeyId,
}

impl FixtureSigner {
    /// Builds a fixture signer.
    ///
    /// # Errors
    ///
    /// Propagates an identity parse failure, which cannot occur for the
    /// literal used here.
    pub fn new() -> Result<Self, DecisionError> {
        Ok(Self {
            key_id: SignerKeyId::parse("fixture-key")?,
        })
    }
}

impl RecordSigner for FixtureSigner {
    fn key_id(&self) -> &SignerKeyId {
        &self.key_id
    }

    fn sign(&self, digest: &Digest32) -> Result<Signature, SignError> {
        Signature::new(self.key_id, digest.as_bytes())
    }
}

/// A bound signer whose backend returns one byte more than the crate admits,
/// to exercise the fail-closed seal path with a signer actually bound.
///
/// The refusal is produced by the library itself: [`Signature::new`] is the
/// only producer of [`SignError::TooLong`], so this fixture reaches a real
/// library path rather than fabricating an error value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OversizedSigner {
    key_id: SignerKeyId,
}

impl OversizedSigner {
    /// The width the backend returns: one past the scalar bound.
    pub const WIDTH: usize = MAX_SIGNATURE_BYTES.saturating_add(1);

    /// Builds an oversized signer.
    ///
    /// # Errors
    ///
    /// Propagates an identity parse failure.
    pub fn new() -> Result<Self, DecisionError> {
        Ok(Self {
            key_id: SignerKeyId::parse("oversized-key")?,
        })
    }
}

impl RecordSigner for OversizedSigner {
    fn key_id(&self) -> &SignerKeyId {
        &self.key_id
    }

    fn sign(&self, _digest: &Digest32) -> Result<Signature, SignError> {
        Signature::new(self.key_id, &[0u8; Self::WIDTH])
    }
}

/// A clock whose source is broken. `amussis_decision::Clock` is public API, so a
/// fault injector is an ordinary implementation of it rather than a hook.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultyClock;

impl amussis_decision::Clock for FaultyClock {
    fn now(&self) -> Result<UnixSeconds, ClockError> {
        Err(ClockError::BeforeEpoch)
    }
}

/// The engine shape used by most tests: SHA-256, a fixture signer, an in-memory
/// sink and a clock the test advances.
pub type TestEngine = DecisionEngine<Sha256Hasher, FixtureSigner, InMemorySink, FixedClock>;

/// The engine shape used to exercise a clock fault.
pub type FaultyClockEngine = DecisionEngine<Sha256Hasher, FixtureSigner, InMemorySink, FaultyClock>;

/// The scalar audit bound the fixtures use. Small on purpose: a fixture engine
/// should reserve kilobytes, not the crate default.
pub const FIXTURE_AUDIT_BOUND: usize = 32;

/// The time every fixture engine starts at.
pub const START: UnixSeconds = UnixSeconds::new(1_000);

/// Builds a fixture engine configuration.
///
/// # Errors
///
/// Returns [`FixtureError::BadConstant`] when `ttl_secs` is zero.
pub fn config(ttl_secs: u32, max_pending: usize) -> Fallible<EngineConfig> {
    let ttl = Ttl::from_secs(ttl_secs).ok_or(FixtureError::BadConstant("ttl_secs"))?;
    Ok(EngineConfig {
        approval_ttl: ttl,
        annex_iii_ttl: ttl,
        max_pending,
        max_audit_records: FIXTURE_AUDIT_BOUND,
    })
}

/// Builds an engine with an approval window of `ttl_secs` seconds, room for
/// `max_pending` live requests, and a clock pinned to [`START`].
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn engine(ttl_secs: u32, max_pending: usize) -> Fallible<TestEngine> {
    Ok(DecisionEngine::new(
        config(ttl_secs, max_pending)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FixedClock::new(START),
    ))
}

/// Builds an engine whose audit chain is bounded at `records`, so an append
/// past that bound fails and the decision it carried cannot be recorded.
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn engine_with_audit_bound(
    ttl_secs: u32,
    max_pending: usize,
    records: usize,
) -> Fallible<TestEngine> {
    let mut settings = config(ttl_secs, max_pending)?;
    settings.max_audit_records = records;
    Ok(DecisionEngine::new(
        settings,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FixedClock::new(START),
    ))
}

/// Builds an engine with no signer bound, so every seal fails closed.
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn unsigned_engine() -> Fallible<TestEngine> {
    Ok(DecisionEngine::new(
        config(60, 8)?,
        SignerBinding::unbound(),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FixedClock::new(START),
    ))
}

/// Builds an engine whose clock always fails.
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn faulty_clock_engine() -> Fallible<FaultyClockEngine> {
    Ok(DecisionEngine::new(
        config(60, 8)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FaultyClock,
    ))
}

/// The last record the engine's store holds.
///
/// # Errors
///
/// Returns [`FixtureError::NoRecord`] for an empty store.
pub fn stored_head(engine: &TestEngine) -> Fallible<AuditRecord> {
    let stored = engine.ledger().sink().accepted();
    Ok(*stored.last().ok_or(FixtureError::NoRecord)?)
}

/// The anchor of the chain the engine's store holds.
///
/// # Errors
///
/// Returns [`FixtureError::NoRecord`] for an empty store, and whatever the
/// library refuses the head record for.
pub fn anchor_of(engine: &TestEngine) -> Fallible<ChainAnchor> {
    Ok(ChainAnchor::from_record::<Sha256Hasher>(&stored_head(
        engine,
    )?)?)
}

/// A one-second sink deadline, comfortably above the sink's service time.
#[must_use]
pub fn io_deadline() -> IoDeadline {
    IoDeadline::try_from_millis(1_000)
        .unwrap_or(IoDeadline::from_millis(core::num::NonZeroU32::MIN))
}

/// Builds a validated intent.
///
/// # Errors
///
/// Propagates an identity parse or tier-downgrade failure.
pub fn intent(
    id: &str,
    maker: &str,
    action: ActionType,
    tier: RiskTier,
    class: OversightClass,
) -> Result<ActionIntent, DecisionError> {
    let spec = IntentSpec {
        id: IntentId::parse(id)?,
        agent: AgentId::parse("agent-01")?,
        maker: MakerId::parse(maker)?,
        action,
        declared_tier: tier,
        oversight: class,
        target: TargetResource::parse("/var/lib/aegis/example")?,
    };
    Ok(ActionIntent::new(spec)?)
}

/// Who a fixture record of `status` names, so that the record is well
/// formed: a maker at a level the status belongs to, and the one checker a
/// rejection needs. `None` for the record of a halt, which here is one no
/// person engaged and names nobody.
///
/// # Errors
///
/// Propagates an identity parse failure.
pub fn named_for(status: RecordStatus) -> Result<Option<RecordPrincipals>, DecisionError> {
    let held = RiskLevel::new(RiskTier::TierAConsequential, OversightClass::Standard);
    let (level, checkers) = match status {
        RecordStatus::HaltEngaged => return Ok(None),
        RecordStatus::PendingApproval => (held, None),
        RecordStatus::Rejected => (
            held,
            Some(CheckerSet::single(CheckerId::parse("checker-01")?)),
        ),
        RecordStatus::Approved
        | RecordStatus::Blocked
        | RecordStatus::Halted
        | RecordStatus::HaltReleased => (RiskLevel::LOWEST, None),
    };
    Ok(Some(RecordPrincipals {
        level,
        maker: MakerId::parse("maker-01")?,
        checkers,
    }))
}

// --- Fixtures for the encoding rules ---------------------------------------

/// A non-empty seal, produced through the library's own signer rather than
/// assembled from bytes, so the wire form under test is one the crate can
/// actually emit. Nothing here is a TPM2 signature: the library ships no
/// signer.
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn seal() -> Fallible<OversightSignature> {
    let signer = FixtureSigner::new()?;
    let signature = signer.sign(&Digest32::from_bytes([7u8; DIGEST_LEN]))?;
    Ok(OversightSignature::from_signature(
        &signature,
        SignatureAlgorithm::Tpm2RsaPss,
    ))
}

/// The correlation identifier every envelope fixture carries.
pub const CORRELATION: &str = "intent-0001";

/// The version tag of the fixture schema.
///
/// The library declares no schema of this kind; an adapter does. The fixture
/// plays that adapter with a schema of no real system, so that the encoding
/// rules are exercised the way an adapter uses them: through the public API.
pub const ENVELOPE: SchemaTag = SchemaTag::new("example.envelope.v1");

/// The versions of the fixture schema: the one tagged [`ENVELOPE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EnvelopeVersion {
    /// Version 1.
    #[serde(rename = "example.envelope.v1")]
    V1,
}

/// The fixture schema: one field of every type the library gives a wire form.
///
/// It is built the way the module documentation of `encoding` describes a
/// schema: the version first, the correlation identifier under its fixed key,
/// kebab-case keys, unknown keys refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Envelope {
    /// The schema version.
    pub schema: EnvelopeVersion,
    /// The identifier a refusal is correlated by.
    pub correlation_id: Identity,
    /// A request identifier.
    pub request_id: RequestId,
    /// An event identifier.
    pub event_id: EventId,
    /// An agent identifier.
    pub agent_id: AgentId,
    /// A maker identifier.
    pub maker: MakerId,
    /// An action type.
    pub action_type: ActionType,
    /// A target resource.
    pub target: TargetResource,
    /// A risk tier.
    pub risk_tier: RiskTier,
    /// An oversight class.
    pub oversight: OversightClass,
    /// A required approval.
    pub required_approval: RequiredApproval,
    /// A chain position.
    pub sequence: Sequence,
    /// A hash algorithm.
    pub algorithm: HashAlgorithm,
    /// A digest.
    pub previous: Digest32,
    /// A record status.
    pub status: RecordStatus,
    /// A refusal reason, when there is one.
    pub block_reason: Option<BlockReason>,
    /// A point in time.
    pub recorded_at: UnixSeconds,
    /// A seal, when there is one.
    pub signature: Option<OversightSignature>,
}

/// A well-formed, sealed envelope.
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn envelope() -> Fallible<Envelope> {
    Ok(Envelope {
        schema: EnvelopeVersion::V1,
        correlation_id: Identity::parse(CORRELATION)?,
        request_id: RequestId::parse("request-0001")?,
        event_id: EventId::parse("event-0001")?,
        agent_id: AgentId::parse("agent-01")?,
        maker: MakerId::parse("maker-alice")?,
        action_type: ActionType::FileDeletion,
        target: TargetResource::parse("/var/lib/example/file")?,
        risk_tier: RiskTier::TierAConsequential,
        oversight: OversightClass::Standard,
        required_approval: RequiredApproval::SingleChecker,
        sequence: Sequence::new(1),
        algorithm: HashAlgorithm::Sha256,
        previous: Digest32::GENESIS,
        status: RecordStatus::Approved,
        block_reason: None,
        recorded_at: UnixSeconds::new(1_000),
        signature: Some(seal()?),
    })
}

/// The correlation an envelope's refusals carry.
#[must_use]
pub fn correlation(value: &Envelope) -> Correlation {
    Correlation::new(ENVELOPE, Some(value.correlation_id))
}

/// Renders a value as one JSON payload, without the byte bound.
///
/// Negative tests need payloads the bounded encoder refuses to produce, so
/// they build the text here and hand it to the decoder under test.
///
/// # Errors
///
/// Propagates a serialisation failure.
pub fn render<T: serde::Serialize>(value: &T) -> Fallible<String> {
    Ok(serde_json::to_string(value)?)
}

/// Encodes an envelope through the library's own bounded encoder.
///
/// # Errors
///
/// Propagates the library's refusal.
pub fn encoded(value: &Envelope) -> Fallible<String> {
    let mut buffer = PayloadBuffer::new();
    Ok(encode_into(value, correlation(value), &mut buffer)?.to_owned())
}

/// Decodes an envelope through the library's own bounded decoder.
///
/// # Errors
///
/// Returns the library's refusal unchanged, so a test can compare it.
pub fn decoded(text: &str) -> Result<Envelope, ContractError> {
    decode_text(ENVELOPE, text)
}

/// Parses a rendered payload, edits it, and renders it again.
///
/// # Errors
///
/// Propagates a parse or render failure.
pub fn tamper(text: &str, edit: impl FnOnce(&mut serde_json::Value)) -> Fallible<String> {
    let mut value: serde_json::Value = serde_json::from_str(text)?;
    edit(&mut value);
    Ok(serde_json::to_string(&value)?)
}

/// Builds a string of `len` ASCII bytes drawn from the identifier charset.
#[must_use]
pub fn filler(len: usize) -> String {
    "a".repeat(len)
}
