// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Fixtures shared by the integration tests.
//!
//! Everything here reaches `aegis-justitia` through its public API only. That
//! is the proof the milestone asks for: the risk-tier, maker-checker, Annex III,
//! timeout and killswitch logic is library code, not a `#[cfg(test)]` module.
//!
//! Fixture failures raise [`FixtureError`], never a library error borrowed as
//! filler. A test that cannot build its own inputs is a broken fixture, not a
//! refused signature or an expired window, and the two must not be confusable
//! in a failure report.

#![allow(dead_code)]

use aegis_justitia::{
    ActionIntent, ActionProposal, ActionProposalVersion, ActionType, AgentId, AuditRecordVersion,
    ClockError, DIGEST_LEN, DecisionRequest, DecisionRequestVersion, Digest32, EngineConfig,
    EventId, FixedClock, HashAlgorithm, Identity, InMemorySink, IntentId, IntentSpec, IoDeadline,
    JustitiaEngine, JustitiaError, MAX_SIGNATURE_BYTES, MakerId, OversightClass,
    OversightSignature, PayloadBuffer, RecordSigner, RecordStatus, RequestId, RequiredApproval,
    RiskTier, Sequence, Sha256Hasher, SignError, Signature, SignatureAlgorithm, SignedAuditRecord,
    SignerBinding, SignerKeyId, TargetResource, Ttl, UnixSeconds,
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
    pub fn new() -> Result<Self, JustitiaError> {
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
    pub fn new() -> Result<Self, JustitiaError> {
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

/// A clock whose source is broken. `aegis_justitia::Clock` is public API, so a
/// fault injector is an ordinary implementation of it rather than a hook.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultyClock;

impl aegis_justitia::Clock for FaultyClock {
    fn now(&self) -> Result<UnixSeconds, ClockError> {
        Err(ClockError::BeforeEpoch)
    }
}

/// The engine shape used by most tests: SHA-256, a fixture signer, an in-memory
/// sink and a clock the test advances.
pub type TestEngine = JustitiaEngine<Sha256Hasher, FixtureSigner, InMemorySink, FixedClock>;

/// The engine shape used to exercise a clock fault.
pub type FaultyClockEngine = JustitiaEngine<Sha256Hasher, FixtureSigner, InMemorySink, FaultyClock>;

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
    Ok(JustitiaEngine::new(
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
    Ok(JustitiaEngine::new(
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
    Ok(JustitiaEngine::new(
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
    Ok(JustitiaEngine::new(
        config(60, 8)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FaultyClock,
    ))
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
) -> Result<ActionIntent, JustitiaError> {
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

// --- Milestone M14 consumer-contract fixtures -----------------------------

/// A non-empty seal, produced through the library's own signer rather than
/// assembled from bytes, so the wire form under test is one the crate can
/// actually emit. Nothing here is a TPM2 signature: M14 implements no signing.
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

/// The correlation identifier every contract fixture threads through.
pub const CORRELATION: &str = "intent-0001";

/// A well-formed, signed action proposal from P09 Minerva.
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn proposal() -> Fallible<ActionProposal> {
    Ok(ActionProposal {
        schema: ActionProposalVersion::V1,
        edge: ActionProposal::EDGE,
        direction: ActionProposal::DIRECTION,
        correlation_id: Identity::parse(CORRELATION)?,
        agent_id: AgentId::parse("agent-01")?,
        maker: MakerId::parse("maker-alice")?,
        action_type: ActionType::FileDeletion,
        target: TargetResource::parse("/var/lib/aegis/example")?,
        declared_tier: RiskTier::TierAConsequential,
        oversight: OversightClass::Standard,
        payload_hash: Digest32::from_bytes([3u8; DIGEST_LEN]),
        proposed_at: UnixSeconds::new(1_000),
        signature: Some(seal()?),
    })
}

/// A well-formed decision request for P05 Forum, with a `window` second window.
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn decision_request(
    tier: RiskTier,
    class: OversightClass,
    window: u64,
) -> Fallible<DecisionRequest> {
    let created = 1_000u64;
    Ok(DecisionRequest {
        schema: DecisionRequestVersion::V1,
        edge: DecisionRequest::EDGE,
        correlation_id: Identity::parse(CORRELATION)?,
        request_id: RequestId::parse("request-0001")?,
        agent_id: AgentId::parse("agent-01")?,
        maker: MakerId::parse("maker-alice")?,
        proposed_action: ActionType::FileDeletion,
        target: TargetResource::parse("/var/lib/aegis/example")?,
        risk_tier: tier,
        oversight: class,
        required_approval: RequiredApproval::for_action(tier, class),
        created_at: UnixSeconds::new(created),
        due_at: UnixSeconds::new(created.saturating_add(window)),
    })
}

/// A well-formed signed audit record for P16 Athena at `sequence`.
///
/// The predecessor link follows the genesis rule: all zero at the head of the
/// chain, and a real digest anywhere else.
///
/// # Errors
///
/// Propagates a fixture construction failure.
pub fn audit_record(sequence: u64) -> Fallible<SignedAuditRecord> {
    let previous = if sequence == 1 {
        Digest32::GENESIS
    } else {
        Digest32::from_bytes([9u8; DIGEST_LEN])
    };
    Ok(SignedAuditRecord {
        schema: AuditRecordVersion::V1,
        edge: SignedAuditRecord::EDGE,
        correlation_id: Identity::parse(CORRELATION)?,
        event_id: EventId::parse("event-0001")?,
        sequence: Sequence::new(sequence),
        algorithm: HashAlgorithm::Sha256,
        previous,
        digest: Digest32::from_bytes([5u8; DIGEST_LEN]),
        action_type: ActionType::FileDeletion,
        status: RecordStatus::Approved,
        block_reason: None,
        actor_id: AgentId::parse("agent-01")?,
        recorded_at: UnixSeconds::new(1_000),
        oversight_signature: Some(seal()?),
    })
}

/// Renders a value as one JSON payload, without the contract validation.
///
/// Negative tests need payloads the encoders refuse to produce, so they build
/// the text here and hand it to the decoder under test.
///
/// # Errors
///
/// Propagates a serialisation failure.
pub fn render<T: serde::Serialize>(value: &T) -> Fallible<String> {
    Ok(serde_json::to_string(value)?)
}

/// Encodes a valid payload through the contract's own bounded encoder.
///
/// # Errors
///
/// Propagates the contract refusal.
pub fn encoded<T>(value: &T) -> Fallible<String>
where
    T: Encodable,
{
    let mut buffer = PayloadBuffer::new();
    Ok(value.encode(&mut buffer)?.to_owned())
}

/// The three contract payloads, behind one fixture-side encoding call.
pub trait Encodable {
    /// Encodes this payload into `buffer`.
    ///
    /// # Errors
    ///
    /// Propagates the contract refusal.
    fn encode<'b>(
        &self,
        buffer: &'b mut PayloadBuffer,
    ) -> Result<&'b str, aegis_justitia::ContractError>;
}

impl Encodable for ActionProposal {
    fn encode<'b>(
        &self,
        buffer: &'b mut PayloadBuffer,
    ) -> Result<&'b str, aegis_justitia::ContractError> {
        self.encode_into(buffer)
    }
}

impl Encodable for DecisionRequest {
    fn encode<'b>(
        &self,
        buffer: &'b mut PayloadBuffer,
    ) -> Result<&'b str, aegis_justitia::ContractError> {
        self.encode_into(buffer)
    }
}

impl Encodable for SignedAuditRecord {
    fn encode<'b>(
        &self,
        buffer: &'b mut PayloadBuffer,
    ) -> Result<&'b str, aegis_justitia::ContractError> {
        self.encode_into(buffer)
    }
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
