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
    ActionIntent, ActionType, AgentId, ClockError, Digest32, EngineConfig, FixedClock,
    InMemorySink, IntentId, IntentSpec, IoDeadline, JustitiaEngine, JustitiaError,
    MAX_SIGNATURE_BYTES, MakerId, OversightClass, RecordSigner, RiskTier, Sha256Hasher, SignError,
    Signature, SignerBinding, SignerKeyId, TargetResource, Ttl, UnixSeconds,
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
