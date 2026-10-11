// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! One decision behind one call: proposal text in, outcome code out.

use amussis_decision::{
    AnchorError, ChainAnchor, DecisionEngine, Digest32, EngineConfig, InterceptorOutcome,
    IoDeadline, Proposal, ProposalError, Sha256Hasher, SignerBinding, SignerKeyId, WarningCode,
};

use crate::host::{ClockAdapter, HostClock, HostSigner, HostSink, SignerAdapter, SinkAdapter};
use crate::wire::FrameParts;

/// The engine a binding runs: SHA-256 chain, host signer, host sink, host clock.
pub type Engine<C, S, K> =
    DecisionEngine<Sha256Hasher, SignerAdapter<S>, SinkAdapter<K>, ClockAdapter<C>>;

/// What an outcome means for the action; the low byte of an outcome code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    /// The action may proceed.
    Allow = 0,
    /// The action may proceed, with a notice recorded.
    Warn = 1,
    /// The action waits for a human decision.
    RequireApproval = 2,
    /// The engine refused the action and recorded the refusal.
    Block = 3,
    /// The binding refused the call before the engine saw it; nothing is recorded.
    Refused = 4,
}

/// Why the binding refused a call; the second byte of a [`Class::Refused`] code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Refusal {
    /// No engine is set up yet.
    NotInitialised = 1,
    /// The proposal text is longer than the bound.
    TooLong = 2,
    /// The proposal bytes are not UTF-8.
    NotUtf8 = 3,
    /// The proposal names a schema version this library does not read.
    UnknownVersion = 4,
    /// The proposal text does not follow the schema.
    Malformed = 5,
    /// The proposal follows the schema, and the engine's rules refuse its content.
    IntentRefused = 6,
    /// A call was made from inside a host function of another call.
    Busy = 7,
}

/// Why setting up a binding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InitError {
    /// A binding is already set up; its audit chain is not replaced.
    AlreadyInitialised = 1,
    /// The signer key identifier is not a valid identifier.
    KeyId = 2,
    /// The sink deadline is zero.
    Deadline = 3,
    /// The call was made from inside a host function of another call.
    Busy = 4,
    /// The head bytes are not one record frame, or its pre-image is not a
    /// canonical audit pre-image of this contract.
    Head = 5,
    /// The head record does not hash to the digest it is filed under.
    HeadDigest = 6,
    /// The chain ends halted as compromised; its halt is not released.
    Compromised = 7,
    /// The latch flag is neither [`Latch::Keep`] nor [`Latch::Release`].
    Latch = 8,
}

/// What a continuation does with the halt latch of the chain it continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Latch {
    /// The engine starts in the state the head record carries: a chain that
    /// ends halted continues halted.
    Keep = 0,
    /// The engine starts with the latch armed. This is the release of a halt;
    /// the chain shows it as the step from a halted record to an armed one.
    Release = 1,
}

impl Latch {
    /// Reads the flag that crosses the interface, or returns `None` for a
    /// number that names neither choice.
    #[must_use]
    pub const fn from_flag(flag: u32) -> Option<Self> {
        match flag {
            0 => Some(Self::Keep),
            1 => Some(Self::Release),
            _ => None,
        }
    }
}

/// One outcome as the three bytes that cross to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeCode {
    class: Class,
    detail: u8,
    halt: u8,
}

impl OutcomeCode {
    /// The code of a call the binding refused.
    #[must_use]
    pub const fn refused(why: Refusal) -> Self {
        Self {
            class: Class::Refused,
            detail: why as u8,
            halt: 0,
        }
    }

    /// The code of an engine outcome.
    #[must_use]
    pub const fn from_outcome(outcome: &InterceptorOutcome) -> Self {
        match outcome {
            InterceptorOutcome::Allow => Self::of(Class::Allow, 0, 0),
            InterceptorOutcome::Warn { code } => Self::of(Class::Warn, warning_tag(*code), 0),
            InterceptorOutcome::RequireApproval(_) => Self::of(Class::RequireApproval, 0, 0),
            InterceptorOutcome::Block { reason } => {
                Self::of(Class::Block, reason.tag(), reason.halt_tag())
            }
        }
    }

    const fn of(class: Class, detail: u8, halt: u8) -> Self {
        Self {
            class,
            detail,
            halt,
        }
    }

    /// Returns the outcome class.
    #[must_use]
    pub const fn class(self) -> Class {
        self.class
    }

    /// Returns the detail byte: the warning tag of a warning, the block-reason
    /// tag of a block, the [`Refusal`] of a refused call, else zero.
    #[must_use]
    pub const fn detail(self) -> u8 {
        self.detail
    }

    /// Returns the halt-reason tag when the halt latch caused a block, else zero.
    #[must_use]
    pub const fn halt(self) -> u8 {
        self.halt
    }

    /// Returns whether the action may proceed.
    #[must_use]
    pub const fn permits_execution(self) -> bool {
        matches!(self.class, Class::Allow | Class::Warn)
    }

    /// Packs the code: class in the low byte, then detail, then halt.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        u32::from_le_bytes([self.class as u8, self.detail, self.halt, 0])
    }
}

/// The chain a new engine continues: the frame of the last record the host's
/// store holds, and what becomes of the halt latch that record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuation<'a> {
    head: &'a [u8],
    latch: Latch,
}

impl<'a> Continuation<'a> {
    /// Names the head frame of a chain and the choice for its halt latch.
    #[must_use]
    pub const fn new(head: &'a [u8], latch: Latch) -> Self {
        Self { head, latch }
    }

    /// Returns the head frame.
    #[must_use]
    pub const fn head(&self) -> &'a [u8] {
        self.head
    }

    /// Returns the choice for the halt latch.
    #[must_use]
    pub const fn latch(&self) -> Latch {
        self.latch
    }
}

/// The stable tag of a warning; zero is reserved for "no warning".
const fn warning_tag(code: WarningCode) -> u8 {
    match code {
        WarningCode::MonitoredTierB => 1,
    }
}

/// The decision engine over three host effects.
#[derive(Debug)]
pub struct Binding<C: HostClock, S: HostSigner, K: HostSink> {
    engine: Engine<C, S, K>,
}

impl<C: HostClock, S: HostSigner, K: HostSink> Binding<C, S, K> {
    /// Sets up an engine whose signer signs under `key_id` and whose sink is
    /// given `io_deadline_ms` milliseconds for each record.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::KeyId`] when `key_id` is not a valid identifier
    /// and [`InitError::Deadline`] when the deadline is zero.
    pub fn new(
        key_id: &[u8],
        io_deadline_ms: u32,
        clock: C,
        signer: S,
        sink: K,
    ) -> Result<Self, InitError> {
        let (key_id, deadline) = settings(key_id, io_deadline_ms)?;
        Ok(Self {
            engine: DecisionEngine::new(
                EngineConfig::default(),
                SignerBinding::Bound(SignerAdapter::new(key_id, signer)),
                SinkAdapter::new(sink),
                deadline,
                ClockAdapter::new(clock),
            ),
        })
    }

    /// Sets up an engine that continues the chain `from` names by the frame of
    /// its last stored record, as the host's sink received it.
    ///
    /// The first record of the new engine links onto the head record and
    /// carries the next sequence number. The engine starts in the halt-latch
    /// state the head record carries unless `from` asks for [`Latch::Release`].
    /// Held actions of the engine that wrote the head record are not carried
    /// over: they stay unreleased.
    ///
    /// The head is checked for integrity, not for origin: its content must
    /// hash to its digest, and its signature is not verified. That the frame
    /// is the last record of the store, and that the store is the host's own,
    /// is the host's statement.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::KeyId`] and [`InitError::Deadline`] as
    /// [`Self::new`] does, [`InitError::Head`] when the head is not a record
    /// frame of this contract, [`InitError::HeadDigest`] when the record does
    /// not hash to its digest, and [`InitError::Compromised`] when a release
    /// is asked for a chain halted as compromised.
    pub fn continue_from(
        key_id: &[u8],
        io_deadline_ms: u32,
        from: Continuation<'_>,
        clock: C,
        signer: S,
        sink: K,
    ) -> Result<Self, InitError> {
        let (key_id, deadline) = settings(key_id, io_deadline_ms)?;
        let anchor = anchor_of(from)?;
        Ok(Self {
            engine: DecisionEngine::continue_from(
                EngineConfig::default(),
                SignerBinding::Bound(SignerAdapter::new(key_id, signer)),
                SinkAdapter::new(sink),
                deadline,
                ClockAdapter::new(clock),
                &anchor,
            ),
        })
    }

    /// Returns the engine, for reading its ledger and halt latch.
    #[must_use]
    pub const fn engine(&self) -> &Engine<C, S, K> {
        &self.engine
    }

    /// Decides the proposal given as its text.
    pub fn decide(&mut self, text: &[u8]) -> OutcomeCode {
        let Ok(text) = core::str::from_utf8(text) else {
            return OutcomeCode::refused(Refusal::NotUtf8);
        };
        let proposal = match Proposal::decode(text) {
            Ok(proposal) => proposal,
            Err(ProposalError::TooLong { .. }) => return OutcomeCode::refused(Refusal::TooLong),
            Err(ProposalError::UnknownVersion { .. }) => {
                return OutcomeCode::refused(Refusal::UnknownVersion);
            }
            Err(_) => return OutcomeCode::refused(Refusal::Malformed),
        };
        let Ok(intent) = proposal.intent() else {
            return OutcomeCode::refused(Refusal::IntentRefused);
        };
        self.make_room();
        OutcomeCode::from_outcome(&self.engine.decide(&intent))
    }

    /// Drops the engine's audit window when it is full, so that the chain
    /// goes on past the window; the host's sink holds every record of it.
    fn make_room(&mut self) {
        if self.engine.audit_room() == 0 {
            // A rotation that fails frees no room and is not answered here.
            // The decision that follows finds the window full, or the halt
            // latch the failed walk engaged, and blocks with that reason.
            self.engine.rotate_ledger().ok();
        }
    }
}

/// Reads the two settings every set-up takes.
fn settings(key_id: &[u8], io_deadline_ms: u32) -> Result<(SignerKeyId, IoDeadline), InitError> {
    let key_id = core::str::from_utf8(key_id)
        .ok()
        .and_then(|text| SignerKeyId::parse(text).ok())
        .ok_or(InitError::KeyId)?;
    let deadline = IoDeadline::try_from_millis(io_deadline_ms).ok_or(InitError::Deadline)?;
    Ok((key_id, deadline))
}

/// Reads the head frame of a chain as the point to continue it from.
fn anchor_of(from: Continuation<'_>) -> Result<ChainAnchor, InitError> {
    let parts = FrameParts::split(from.head()).ok_or(InitError::Head)?;
    let digest = Digest32::from_bytes(parts.digest());
    let anchor =
        ChainAnchor::from_preimage::<Sha256Hasher>(parts.preimage(), &digest).map_err(|error| {
            match error {
                AnchorError::DigestMismatch => InitError::HeadDigest,
                _ => InitError::Head,
            }
        })?;
    match from.latch() {
        Latch::Keep => Ok(anchor),
        Latch::Release => anchor.release_latch().map_err(|_| InitError::Compromised),
    }
}
