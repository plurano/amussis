// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! One decision behind one call: proposal text in, outcome code out.

use amussis_decision::{
    AnchorError, ChainAnchor, CheckerId, CheckerSet, DecisionEngine, Digest32, EngineConfig,
    Identity, InterceptorOutcome, IoDeadline, MakerId, Proposal, ProposalError, ReleaseError,
    Sha256Hasher, SignerBinding, SignerKeyId, WarningCode,
};

use crate::host::{ClockAdapter, HostClock, HostSigner, HostSink, SignerAdapter, SinkAdapter};
use crate::wire::{FrameParts, ReleaseParts};

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
    /// The release bytes are not a release: they name no person or more than
    /// three, or the bytes of a person are not an identity.
    Release = 8,
    /// A release was asked for a chain that does not end halted.
    NotHalted = 9,
    /// The release lacks the approval the halted level demands: checkers are
    /// missing or too few, one person fills two places, or a checker is the
    /// releasing person.
    Approval = 10,
    /// The release was approved and could not be written into the chain: the
    /// clock, the signer or the sink failed. The chain stays halted.
    ReleaseFailed = 11,
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
/// store holds, and the release of the halt that record carries, if the halt
/// is to be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuation<'a> {
    head: &'a [u8],
    release: &'a [u8],
}

impl<'a> Continuation<'a> {
    /// Names the head frame of a chain and the release of its halt.
    ///
    /// `release` is empty, or the bytes [`ReleaseParts`] reads: the person
    /// who releases the halt and the checkers who approve it. With an empty
    /// `release` the engine starts in the state the head record carries, so a
    /// chain that ends halted continues halted.
    #[must_use]
    pub const fn new(head: &'a [u8], release: &'a [u8]) -> Self {
        Self { head, release }
    }

    /// Returns the head frame.
    #[must_use]
    pub const fn head(&self) -> &'a [u8] {
        self.head
    }

    /// Returns the release bytes; empty when the halt is kept.
    #[must_use]
    pub const fn release(&self) -> &'a [u8] {
        self.release
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
    /// state the head record carries. Held actions of the engine that wrote
    /// the head record are not carried over: they stay unreleased.
    ///
    /// When `from` carries a release, the engine is asked to release the halt
    /// before the binding exists: the release is held to the approval rule of
    /// the level the halt stands at, and its record is the first record of
    /// the new engine. A release that is refused or cannot be recorded sets
    /// up no binding; the store is as it was, and the host may continue from
    /// the same head again.
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
    /// frame of this contract and [`InitError::HeadDigest`] when the record
    /// does not hash to its digest. A release adds [`InitError::Release`]
    /// when its bytes are not a release, [`InitError::NotHalted`] when the
    /// chain does not end halted, [`InitError::Compromised`] when it ends
    /// halted as compromised, [`InitError::Approval`] when the checkers do
    /// not satisfy the approval rule of the halted level, and
    /// [`InitError::ReleaseFailed`] when the release cannot be recorded.
    pub fn continue_from(
        key_id: &[u8],
        io_deadline_ms: u32,
        from: Continuation<'_>,
        clock: C,
        signer: S,
        sink: K,
    ) -> Result<Self, InitError> {
        let (key_id, deadline) = settings(key_id, io_deadline_ms)?;
        let anchor = anchor_of(from.head())?;
        let release = release_of(from.release())?;
        let mut engine = DecisionEngine::continue_from(
            EngineConfig::default(),
            SignerBinding::Bound(SignerAdapter::new(key_id, signer)),
            SinkAdapter::new(sink),
            deadline,
            ClockAdapter::new(clock),
            &anchor,
        );
        if let Some((releaser, panel)) = release {
            engine
                .release_halt(&releaser, panel)
                .map_err(release_refusal)?;
        }
        Ok(Self { engine })
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
fn anchor_of(head: &[u8]) -> Result<ChainAnchor, InitError> {
    let parts = FrameParts::split(head).ok_or(InitError::Head)?;
    let digest = Digest32::from_bytes(parts.digest());
    ChainAnchor::from_preimage::<Sha256Hasher>(parts.preimage(), &digest).map_err(|error| {
        match error {
            AnchorError::DigestMismatch => InitError::HeadDigest,
            _ => InitError::Head,
        }
    })
}

/// The persons of a release: who releases, and the checkers who approve.
type Release = (MakerId, Option<CheckerSet>);

/// Reads the release bytes of a continuation; empty bytes ask for none.
fn release_of(release: &[u8]) -> Result<Option<Release>, InitError> {
    if release.is_empty() {
        return Ok(None);
    }
    let parts = ReleaseParts::split(release).ok_or(InitError::Release)?;
    let releaser = MakerId::from_identity(identity(parts.releaser())?);
    let panel = match parts.checkers() {
        [None, _] => None,
        [Some(only), None] => Some(CheckerSet::single(checker(only)?)),
        [Some(first), Some(second)] => Some(
            CheckerSet::dual(checker(first)?, checker(second)?).map_err(|_| InitError::Approval)?,
        ),
    };
    Ok(Some((releaser, panel)))
}

/// Reads the bytes of one person as an identity.
fn identity(bytes: &[u8]) -> Result<Identity, InitError> {
    core::str::from_utf8(bytes)
        .ok()
        .and_then(|text| Identity::parse(text).ok())
        .ok_or(InitError::Release)
}

fn checker(bytes: &[u8]) -> Result<CheckerId, InitError> {
    identity(bytes).map(CheckerId::from_identity)
}

/// The set-up error of a release the engine refused.
const fn release_refusal(error: ReleaseError) -> InitError {
    match error {
        ReleaseError::NotHalted => InitError::NotHalted,
        ReleaseError::Compromised => InitError::Compromised,
        ReleaseError::ApprovalMissing { .. } | ReleaseError::Approval(_) => InitError::Approval,
        // A halt that is not the inherited one cannot occur on an engine that
        // decided nothing yet; were it to occur, the release failed.
        _ => InitError::ReleaseFailed,
    }
}
