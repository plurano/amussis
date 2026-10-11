// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! One decision behind one call: proposal text in, outcome code out. The
//! decision of a held action and the operator halt are a call each.

use amussis_decision::{
    Adjudication, AnchorError, ChainAnchor, CheckerId, CheckerSet, DecisionEngine, DecisionError,
    Digest32, EngineConfig, HaltReason, Identity, InterceptorOutcome, IoDeadline, MakerId,
    OversightError, Proposal, ProposalError, ReleaseError, RequestId, RiskLevel, Sha256Hasher,
    SignerBinding, SignerKeyId, WarningCode,
};

use crate::host::{ClockAdapter, HostClock, HostSigner, HostSink, SignerAdapter, SinkAdapter};
use crate::wire::{AdjudicationParts, FrameParts, ReleaseParts};

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
    /// The checkers rejected a held action, and the rejection is recorded.
    /// Only an adjudication yields it.
    Rejected = 5,
    /// The engine did not take an adjudication; no vote is recorded. Only an
    /// adjudication yields it.
    NotAdjudicated = 6,
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
    /// The bytes are not an adjudication: the layout, the vote byte, or a
    /// person or an intent id that is no identity.
    Adjudication = 8,
}

/// Why the engine did not take an adjudication; the second byte of a
/// [`Class::NotAdjudicated`] code. An action that is held stays held, but for
/// the one case that says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Unadjudicated {
    /// The engine is halted; a halted engine takes no decision of a held
    /// action.
    Halted = 1,
    /// No action is held under the intent id.
    UnknownRequest = 2,
    /// The action was approved or rejected before.
    AlreadyDecided = 3,
    /// The approval window of the action closed.
    Expired = 4,
    /// The checkers do not satisfy the approval rule of the action: too few,
    /// one person named twice, or the maker of the action among them.
    Approval = 5,
    /// The clock was unreadable. The engine is halted.
    ClockUnavailable = 6,
    /// The vote could not be signed or stored. The hold is released without a
    /// decision and the engine is halted.
    Unrecorded = 7,
    /// The engine refused for a reason this table has no number for.
    Engine = 8,
}

/// What an operator halt came to; the answer of the halt export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HaltStatus {
    /// The engine is halted and the halt is a record of the chain.
    Recorded = 0,
    /// No engine is set up; nothing is halted.
    NotInitialised = 1,
    /// The call was made from inside a host function of another call; nothing
    /// is halted by it.
    Busy = 2,
    /// The engine is halted, and the record of the halt could not be signed
    /// or stored. The stored chain does not show the halt.
    Unrecorded = 3,
    /// The engine is halted and the halt is a record of the chain, and this
    /// call named nobody for it: the bytes handed over as the person who
    /// halts are not an identity.
    Unnamed = 4,
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
    /// tag of a block, the [`Refusal`] of a refused call, the
    /// [`Unadjudicated`] of an adjudication the engine did not take, else
    /// zero.
    #[must_use]
    pub const fn detail(self) -> u8 {
        self.detail
    }

    /// Returns the halt-reason tag when the halt latch caused a block, or
    /// when the engine is halted behind an adjudication it did not take, else
    /// zero.
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

    /// Brings the checkers' decision of a held action to the engine.
    ///
    /// `bytes` are what [`AdjudicationParts`] reads: the vote, the intent id
    /// the action was held under and one or two checkers. The engine holds
    /// the checkers to the approval rule of the action, against the maker it
    /// issued the hold for, and records the vote; who the checkers are is the
    /// host's statement.
    ///
    /// The code is [`Class::Allow`] for an approval and [`Class::Rejected`]
    /// for a rejection, each recorded; [`Class::NotAdjudicated`] with an
    /// [`Unadjudicated`] detail when the engine did not take the decision,
    /// its halt byte the halt-reason tag when the engine is halted after the
    /// call; and [`Class::Refused`] with [`Refusal::Adjudication`] when the
    /// bytes are not an adjudication.
    pub fn adjudicate(&mut self, bytes: &[u8]) -> OutcomeCode {
        let refused = OutcomeCode::refused(Refusal::Adjudication);
        let Some(parts) = AdjudicationParts::split(bytes) else {
            return refused;
        };
        let Some((request, panel)) = persons_of(&parts) else {
            return refused;
        };
        self.make_room();
        let taken = panel
            .map_err(DecisionError::from)
            .and_then(|panel| self.engine.adjudicate(&request, panel, parts.vote()));
        match taken {
            Ok(Adjudication::Approved { .. }) => OutcomeCode::of(Class::Allow, 0, 0),
            Ok(Adjudication::Rejected { .. }) => OutcomeCode::of(Class::Rejected, 0, 0),
            Err(error) => {
                let halt = self.engine.killswitch().reason().map_or(0, HaltReason::tag);
                OutcomeCode::of(Class::NotAdjudicated, unadjudicated(&error) as u8, halt)
            }
        }
    }

    /// Halts the engine as the stop of the person `by` is the identity of,
    /// at the risk level `level` is the tag of. The record of the halt names
    /// that person where the call engaged the halt or made it stricter.
    ///
    /// The halt is never refused for an argument. A value that is the tag of
    /// no level halts at the highest level, and its release is then held to
    /// the strictest approval. Bytes that are no identity halt as an operator
    /// stop that names nobody, and the answer says so.
    ///
    /// The engine is halted whatever this returns.
    /// [`HaltStatus::Unrecorded`] says that the record of the halt was not
    /// written, and [`HaltStatus::Unnamed`] that this call named nobody.
    pub fn halt(&mut self, level: u32, by: &[u8]) -> HaltStatus {
        let level = u8::try_from(level)
            .ok()
            .and_then(RiskLevel::from_tag)
            .unwrap_or(RiskLevel::HIGHEST);
        let operator = identity(by).map(MakerId::from_identity);
        self.make_room();
        let written = match &operator {
            Some(person) => self.engine.halt(person, level),
            None => self.engine.halt_unnamed(HaltReason::OperatorStop, level),
        };
        match (written, operator) {
            (Err(_), _) => HaltStatus::Unrecorded,
            (Ok(()), Some(_)) => HaltStatus::Recorded,
            (Ok(()), None) => HaltStatus::Unnamed,
        }
    }

    /// Drops the engine's audit window when it is full, so that the chain
    /// goes on past the window; the host's sink holds every record of it.
    fn make_room(&mut self) {
        if self.engine.audit_room() == 0 {
            // A rotation that fails frees no room and is not answered here.
            // The call that follows finds the window full, or the halt latch
            // the failed walk engaged, and answers with that.
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
    let person = |bytes| identity(bytes).ok_or(InitError::Release);
    let releaser = MakerId::from_identity(person(parts.releaser())?);
    let panel = match parts.checkers() {
        [None, _] => None,
        [Some(only), None] => Some(CheckerSet::single(CheckerId::from_identity(person(only)?))),
        [Some(first), Some(second)] => Some(
            CheckerSet::dual(
                CheckerId::from_identity(person(first)?),
                CheckerId::from_identity(person(second)?),
            )
            .map_err(|_| InitError::Approval)?,
        ),
    };
    Ok(Some((releaser, panel)))
}

/// Reads the bytes of one person, or of an intent id, as an identity.
fn identity(bytes: &[u8]) -> Option<Identity> {
    core::str::from_utf8(bytes)
        .ok()
        .and_then(|text| Identity::parse(text).ok())
}

/// The held action an adjudication names, and its panel: an error when two
/// checkers are one person. `None` when a part is no identity.
type Named = (RequestId, Result<CheckerSet, OversightError>);

/// Reads the persons of an adjudication.
fn persons_of(parts: &AdjudicationParts<'_>) -> Option<Named> {
    let request = RequestId::from_identity(identity(parts.request())?);
    let first = CheckerId::from_identity(identity(parts.first())?);
    let panel = match parts.second() {
        None => Ok(CheckerSet::single(first)),
        Some(second) => CheckerSet::dual(first, CheckerId::from_identity(identity(second)?)),
    };
    Some((request, panel))
}

/// The number of the reason the engine did not take an adjudication for.
const fn unadjudicated(error: &DecisionError) -> Unadjudicated {
    match error {
        DecisionError::Oversight(OversightError::SystemHalted) => Unadjudicated::Halted,
        DecisionError::Oversight(OversightError::UnknownRequest) => Unadjudicated::UnknownRequest,
        DecisionError::Oversight(OversightError::AlreadyDecided) => Unadjudicated::AlreadyDecided,
        DecisionError::Oversight(OversightError::ApprovalExpired) => Unadjudicated::Expired,
        DecisionError::Oversight(
            OversightError::DuplicateChecker
            | OversightError::MakerIsChecker
            | OversightError::AnnexIiiRequiresTwoCheckers
            | OversightError::NoApprovalRequired,
        ) => Unadjudicated::Approval,
        DecisionError::Clock(_) => Unadjudicated::ClockUnavailable,
        DecisionError::Ledger(_) => Unadjudicated::Unrecorded,
        _ => Unadjudicated::Engine,
    }
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
