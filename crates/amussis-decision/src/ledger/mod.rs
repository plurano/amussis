// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The hash-linked audit ledger.
//!
//! Each record commits to the digest of its predecessor, so a chain re-walk
//! detects any edit to a stored record. The walk is iterative and bounded; the
//! recursion NASA rule 1 forbids has no place here.
//!
//! Every refusal is recorded, not only every release. A record carries the
//! [`BlockReason`] that produced it whenever one exists, so a refused action is
//! reconstructible from the chain alone.
//!
//! # Two kinds of record
//!
//! Most records decide a proposed action and name it: the intent, the agent
//! and what the action does ([`RecordSubject`]). A record of the halt latch
//! itself has no proposal behind it and names none: the halt
//! ([`RecordStatus::HaltEngaged`]) and its release
//! ([`RecordStatus::HaltReleased`]). The canonical pre-image keeps one layout
//! for both; a latch record writes a zero action tag and two empty
//! identifiers, which no decision record has. A draft whose status and fields
//! do not belong together has no canonical pre-image
//! ([`PreimageError::Shape`]), so it is neither sealed nor verified.
//!
//! # Who a record names
//!
//! A record that decides an action names the maker of the proposal, and the
//! record of a vote names the checkers who cast it. The record of a release
//! names the person who released the halt and the checkers who approved the
//! release. Each of these records also states the risk level the approval
//! rule was asked at ([`RecordPrincipals`]), so a reader holds a record to
//! that rule with the record alone: a vote or a release that names fewer
//! checkers than its level demands has no canonical pre-image, and neither
//! has one whose maker is among its checkers or whose two checkers are one.
//! Both are comparisons of bytes. The record of a halt names the person who
//! engaged it, at the level the halt stands at and without a checker. A halt
//! no person engaged names nobody: a fault the engine found, or a stop whose
//! person the caller cannot name.
//!
//! An identity is the bytes the caller passed in, and the chain keeps them
//! for as long as it is kept. The library does not hash them and cannot tell
//! a name from a pseudonym. What a caller passes in is the caller's rule; the
//! repository's `README.md` states the one this library is built for.
//!
//! Both retention buffers -- [`AuditLedger`]'s own record list and
//! [`InMemorySink`]'s -- are reserved to their scalar bound at construction and
//! refuse a push at that bound, so neither reallocates on the decision path.
//! See the crate documentation for the memory arithmetic behind the bounds.
//!
//! # The window and the chain
//!
//! The ledger's record list is a window on the chain, not the chain. The sink
//! holds every record; the ledger holds those sealed since the window was
//! last dropped, at most `bound` of them, and refuses the next one at the
//! bound. [`AuditLedger::remaining`] is the room left, and
//! [`AuditLedger::rotate`] drops the window once it has been re-walked and the
//! sink has flushed. The head digest, the next sequence number and the last
//! time stay, so the next record links onto the dropped one.
//!
//! A new ledger value continues a stored chain through
//! [`AuditLedger::continue_from`] and a [`ChainAnchor`]; see [`anchor`].

pub mod anchor;
pub mod hash;
#[cfg(feature = "jsonl")]
pub mod jsonl;
pub mod sha256;
pub mod signer;

use core::num::NonZeroU32;

use crate::identity::{AgentId, CheckerId, IntentId, MakerId};
use crate::killswitch::KillswitchState;
use crate::ledger::anchor::ChainAnchor;
use crate::ledger::hash::{
    CanonicalBuffer, Digest32, HashAlgorithm, HashError, LedgerHasher, PreimageError,
};
use crate::ledger::sha256::Sha256Hasher;
use crate::ledger::signer::{RecordSigner, SignError, Signature, SignerBinding};
use crate::outcome::BlockReason;
use crate::oversight::CheckerSet;
use crate::risk::{ActionType, RiskLevel};
use crate::time::UnixSeconds;
use crate::{CONTRACT_VERSION, DEFAULT_SINK_SERVICE_MILLIS, MAX_LEDGER_RECORDS};

/// Domain-separation tag prefixed to every canonical audit pre-image.
pub const AUDIT_DOMAIN: &[u8] = b"amussis.decision.audit.v1\0";

/// Reasons the ledger refuses a record or a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// A record names an algorithm the ledger does not use.
    #[error("record algorithm {found} does not match the ledger algorithm {expected}")]
    AlgorithmMismatch {
        /// The algorithm the ledger uses.
        expected: HashAlgorithm,
        /// The algorithm the record names.
        found: HashAlgorithm,
    },
    /// A record does not link to its predecessor.
    #[error("record {at} does not link to its predecessor")]
    PreviousHashMismatch {
        /// The sequence number of the offending record.
        at: u64,
    },
    /// A record's stored digest does not match its content.
    #[error("record {at} has a stored digest that does not match its content")]
    DigestMismatch {
        /// The sequence number of the offending record.
        at: u64,
    },
    /// A record's sequence number is not the expected successor.
    #[error("expected sequence {expected}, found {found}")]
    SequenceGap {
        /// The sequence number the chain expected.
        expected: u64,
        /// The sequence number observed.
        found: u64,
    },
    /// The chain or the ledger exceeded its scalar bound.
    #[error("record count exceeds the bound of {max}")]
    LengthBoundExceeded {
        /// The scalar bound.
        max: usize,
    },
    /// A record carries a timestamp earlier than its predecessor.
    #[error("record timestamp {observed} precedes the previous record at {last}")]
    NonMonotonicTimestamp {
        /// The previous record's timestamp.
        last: u64,
        /// The timestamp observed.
        observed: u64,
    },
    /// The canonical pre-image could not be built.
    #[error("canonical pre-image: {0}")]
    Preimage(#[from] PreimageError),
    /// The digest could not be produced.
    #[error("digest: {0}")]
    Hash(#[from] HashError),
    /// The record could not be sealed.
    #[error("seal: {0}")]
    Sign(#[from] SignError),
    /// The record could not be handed to the sink.
    #[error("sink: {0}")]
    Sink(#[from] SinkError),
}

/// Reasons a sink refuses a record.
///
/// Each variant has a producer in this module: [`InMemorySink`] produces
/// [`Self::WouldBlock`] when the offered [`IoDeadline`] is shorter than the
/// service time it declares and [`Self::Full`] at its bound, and
/// [`UnavailableSink`] produces [`Self::Unavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SinkError {
    /// The offered deadline is shorter than the sink's declared service time.
    #[error("the sink would block past the {offered}ms deadline; it needs {needed}ms")]
    WouldBlock {
        /// The service time the sink declares, in milliseconds.
        needed: u32,
        /// The deadline the caller offered, in milliseconds.
        offered: u32,
    },
    /// The sink reached its capacity bound.
    #[error("the sink reached its capacity bound of {max}")]
    Full {
        /// The scalar capacity bound.
        max: usize,
    },
    /// The sink is not usable at all.
    #[error("the sink is unavailable")]
    Unavailable,
}

/// The deadline within which a sink operation must complete.
///
/// The parameter is in the trait signature so a future file-backed or daemon
/// sink cannot implement [`LedgerSink`] without receiving one; that is the
/// HISS-02 obligation for I/O made structural.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoDeadline(NonZeroU32);

impl IoDeadline {
    /// Builds a deadline of `millis` milliseconds.
    #[must_use]
    pub const fn from_millis(millis: NonZeroU32) -> Self {
        Self(millis)
    }

    /// Builds a deadline of `millis` milliseconds, or `None` when it is zero.
    #[must_use]
    pub const fn try_from_millis(millis: u32) -> Option<Self> {
        match NonZeroU32::new(millis) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the deadline in milliseconds.
    #[must_use]
    pub const fn millis(self) -> u32 {
        self.0.get()
    }
}

/// A monotonically increasing record sequence number, starting at one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct Sequence(u64);

impl Sequence {
    /// The sequence number of the first record in a chain.
    pub const FIRST: Self = Self(1);

    /// Wraps a raw sequence number.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw sequence number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the successor, or `None` on overflow.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Returns the sequence number after `sequence`.
///
/// Saturating, not wrapping: at the `u64` ceiling a chain stops moving on
/// instead of restarting at one, and the walk refuses what follows.
const fn successor(sequence: Sequence) -> Sequence {
    Sequence::new(sequence.get().saturating_add(1))
}

/// Where a chain stands: what the next record must link to, the sequence
/// number it must carry, and the time it must not precede.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Position {
    previous: Digest32,
    expected: Sequence,
    last_at: Option<UnixSeconds>,
}

impl Position {
    /// Before the first record of a chain.
    const GENESIS: Self = Self {
        previous: Digest32::GENESIS,
        expected: Sequence::FIRST,
        last_at: None,
    };

    /// Directly after the head record `anchor` names.
    const fn after(anchor: &ChainAnchor) -> Self {
        Self {
            previous: anchor.head(),
            expected: successor(anchor.sequence()),
            last_at: Some(anchor.at()),
        }
    }
}

/// The terminal or interim status a record carries.
///
/// `Blocked` and `Halted` extend the three-value vocabulary of the imported
/// oversight sketch; M14 must take the superset into the versioned schema.
/// `HaltEngaged` and `HaltReleased` are the two records of the halt latch
/// itself; they decide no action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordStatus {
    /// Held for a checker decision.
    PendingApproval,
    /// Allowed to proceed.
    Approved,
    /// Refused by a checker.
    Rejected,
    /// Refused by the engine.
    Blocked,
    /// Refused because the system is halted.
    Halted,
    /// The halt latch engaged. The record decides no action.
    HaltEngaged,
    /// The halt latch was released. The record decides no action.
    HaltReleased,
}

impl RecordStatus {
    /// Returns the stable tag mixed into the canonical audit pre-image.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::PendingApproval => 1,
            Self::Approved => 2,
            Self::Rejected => 3,
            Self::Blocked => 4,
            Self::Halted => 5,
            Self::HaltEngaged => 6,
            Self::HaltReleased => 7,
        }
    }

    /// Returns `true` for the two records of the halt latch itself, which
    /// decide no action and name no subject.
    #[must_use]
    pub const fn is_of_latch(self) -> bool {
        matches!(self, Self::HaltEngaged | Self::HaltReleased)
    }

    /// Returns the record status name used in records and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PendingApproval => "pending-approval",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Blocked => "blocked",
            Self::Halted => "halted",
            Self::HaltEngaged => "halt-engaged",
            Self::HaltReleased => "halt-released",
        }
    }
}

/// The proposed action a record decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSubject {
    /// The intent the record describes.
    pub intent_id: IntentId,
    /// The agent that proposed the action.
    pub agent: AgentId,
    /// What the action does.
    pub action_type: ActionType,
}

/// Who a record names, and the risk level the approval rule was asked at.
///
/// Every identity is the bytes the caller passed in. Two identities are one
/// principal exactly when their bytes are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordPrincipals {
    /// The risk level of the action the record decides, or of the halt the
    /// record engages or releases.
    pub level: RiskLevel,
    /// The maker of the proposal the record decides, or the person who
    /// engaged or released the halt.
    pub maker: MakerId,
    /// The checkers who cast the vote the record states, or who approved the
    /// release. `None` where nobody voted.
    pub checkers: Option<CheckerSet>,
}

impl RecordPrincipals {
    /// Returns the checkers in the order the record states them.
    #[must_use]
    pub const fn checkers(&self) -> [Option<CheckerId>; 2] {
        match self.checkers {
            None => [None, None],
            Some(CheckerSet::Single(only)) => [Some(only), None],
            Some(CheckerSet::Dual { first, second }) => [Some(first), Some(second)],
        }
    }

    /// Returns whether the maker is none of the checkers and two checkers
    /// are two principals. Both are comparisons of bytes.
    #[must_use]
    pub fn is_separated(&self) -> bool {
        match self.checkers {
            None => true,
            Some(CheckerSet::Single(only)) => !self.maker.is_same_principal(&only),
            Some(CheckerSet::Dual { first, second }) => {
                first != second
                    && !self.maker.is_same_principal(&first)
                    && !self.maker.is_same_principal(&second)
            }
        }
    }

    /// Returns whether nobody voted.
    const fn is_unvoted(&self) -> bool {
        self.checkers.is_none()
    }

    /// Returns whether the checkers are a vote the approval rule of the level
    /// takes: separated from the maker, and as many as the level demands.
    fn is_voted(&self) -> bool {
        let required = self.level.required_approval();
        let named = self.checkers.map_or(0, |panel| panel.len());
        required.needs_human() && self.is_separated() && named >= required.checker_count()
    }

    /// Returns whether the principals are those of a release: the level's
    /// vote where the level demands one, and otherwise the releasing person
    /// alone or beside checkers who are not that person.
    fn is_release(&self) -> bool {
        if self.level.required_approval().needs_human() {
            self.is_voted()
        } else {
            self.is_separated()
        }
    }

    /// Returns whether the principals are those of a halt in the state
    /// `killswitch`: one person, at the level the halt stands at. Nobody
    /// votes on a halt.
    fn is_halt_of(&self, killswitch: KillswitchState) -> bool {
        let stands_at = match killswitch {
            KillswitchState::Engaged { level, .. } => Some(level),
            KillswitchState::Armed => None,
        };
        self.is_unvoted() && stands_at == Some(self.level)
    }

    /// Returns whether the principals belong to a record of `status` that
    /// decides an action.
    fn fits_decision(&self, status: RecordStatus) -> bool {
        let held = self.level.required_approval().needs_human();
        match status {
            RecordStatus::Approved if held => self.is_voted(),
            RecordStatus::Rejected => self.is_voted(),
            RecordStatus::PendingApproval => held && self.is_unvoted(),
            RecordStatus::Approved | RecordStatus::Blocked | RecordStatus::Halted => {
                self.is_unvoted()
            }
            RecordStatus::HaltEngaged | RecordStatus::HaltReleased => false,
        }
    }
}

/// The caller-supplied fields of one audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordDraft {
    /// The action the record decides.
    ///
    /// `None` for a record of the halt latch itself and for no other record:
    /// see [`Self::is_well_formed`].
    pub subject: Option<RecordSubject>,
    /// Who the record names, and the risk level they answer at.
    ///
    /// `None` for the record of a halt no person engaged and for no other
    /// record: see [`Self::is_well_formed`].
    pub principals: Option<RecordPrincipals>,
    /// The decision recorded.
    pub status: RecordStatus,
    /// Why the action was refused, when it was.
    ///
    /// `Some` for every [`RecordStatus::Blocked`] and [`RecordStatus::Halted`]
    /// record the engine writes, so a refusal is never recorded without its
    /// reason. It is part of the canonical pre-image, so it cannot be edited
    /// after the fact without breaking the chain.
    pub block_reason: Option<BlockReason>,
    /// The halt-latch state observed when the decision was taken.
    pub killswitch: KillswitchState,
    /// When the decision was taken.
    pub at: UnixSeconds,
}

impl RecordDraft {
    /// Drafts the record of a halt no person engaged: the latch engaged in
    /// the state `killswitch`, written at `at`. It names nobody.
    ///
    /// A draft of an armed latch is not well formed: a halt record carries
    /// the halt.
    #[must_use]
    pub const fn of_halt(killswitch: KillswitchState, at: UnixSeconds) -> Self {
        Self {
            subject: None,
            principals: None,
            status: RecordStatus::HaltEngaged,
            block_reason: None,
            killswitch,
            at,
        }
    }

    /// Drafts the record of a halt a person engaged: the latch engaged in the
    /// state `killswitch`, written at `at`. It names that person as the
    /// maker, at the risk level the halt stands at, and no checker.
    ///
    /// A draft whose level is not the one of `killswitch`, or that names a
    /// checker, is not well formed.
    #[must_use]
    pub const fn of_halt_by(
        killswitch: KillswitchState,
        operator: RecordPrincipals,
        at: UnixSeconds,
    ) -> Self {
        Self {
            subject: None,
            principals: Some(operator),
            status: RecordStatus::HaltEngaged,
            block_reason: None,
            killswitch,
            at,
        }
    }

    /// Drafts the record of the release of a halt, written at `at`. It names
    /// the releasing person as the maker, the checkers who approved, and the
    /// risk level the halt stood at.
    #[must_use]
    pub const fn of_release(principals: RecordPrincipals, at: UnixSeconds) -> Self {
        Self {
            subject: None,
            principals: Some(principals),
            status: RecordStatus::HaltReleased,
            block_reason: None,
            killswitch: KillswitchState::Armed,
            at,
        }
    }

    /// Returns whether the status and the other fields belong together.
    ///
    /// A record that decides an action names the action and the maker of its
    /// proposal. It names checkers exactly when it states a vote: a rejection,
    /// or the approval of an action whose level demands a checker. A record
    /// of the halt latch names no action and no refusal reason, and carries
    /// the latch state its status states: engaged for the halt, and armed
    /// for the release, which names the releasing person. The record of a
    /// halt names the person who engaged it, at the level the halt stands at
    /// and with no checker, or it names nobody.
    ///
    /// Where checkers are named they are as many as the level demands, the
    /// maker is none of them and two of them are two principals.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let unnamed = self.subject.is_none() && self.block_reason.is_none();
        match self.status {
            RecordStatus::HaltEngaged => {
                let engaged_by = match self.principals {
                    Some(operator) => operator.is_halt_of(self.killswitch),
                    None => true,
                };
                unnamed && self.killswitch.is_engaged() && engaged_by
            }
            RecordStatus::HaltReleased => {
                unnamed
                    && !self.killswitch.is_engaged()
                    && self.principals.is_some_and(|named| named.is_release())
            }
            decision => {
                self.subject.is_some()
                    && self
                        .principals
                        .is_some_and(|named| named.fits_decision(decision))
            }
        }
    }
}

/// One sealed audit-record body, including its chain position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordBody {
    sequence: Sequence,
    previous: Digest32,
    algorithm: HashAlgorithm,
    draft: RecordDraft,
}

impl RecordBody {
    /// Places a draft at a chain position.
    #[must_use]
    pub const fn from_parts(
        sequence: Sequence,
        previous: Digest32,
        algorithm: HashAlgorithm,
        draft: RecordDraft,
    ) -> Self {
        Self {
            sequence,
            previous,
            algorithm,
            draft,
        }
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Returns the predecessor link.
    #[must_use]
    pub const fn previous(&self) -> Digest32 {
        self.previous
    }

    /// Returns the algorithm named by the record.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Returns the caller-supplied fields.
    #[must_use]
    pub const fn draft(&self) -> &RecordDraft {
        &self.draft
    }

    /// Returns a copy of this body carrying a different status.
    ///
    /// This is the storage round-trip path: it lets a caller restate a record
    /// read back from durable storage, and it lets a test forge one.
    #[must_use]
    pub const fn with_status(&self, status: RecordStatus) -> Self {
        let mut draft = self.draft;
        draft.status = status;
        Self { draft, ..*self }
    }

    /// Builds the canonical, domain-separated, length-prefixed pre-image.
    ///
    /// # Errors
    ///
    /// Returns [`PreimageError::Shape`] for a draft whose status and fields do
    /// not belong together ([`RecordDraft::is_well_formed`]), and
    /// [`PreimageError::Overflow`] when the encoding would exceed the fixed
    /// buffer. The encoding never truncates.
    pub fn canonical_preimage(&self) -> Result<CanonicalBuffer, PreimageError> {
        if !self.draft.is_well_formed() {
            return Err(PreimageError::Shape);
        }
        let mut buffer = CanonicalBuffer::new();
        buffer.write_tag(AUDIT_DOMAIN)?;
        buffer.write_framed(CONTRACT_VERSION.as_bytes())?;
        buffer.write_u8(self.algorithm.tag())?;
        buffer.write_u64(self.sequence.get())?;
        buffer.write_digest(&self.previous)?;
        buffer.write_u64(self.draft.at.get())?;
        buffer.write_u8(self.draft.status.tag())?;
        buffer.write_u8(action_tag(self.draft.subject.as_ref()))?;
        write_block_reason(&mut buffer, self.draft.block_reason)?;
        write_killswitch(&mut buffer, self.draft.killswitch)?;
        write_names(&mut buffer, self.draft.subject.as_ref())?;
        write_principals(&mut buffer, self.draft.principals.as_ref())?;
        Ok(buffer)
    }

    /// Computes the digest of this body under `H`.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the pre-image overflows or the hash
    /// backend returns an output of the wrong width.
    pub fn digest<H: LedgerHasher>(&self) -> Result<Digest32, LedgerError> {
        let preimage = self.canonical_preimage()?;
        Ok(H::digest(preimage.as_slice())?)
    }
}

/// Returns the action tag of a record: zero, which no action has, for a
/// record that decides none.
const fn action_tag(subject: Option<&RecordSubject>) -> u8 {
    match subject {
        Some(subject) => subject.action_type.tag(),
        None => 0,
    }
}

/// Encodes the intent and the agent a record names, each behind its length.
///
/// A record that names none writes two empty fields, which no identifier
/// encodes to, so the layout is one for every record.
fn write_names(
    buffer: &mut CanonicalBuffer,
    subject: Option<&RecordSubject>,
) -> Result<(), PreimageError> {
    if let Some(subject) = subject {
        buffer.write_framed(subject.intent_id.as_bytes())?;
        buffer.write_framed(subject.agent.as_bytes())
    } else {
        buffer.write_framed(&[])?;
        buffer.write_framed(&[])
    }
}

/// Encodes who a record names: the tag of the risk level, then the maker and
/// the two checkers, each behind its length.
///
/// A record that names nobody writes a zero level, which no level has, and a
/// place a record leaves open is an empty field, which no identity encodes
/// to. The layout is one for every record.
fn write_principals(
    buffer: &mut CanonicalBuffer,
    principals: Option<&RecordPrincipals>,
) -> Result<(), PreimageError> {
    let Some(named) = principals else {
        buffer.write_u8(0)?;
        buffer.write_framed(&[])?;
        buffer.write_framed(&[])?;
        return buffer.write_framed(&[]);
    };
    buffer.write_u8(named.level.tag())?;
    buffer.write_framed(named.maker.as_bytes())?;
    for checker in named.checkers() {
        match checker {
            Some(checker) => buffer.write_framed(checker.as_bytes())?,
            None => buffer.write_framed(&[])?,
        }
    }
    Ok(())
}

/// Encodes the recorded refusal reason, if any, into the pre-image.
///
/// The absent case writes two zero bytes rather than nothing, so a record with
/// no reason and a record with a reason never share a pre-image length.
fn write_block_reason(
    buffer: &mut CanonicalBuffer,
    reason: Option<BlockReason>,
) -> Result<(), PreimageError> {
    match reason {
        None => {
            buffer.write_u8(0)?;
            buffer.write_u8(0)
        }
        Some(reason) => {
            buffer.write_u8(reason.tag())?;
            buffer.write_u8(reason.halt_tag())
        }
    }
}

/// Encodes the observed halt-latch state into the pre-image.
fn write_killswitch(
    buffer: &mut CanonicalBuffer,
    state: KillswitchState,
) -> Result<(), PreimageError> {
    match state {
        KillswitchState::Armed => {
            buffer.write_u8(0)?;
            buffer.write_u64(0)?;
            buffer.write_u8(0)?;
            buffer.write_u8(0)
        }
        KillswitchState::Engaged { at, reason, level } => {
            buffer.write_u8(1)?;
            buffer.write_u64(at.get())?;
            buffer.write_u8(reason.tag())?;
            buffer.write_u8(level.tag())
        }
    }
}

/// One sealed audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRecord {
    body: RecordBody,
    signature: Signature,
    digest: Digest32,
}

impl AuditRecord {
    /// Assembles a record from stored parts.
    ///
    /// The digest is carried rather than recomputed, so a chain re-walk can
    /// detect a stored record whose content no longer matches its digest.
    #[must_use]
    pub const fn from_parts(body: RecordBody, signature: Signature, digest: Digest32) -> Self {
        Self {
            body,
            signature,
            digest,
        }
    }

    /// Returns the record body.
    #[must_use]
    pub const fn body(&self) -> &RecordBody {
        &self.body
    }

    /// Returns the detached signature.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the stored digest.
    #[must_use]
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }
}

/// Receives sealed records. Milestone M02 ships [`InMemorySink`] only.
pub trait LedgerSink {
    /// Accepts one sealed record.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError`] when the record cannot be accepted within
    /// `deadline`.
    fn append_record(
        &mut self,
        record: &AuditRecord,
        deadline: IoDeadline,
    ) -> Result<(), SinkError>;

    /// Flushes anything the sink holds.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError`] when the flush cannot complete within `deadline`.
    fn sync(&mut self, deadline: IoDeadline) -> Result<(), SinkError>;
}

/// A sink that accepts nothing.
///
/// This is the sink dual of [`SignerBinding::Unbound`]: the durable sink is M14
/// work, so "no sink bound" is a typed hole that fails closed rather than a
/// silent drop. It is also the only producer of [`SinkError::Unavailable`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnavailableSink;

impl UnavailableSink {
    /// Builds the unavailable sink.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LedgerSink for UnavailableSink {
    fn append_record(
        &mut self,
        _record: &AuditRecord,
        _deadline: IoDeadline,
    ) -> Result<(), SinkError> {
        Err(SinkError::Unavailable)
    }

    fn sync(&mut self, _deadline: IoDeadline) -> Result<(), SinkError> {
        Err(SinkError::Unavailable)
    }
}

/// A bounded in-memory sink. No file path, no daemon, no network.
///
/// The record list is reserved to `bound` at construction and every push is
/// refused at that bound, so accepting a record never reallocates. The sink
/// also declares a service time: a caller offering a shorter [`IoDeadline`] is
/// refused with [`SinkError::WouldBlock`] instead of being allowed to block
/// past its own deadline, which is the HISS-02 obligation made checkable
/// without a timer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemorySink {
    accepted: Vec<AuditRecord>,
    bound: usize,
    service: IoDeadline,
    syncs: usize,
}

impl InMemorySink {
    /// Builds a sink with an explicit scalar record bound and the default
    /// service time of [`DEFAULT_SINK_SERVICE_MILLIS`] milliseconds.
    #[must_use]
    pub fn with_bound(bound: usize) -> Self {
        Self::with_service_time(bound, default_service_time())
    }

    /// Builds a sink with an explicit record bound and service time.
    #[must_use]
    pub fn with_service_time(bound: usize, service: IoDeadline) -> Self {
        Self {
            accepted: Vec::with_capacity(bound),
            bound,
            service,
            syncs: 0,
        }
    }

    /// Returns the records the sink accepted.
    #[must_use]
    pub fn accepted(&self) -> &[AuditRecord] {
        &self.accepted
    }

    /// Returns the scalar record bound.
    #[must_use]
    pub const fn bound(&self) -> usize {
        self.bound
    }

    /// Returns the capacity reserved at construction.
    ///
    /// HISS-03 evidence: this value must not change while the sink is in use.
    #[must_use]
    pub fn reserved(&self) -> usize {
        self.accepted.capacity()
    }

    /// Returns the service time the sink demands of a caller's deadline.
    #[must_use]
    pub const fn service_time(&self) -> IoDeadline {
        self.service
    }

    /// Returns how many times the sink was flushed.
    #[must_use]
    pub const fn syncs(&self) -> usize {
        self.syncs
    }

    /// Refuses a deadline shorter than the declared service time.
    const fn admit(&self, deadline: IoDeadline) -> Result<(), SinkError> {
        if deadline.millis() < self.service.millis() {
            return Err(SinkError::WouldBlock {
                needed: self.service.millis(),
                offered: deadline.millis(),
            });
        }
        Ok(())
    }
}

/// Returns the default sink service time, one millisecond.
fn default_service_time() -> IoDeadline {
    IoDeadline::try_from_millis(DEFAULT_SINK_SERVICE_MILLIS)
        .unwrap_or(IoDeadline::from_millis(NonZeroU32::MIN))
}

impl Default for InMemorySink {
    fn default() -> Self {
        Self::with_bound(MAX_LEDGER_RECORDS)
    }
}

impl LedgerSink for InMemorySink {
    fn append_record(
        &mut self,
        record: &AuditRecord,
        deadline: IoDeadline,
    ) -> Result<(), SinkError> {
        self.admit(deadline)?;
        if self.accepted.len() >= self.bound {
            return Err(SinkError::Full { max: self.bound });
        }
        self.accepted.push(*record);
        Ok(())
    }

    fn sync(&mut self, deadline: IoDeadline) -> Result<(), SinkError> {
        self.admit(deadline)?;
        self.syncs = self.syncs.saturating_add(1);
        Ok(())
    }
}

/// A hash-linked audit ledger over a hasher, a signer binding and a sink.
///
/// Dispatch is static: there is no `dyn` and no vtable on the audit path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLedger<H: LedgerHasher, S: RecordSigner, K: LedgerSink> {
    records: Vec<AuditRecord>,
    origin: Position,
    tip: Position,
    bound: usize,
    signer: SignerBinding<S>,
    sink: K,
    io_deadline: IoDeadline,
    hasher: core::marker::PhantomData<H>,
}

/// The SHA-256 ledger, the only instantiation milestone M02 ships.
pub type Sha256Ledger<S, K> = AuditLedger<Sha256Hasher, S, K>;

impl<H: LedgerHasher, S: RecordSigner, K: LedgerSink> AuditLedger<H, S, K> {
    /// Builds a ledger with the default record bound.
    #[must_use]
    pub fn new(signer: SignerBinding<S>, sink: K, io_deadline: IoDeadline) -> Self {
        Self::with_bound(signer, sink, io_deadline, MAX_LEDGER_RECORDS)
    }

    /// Builds a ledger with an explicit scalar record bound.
    ///
    /// The record list is reserved to `bound` here, once, so that
    /// [`Self::append`] never reallocates. The name is `with_bound`, not
    /// `with_capacity`: the std convention is that `with_capacity` reserves
    /// without capping, and this argument does both.
    #[must_use]
    pub fn with_bound(
        signer: SignerBinding<S>,
        sink: K,
        io_deadline: IoDeadline,
        bound: usize,
    ) -> Self {
        Self::at_position(signer, sink, io_deadline, bound, Position::GENESIS)
    }

    /// Builds a ledger that continues the chain whose last stored record
    /// `anchor` names, with an explicit scalar record bound.
    ///
    /// The first record sealed links to the anchor's head digest, carries the
    /// next sequence number and may not precede the head record in time. The
    /// window starts empty: [`Self::verify`] walks from the anchor, and the
    /// records before it are the store's to verify.
    #[must_use]
    pub fn continue_from(
        signer: SignerBinding<S>,
        sink: K,
        io_deadline: IoDeadline,
        bound: usize,
        anchor: &ChainAnchor,
    ) -> Self {
        Self::at_position(signer, sink, io_deadline, bound, Position::after(anchor))
    }

    /// Builds a ledger with an empty window at `position`.
    fn at_position(
        signer: SignerBinding<S>,
        sink: K,
        io_deadline: IoDeadline,
        bound: usize,
        position: Position,
    ) -> Self {
        Self {
            records: Vec::with_capacity(bound),
            origin: position,
            tip: position,
            bound,
            signer,
            sink,
            io_deadline,
            hasher: core::marker::PhantomData,
        }
    }

    /// Returns the scalar record bound.
    #[must_use]
    pub const fn bound(&self) -> usize {
        self.bound
    }

    /// Returns the capacity reserved at construction.
    ///
    /// HISS-03 evidence: this value must not change while the ledger is in use.
    #[must_use]
    pub fn reserved(&self) -> usize {
        self.records.capacity()
    }

    /// Returns the digest of the most recent record, or the genesis link.
    #[must_use]
    pub const fn head(&self) -> Digest32 {
        self.tip.previous
    }

    /// Returns the sequence number the next record will carry.
    #[must_use]
    pub const fn next_sequence(&self) -> Sequence {
        self.tip.expected
    }

    /// Returns how many more records the window takes before
    /// [`Self::append`] refuses with [`LedgerError::LengthBoundExceeded`].
    ///
    /// A caller that rotates while this is above zero is never refused at the
    /// bound.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bound.saturating_sub(self.records.len())
    }

    /// Returns the number of records held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` when the ledger holds no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the records held.
    #[must_use]
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Returns the sink.
    #[must_use]
    pub const fn sink(&self) -> &K {
        &self.sink
    }

    /// Seals `draft` and links it onto the chain.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the record bound is reached, the timestamp
    /// precedes the previous record, the pre-image overflows, the hash backend
    /// misbehaves, no signer is bound, or the sink refuses the record. Nothing
    /// is committed unless every step succeeds.
    pub fn append(&mut self, draft: RecordDraft) -> Result<Digest32, LedgerError> {
        if self.records.len() >= self.bound {
            return Err(LedgerError::LengthBoundExceeded { max: self.bound });
        }
        if let Some(last) = self.tip.last_at
            && draft.at < last
        {
            return Err(LedgerError::NonMonotonicTimestamp {
                last: last.get(),
                observed: draft.at.get(),
            });
        }
        let body =
            RecordBody::from_parts(self.tip.expected, self.tip.previous, H::ALGORITHM, draft);
        let digest = body.digest::<H>()?;
        let signature = self.signer.sign(&digest)?;
        let record = AuditRecord::from_parts(body, signature, digest);
        self.sink.append_record(&record, self.io_deadline)?;
        self.commit(&record, draft.at);
        Ok(digest)
    }

    /// Commits a sealed record. Called only after every fallible step passed.
    fn commit(&mut self, record: &AuditRecord, at: UnixSeconds) {
        self.tip = Position {
            previous: record.digest(),
            expected: successor(record.body().sequence()),
            last_at: Some(at),
        };
        self.records.push(*record);
    }

    /// Re-walks the records in the window, from the position the window
    /// starts at: genesis, the anchor the ledger continued from, or the head
    /// at the last rotation.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::LengthBoundExceeded`] when the window is longer
    /// than the bound, and otherwise the first broken link.
    pub fn verify(&self) -> Result<Digest32, LedgerError> {
        walk::<H>(self.origin, &self.records, self.bound)
    }

    /// Drops the window, so that [`Self::remaining`] is the bound again.
    ///
    /// The window is re-walked first and the sink is flushed second; only when
    /// both pass are the records dropped, and the window then starts at the
    /// head. Nothing is reallocated, and the chain position does not move: the
    /// next record links onto the last one dropped. Returns the number of
    /// records dropped.
    ///
    /// # Errors
    ///
    /// Returns the first broken link of the window, or [`LedgerError::Sink`]
    /// when the sink cannot flush within the deadline. The window is kept in
    /// both cases.
    pub fn rotate(&mut self) -> Result<usize, LedgerError> {
        self.verify()?;
        self.sink.sync(self.io_deadline)?;
        let dropped = self.records.len();
        self.records.clear();
        self.origin = self.tip;
        Ok(dropped)
    }
}

/// Verifies one link of a chain against the state that precedes it.
fn verify_link<H: LedgerHasher>(
    previous: Digest32,
    expected: Sequence,
    record: &AuditRecord,
) -> Result<(), LedgerError> {
    let body = record.body();
    if body.algorithm() != H::ALGORITHM {
        return Err(LedgerError::AlgorithmMismatch {
            expected: H::ALGORITHM,
            found: body.algorithm(),
        });
    }
    if body.sequence() != expected {
        return Err(LedgerError::SequenceGap {
            expected: expected.get(),
            found: body.sequence().get(),
        });
    }
    if body.previous() != previous {
        return Err(LedgerError::PreviousHashMismatch {
            at: body.sequence().get(),
        });
    }
    if body.digest::<H>()? != record.digest() {
        return Err(LedgerError::DigestMismatch {
            at: body.sequence().get(),
        });
    }
    Ok(())
}

/// Re-walks `records` under the default bound [`MAX_LEDGER_RECORDS`].
///
/// An empty chain verifies as [`Digest32::GENESIS`].
///
/// # Errors
///
/// Returns [`LedgerError`] on the first broken link.
pub fn verify_chain<H: LedgerHasher>(records: &[AuditRecord]) -> Result<Digest32, LedgerError> {
    verify_chain_bounded::<H>(records, MAX_LEDGER_RECORDS)
}

/// Re-walks `records` under an explicit scalar bound.
///
/// The walk is iterative; the bound is checked before the walk starts, so an
/// oversized chain is refused without being traversed.
///
/// # Errors
///
/// Returns [`LedgerError::LengthBoundExceeded`] when the chain is longer than
/// `max`, and otherwise the first broken link.
pub fn verify_chain_bounded<H: LedgerHasher>(
    records: &[AuditRecord],
    max: usize,
) -> Result<Digest32, LedgerError> {
    walk::<H>(Position::GENESIS, records, max)
}

/// Re-walks `records` as the part of a chain that follows `anchor`, under an
/// explicit scalar bound.
///
/// This is the walk across a continuation: the first record must link to the
/// anchor's head digest, carry the next sequence number and not precede the
/// head record in time. No record after the anchor verifies as the anchor's
/// head digest.
///
/// # Errors
///
/// Returns [`LedgerError::LengthBoundExceeded`] when there are more than `max`
/// records, and otherwise the first broken link.
pub fn verify_continuation<H: LedgerHasher>(
    anchor: &ChainAnchor,
    records: &[AuditRecord],
    max: usize,
) -> Result<Digest32, LedgerError> {
    walk::<H>(Position::after(anchor), records, max)
}

/// Walks `records` from `from` and returns the digest the chain then ends on.
///
/// The walk is iterative; the bound is checked before it starts.
fn walk<H: LedgerHasher>(
    from: Position,
    records: &[AuditRecord],
    max: usize,
) -> Result<Digest32, LedgerError> {
    if records.len() > max {
        return Err(LedgerError::LengthBoundExceeded { max });
    }
    let mut at = from;
    for record in records.iter().take(max) {
        verify_link::<H>(at.previous, at.expected, record)?;
        let observed = record.body().draft().at;
        if let Some(last) = at.last_at
            && observed < last
        {
            return Err(LedgerError::NonMonotonicTimestamp {
                last: last.get(),
                observed: observed.get(),
            });
        }
        at = Position {
            previous: record.digest(),
            expected: at
                .expected
                .next()
                .ok_or(LedgerError::LengthBoundExceeded { max })?,
            last_at: Some(observed),
        };
    }
    Ok(at.previous)
}
