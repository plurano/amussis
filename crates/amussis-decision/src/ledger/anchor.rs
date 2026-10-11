// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The point a chain continues from.
//!
//! A ledger holds a bounded window of records in memory; the chain itself is
//! as long as the store behind the sink. A [`ChainAnchor`] names the last
//! stored record of a chain, so that a new ledger value can link its first
//! record onto it and the two stay one chain.
//!
//! An anchor is never built from loose numbers. Its only two constructors take
//! the head record, or the stored bytes of the head record and its digest, and
//! both recompute the digest: a head whose content no longer hashes to the
//! digest it is filed under is refused. The fields are read from the same
//! bytes the digest was taken over, so the sequence number, the time and the
//! halt-latch state an anchor carries are exactly those the chain commits to.
//!
//! What an anchor cannot prove is that the record is the last one the store
//! holds: that is the caller's statement. A wrong one does not go unseen. A
//! continuation from any record but the head leaves two records with the same
//! sequence number in the store, and the walk over the stored chain
//! ([`verify_continuation`](crate::verify_continuation),
//! [`verify_chain_bounded`](crate::verify_chain_bounded)) refuses it.
//!
//! # The halt latch across a continuation
//!
//! Every record carries the halt-latch state observed when it was written. An
//! anchor carries the state of its head record, and an engine that continues
//! from it starts in that state: a chain that ends halted continues halted.
//! An anchor has no release. The one release is a call on the engine that
//! continued the chain,
//! [`DecisionEngine::release_halt`](crate::DecisionEngine::release_halt),
//! and it is a record of the chain.

use crate::killswitch::{HaltReason, KillswitchState};
use crate::ledger::hash::{Digest32, HashError, LedgerHasher, PreimageError};
use crate::ledger::{AUDIT_DOMAIN, AuditRecord, Sequence};
use crate::risk::RiskLevel;
use crate::time::UnixSeconds;
use crate::{CONTRACT_VERSION, DIGEST_LEN, MAX_PREIMAGE_BYTES};

/// Width of the status tag, the action tag and the two refusal-reason bytes,
/// which an anchor steps over.
const DECISION_TAG_BYTES: usize = 4;

/// Reasons a head is refused as the point to continue a chain from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorError {
    /// The content does not hash to the digest the head is filed under.
    #[error("the head record does not hash to its digest")]
    DigestMismatch,
    /// The bytes are not a canonical audit pre-image of this contract version
    /// and hash algorithm, or carry something after the last field.
    #[error("the head bytes are not a canonical audit pre-image of this contract")]
    Malformed,
    /// The canonical pre-image of the head record could not be built.
    #[error("canonical pre-image: {0}")]
    Preimage(#[from] PreimageError),
    /// The digest could not be produced.
    #[error("digest: {0}")]
    Hash(#[from] HashError),
}

/// The verified last record of a chain, as the point the chain continues from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchor {
    head: Digest32,
    sequence: Sequence,
    at: UnixSeconds,
    killswitch: KillswitchState,
}

impl ChainAnchor {
    /// Builds the anchor of a chain whose last stored record is `record`.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::DigestMismatch`] when the record's content does
    /// not hash to its stored digest, and [`AnchorError::Malformed`] when the
    /// record names another hash algorithm than `H`.
    pub fn from_record<H: LedgerHasher>(record: &AuditRecord) -> Result<Self, AnchorError> {
        let preimage = record.body().canonical_preimage()?;
        Self::from_preimage::<H>(preimage.as_slice(), &record.digest())
    }

    /// Builds the anchor of a chain from the stored bytes of its last record:
    /// the canonical pre-image and the digest it is filed under.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::DigestMismatch`] when `preimage` does not hash
    /// to `head` under `H`, and [`AnchorError::Malformed`] when the bytes are
    /// longer than [`MAX_PREIMAGE_BYTES`] or are not a canonical audit
    /// pre-image of this contract version and of `H`.
    pub fn from_preimage<H: LedgerHasher>(
        preimage: &[u8],
        head: &Digest32,
    ) -> Result<Self, AnchorError> {
        if preimage.len() > MAX_PREIMAGE_BYTES {
            return Err(AnchorError::Malformed);
        }
        if H::digest(preimage)? != *head {
            return Err(AnchorError::DigestMismatch);
        }
        read_anchor::<H>(preimage, *head).ok_or(AnchorError::Malformed)
    }

    /// Returns the digest of the head record.
    #[must_use]
    pub const fn head(&self) -> Digest32 {
        self.head
    }

    /// Returns the sequence number of the head record.
    #[must_use]
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Returns the time of the head record.
    #[must_use]
    pub const fn at(&self) -> UnixSeconds {
        self.at
    }

    /// Returns the halt-latch state a continuation starts in.
    #[must_use]
    pub const fn killswitch(&self) -> KillswitchState {
        self.killswitch
    }
}

/// Reads a canonical pre-image front to back. Every read is bounded by the
/// bytes left, so a short or over-long field ends the read.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Takes the next `len` bytes.
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.rest.split_at_checked(len)?;
        self.rest = rest;
        Some(taken)
    }

    /// Takes one byte.
    fn byte(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    /// Takes a big-endian `u64`.
    fn word(&mut self) -> Option<u64> {
        let raw: [u8; 8] = self.take(8)?.try_into().ok()?;
        Some(u64::from_be_bytes(raw))
    }

    /// Takes a field behind its big-endian `u32` length prefix.
    fn framed(&mut self) -> Option<&'a [u8]> {
        let raw: [u8; 4] = self.take(4)?.try_into().ok()?;
        self.take(usize::try_from(u32::from_be_bytes(raw)).ok()?)
    }
}

/// Reads the fields of an anchor out of the canonical pre-image of its head
/// record, in the order `RecordBody::canonical_preimage` writes them.
fn read_anchor<H: LedgerHasher>(preimage: &[u8], head: Digest32) -> Option<ChainAnchor> {
    let mut reader = Reader { rest: preimage };
    let domain = reader.take(AUDIT_DOMAIN.len())?;
    let contract = reader.framed()?;
    let algorithm = reader.byte()?;
    let sequence = reader.word()?;
    let _previous = reader.take(DIGEST_LEN)?;
    let at = reader.word()?;
    let _decision = reader.take(DECISION_TAG_BYTES)?;
    let killswitch = read_killswitch(&mut reader)?;
    let _intent = reader.framed()?;
    let _agent = reader.framed()?;
    let canonical = domain == AUDIT_DOMAIN
        && contract == CONTRACT_VERSION.as_bytes()
        && algorithm == H::ALGORITHM.tag()
        && sequence >= Sequence::FIRST.get()
        && reader.rest.is_empty();
    canonical.then_some(ChainAnchor {
        head,
        sequence: Sequence::new(sequence),
        at: UnixSeconds::new(at),
        killswitch,
    })
}

/// Reads the halt-latch state. An armed latch is written with a zero time, a
/// zero reason and a zero level; anything else in those bytes is not
/// canonical.
fn read_killswitch(reader: &mut Reader<'_>) -> Option<KillswitchState> {
    let engaged = reader.byte()?;
    let at = reader.word()?;
    let reason = reader.byte()?;
    let level = reader.byte()?;
    match engaged {
        0 => (at == 0 && reason == 0 && level == 0).then_some(KillswitchState::Armed),
        1 => Some(KillswitchState::Engaged {
            at: UnixSeconds::new(at),
            reason: HaltReason::from_tag(reason)?,
            level: RiskLevel::from_tag(level)?,
        }),
        _ => None,
    }
}
