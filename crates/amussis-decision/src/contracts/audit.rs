// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The signed audit record P06 Justitia hands to P16 Athena.
//!
//! # Where the fields come from
//!
//! | Field | Source |
//! | :-- | :-- |
//! | `event-id`, `recorded-at`, `previous`, `action-type`, `actor-id`, `oversight-signature`, `digest` | export-015 `fcbe2caed363`, the Article 12/19 `JustitiaAuditRecord` schema |
//! | `sequence`, `correlation-id`, `status` | export-031 `5ff683328148`, `AuditLogEntry` |
//! | `algorithm` | decision D02: SHA-256 behind a trait, MD5 excluded |
//! | `edge` | export-062 `1ce919ed54bb`, edge `AUDIT_RECONSTRUCTIVE_CANDIDATE` |
//!
//! # Two disagreements the schema resolves
//!
//! * The reference daemon hashes its chain with a digest the project excludes,
//!   while the same subsystem's own schema names SHA-256. Decision D02 settles
//!   it: [`HashAlgorithm`] admits SHA-256 and nothing else, so a record naming
//!   any other algorithm does not decode.
//! * The imported schema's status vocabulary has three values; the crate's
//!   ledger carries five, because a refusal by the engine and a refusal by the
//!   halt latch are recorded distinctly. The superset travels on the wire.
//!
//! # The genesis rule
//!
//! An all-zero previous link means "this is the head of the chain". It is
//! admissible at sequence 1 and nowhere else, and sequence 1 is admissible with
//! nothing else, so a forged record cannot claim to start a second chain in the
//! middle of the first.
//!
//! No transport and no signing are implemented. The signature field is a field
//! encoding: this crate neither produces nor verifies one, and TPM2 sealing is
//! milestone M20 work.

use crate::contracts::encoding::OversightSignature;
use crate::contracts::graph::EdgeId;
use crate::contracts::{
    ContractError, Correlation, PayloadBuffer, SchemaId, decode_text, encode_into,
};
use crate::identity::{AgentId, EventId, Identity};
use crate::ledger::hash::{Digest32, HashAlgorithm};
use crate::ledger::{RecordStatus, Sequence};
use crate::outcome::BlockReason;
use crate::risk::ActionType;
use crate::time::UnixSeconds;

/// The EU Product Liability Directive's stated effective date.
///
/// 9 December 2026, 00:00:00 UTC. It is recorded here because the P06 report
/// names it as the deadline the subsystem's liability mitigation targets
/// (export-015 `fcbe2caed363`). It is an **external deadline the roadmap
/// tracks**, not a gate this crate enforces: nothing in this module compares a
/// record against it, and no behaviour changes when it passes.
pub const PLD_EFFECTIVE_AT: UnixSeconds = UnixSeconds::new(1_796_774_400);

/// The contract versions of the signed audit record this build admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum AuditRecordVersion {
    /// Version 1, tagged `aegis.p06-p16.audit-record.v1`.
    #[serde(rename = "aegis.p06-p16.audit-record.v1")]
    V1,
}

/// One sealed, chain-linked audit record on its way to P16 Athena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SignedAuditRecord {
    /// The contract version this payload claims.
    pub schema: AuditRecordVersion,
    /// The subsystem-graph edge the payload travels on.
    pub edge: EdgeId,
    /// The identifier threading the proposal, its request and this record.
    pub correlation_id: Identity,
    /// Stable identifier of this audit event.
    pub event_id: EventId,
    /// The record's position in the chain, starting at one.
    pub sequence: Sequence,
    /// The hash algorithm the chain is built with (decision D02).
    pub algorithm: HashAlgorithm,
    /// The predecessor link; all zero for the head of the chain.
    pub previous: Digest32,
    /// This record's own digest.
    pub digest: Digest32,
    /// What the recorded action does.
    pub action_type: ActionType,
    /// The decision recorded.
    pub status: RecordStatus,
    /// Why the action was refused, for a refusal and only for a refusal.
    #[serde(default)]
    pub block_reason: Option<BlockReason>,
    /// The agent the record is about.
    pub actor_id: AgentId,
    /// When the decision was taken.
    pub recorded_at: UnixSeconds,
    /// The oversight seal over this record. A record without one is refused.
    #[serde(default)]
    pub oversight_signature: Option<OversightSignature>,
}

impl SignedAuditRecord {
    /// The contract this type instantiates.
    pub const SCHEMA: SchemaId = SchemaId::SignedAuditRecord;

    /// The edge the record travels on, kept from the graph of record.
    pub const EDGE: EdgeId = EdgeId::AuditReconstructiveCandidate;

    /// Returns what a refusal of this payload is about.
    #[must_use]
    pub const fn correlation(&self) -> Correlation {
        Correlation::new(Self::SCHEMA, Some(self.correlation_id))
    }

    /// Returns `true` when this record claims to be the head of a chain.
    #[must_use]
    pub fn is_chain_head(&self) -> bool {
        self.sequence == Sequence::FIRST
    }

    /// Checks the invariants the field types cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::Malformed`] for a payload naming another edge,
    /// [`ContractError::MissingGenesisLink`] and
    /// [`ContractError::GenesisLinkOutOfPlace`] for a link that does not match
    /// the record's chain position, [`ContractError::RefusalWithoutReason`] and
    /// [`ContractError::ReasonWithoutRefusal`] for a reason that does not match
    /// the recorded decision, and [`ContractError::Unsigned`] for a record that
    /// carries no seal or an empty one.
    pub fn validate(&self) -> Result<(), ContractError> {
        let correlation = self.correlation();
        if self.edge != Self::EDGE {
            return Err(ContractError::Malformed { correlation });
        }
        self.validate_link(correlation)?;
        self.validate_reason(correlation)?;
        match self.oversight_signature {
            Some(seal) if !seal.is_empty() => Ok(()),
            _ => Err(ContractError::Unsigned { correlation }),
        }
    }

    /// Checks the predecessor link against the record's chain position.
    fn validate_link(&self, correlation: Correlation) -> Result<(), ContractError> {
        match (self.is_chain_head(), self.previous.is_genesis()) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(ContractError::MissingGenesisLink { correlation }),
            (false, true) => Err(ContractError::GenesisLinkOutOfPlace {
                correlation,
                sequence: self.sequence.get(),
            }),
        }
    }

    /// Checks that a refusal reason is recorded exactly for a refusal.
    fn validate_reason(&self, correlation: Correlation) -> Result<(), ContractError> {
        let refused = matches!(self.status, RecordStatus::Blocked | RecordStatus::Halted);
        match (refused, self.block_reason.is_some()) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(ContractError::RefusalWithoutReason { correlation }),
            (false, true) => Err(ContractError::ReasonWithoutRefusal { correlation }),
        }
    }

    /// Encodes a validated record into `buffer`.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::validate`], and returns
    /// [`ContractError::PayloadTooLong`] when the payload does not fit.
    pub fn encode_into<'b>(&self, buffer: &'b mut PayloadBuffer) -> Result<&'b str, ContractError> {
        self.validate()?;
        encode_into(self, self.correlation(), buffer)
    }

    /// Decodes and validates one audit-record payload.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::UnknownVersion`] for a payload naming another
    /// contract version, [`ContractError::PayloadTooLong`] past the byte bound,
    /// and otherwise whatever [`Self::validate`] refuses.
    pub fn decode(text: &str) -> Result<Self, ContractError> {
        let decoded: Self = decode_text(Self::SCHEMA, text)?;
        decoded.validate()?;
        Ok(decoded)
    }
}
