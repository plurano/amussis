// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The action proposal P09 Minerva sends to P06 Justitia (decision D03).
//!
//! # Where the fields come from
//!
//! | Field | Source |
//! | :-- | :-- |
//! | `correlation-id`, `agent-id`, `action-type`, `target`, `payload-hash`, `proposed-at` | export-031 `5ff683328148`, `ActionIntent` |
//! | `maker`, `declared-tier`, `oversight` | export-047 `971948673346`, `DecisionRequest` and the Annex III checker rule |
//! | `edge`, `direction` | export-062 `1ce919ed54bb`, edge `ACTION_GATE_INTERCEPT`, reinterpreted by D03 |
//! | `signature` | export-015 `fcbe2caed363`, the oversight signature on an intercepted action |
//!
//! # What decision D03 fixes here
//!
//! The direction is a field of the payload and a constant of the type. The
//! graph of record draws the action gate from P06 to P09; the architecture
//! document draws it the other way. D03 settles it as propose/intercept:
//! Minerva proposes, Justitia intercepts and decides, and the graph's edge
//! identifier is kept. Because [`GateDirection`] admits one variant only, a
//! payload asserting the opposite direction does not decode.
//!
//! No transport is implemented. Nothing in this module opens a socket, loads an
//! eBPF program, or produces or verifies a signature.

use crate::contracts::encoding::OversightSignature;
use crate::contracts::graph::{EdgeId, GateDirection};
use crate::contracts::{
    ContractError, Correlation, PayloadBuffer, SchemaId, decode_text, encode_into,
};
use crate::identity::{AgentId, Identity, MakerId, TargetResource};
use crate::ledger::hash::Digest32;
use crate::risk::{ActionType, OversightClass, RiskTier};
use crate::time::UnixSeconds;

/// The contract versions of the action proposal this build admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ActionProposalVersion {
    /// Version 1, tagged `aegis.p09-p06.action-proposal.v1`.
    #[serde(rename = "aegis.p09-p06.action-proposal.v1")]
    V1,
}

/// One action P09 Minerva proposes and P06 Justitia will intercept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ActionProposal {
    /// The contract version this payload claims.
    pub schema: ActionProposalVersion,
    /// The subsystem-graph edge the payload travels on.
    pub edge: EdgeId,
    /// The call direction decision D03 settled.
    pub direction: GateDirection,
    /// The identifier threading this proposal, its decision request and its
    /// audit record together.
    pub correlation_id: Identity,
    /// The agent process on whose behalf the action is proposed.
    pub agent_id: AgentId,
    /// The principal accountable for the proposal.
    pub maker: MakerId,
    /// What the action does.
    pub action_type: ActionType,
    /// The resource the action touches.
    pub target: TargetResource,
    /// The tier the proposer declares. Justitia may only raise it.
    pub declared_tier: RiskTier,
    /// The regulatory oversight class the proposer declares.
    pub oversight: OversightClass,
    /// The digest of the action payload the proposal stands for.
    pub payload_hash: Digest32,
    /// When the proposal was made.
    pub proposed_at: UnixSeconds,
    /// The proposer's seal. A proposal without one is refused.
    #[serde(default)]
    pub signature: Option<OversightSignature>,
}

impl ActionProposal {
    /// The contract this type instantiates.
    pub const SCHEMA: SchemaId = SchemaId::ActionProposal;

    /// The edge the proposal travels on, kept from the graph of record.
    pub const EDGE: EdgeId = EdgeId::ActionGateIntercept;

    /// The call direction decision D03 settled.
    pub const DIRECTION: GateDirection = GateDirection::SETTLED;

    /// Returns what a refusal of this payload is about.
    #[must_use]
    pub const fn correlation(&self) -> Correlation {
        Correlation::new(Self::SCHEMA, Some(self.correlation_id))
    }

    /// Checks the invariants the field types cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::Malformed`] when the payload names an edge
    /// other than [`Self::EDGE`], and [`ContractError::Unsigned`] when it
    /// carries no seal or an empty one.
    pub fn validate(&self) -> Result<(), ContractError> {
        let correlation = self.correlation();
        if self.edge != Self::EDGE {
            return Err(ContractError::Malformed { correlation });
        }
        match self.signature {
            Some(seal) if !seal.is_empty() => Ok(()),
            _ => Err(ContractError::Unsigned { correlation }),
        }
    }

    /// Encodes a validated proposal into `buffer`.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::validate`], and returns
    /// [`ContractError::PayloadTooLong`] when the payload does not fit.
    pub fn encode_into<'b>(&self, buffer: &'b mut PayloadBuffer) -> Result<&'b str, ContractError> {
        self.validate()?;
        encode_into(self, self.correlation(), buffer)
    }

    /// Decodes and validates one proposal payload.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::UnknownVersion`] for a payload naming another
    /// contract version, [`ContractError::Malformed`] for anything else the
    /// schema refuses, [`ContractError::PayloadTooLong`] past the byte bound,
    /// and [`ContractError::Unsigned`] for an unsealed proposal.
    pub fn decode(text: &str) -> Result<Self, ContractError> {
        let decoded: Self = decode_text(Self::SCHEMA, text)?;
        decoded.validate()?;
        Ok(decoded)
    }
}
