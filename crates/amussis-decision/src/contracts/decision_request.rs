// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The decision request P06 Justitia sends to P05 Forum.
//!
//! # Where the fields come from
//!
//! | Field | Source |
//! | :-- | :-- |
//! | `request-id`, `agent-id`, `maker`, `proposed-action`, `target`, `risk-tier`, `oversight`, `created-at`, `due-at` | export-047 `971948673346`, `DecisionRequest` |
//! | `request-id`, `agent-id`, `proposed-action`, `risk-tier` on the prompt | export-050 `8ffa666dcc5a`, `org.aegisos.Justitia1.DecisionRequestPrompt` |
//! | `edge` | export-062 `1ce919ed54bb`, edge `DISPATCH_DECISION_REQUEST` |
//! | `required-approval` | export-047 `971948673346`, the rule that an Annex III action needs two distinct checkers |
//!
//! # The declared window
//!
//! The imported sketch derives a due timestamp and treats a passed deadline as
//! a refusal, never as an implicit approval. The schema keeps that and makes
//! the window an explicit, bounded field: at least
//! [`MIN_DECISION_WINDOW_SECS`] and at most [`MAX_DECISION_WINDOW_SECS`]
//! seconds. A due time at or before the creation time reports a window of zero,
//! which is below the minimum and therefore refused.
//!
//! # The declared approval
//!
//! `required-approval` is not advisory. It must be exactly the approval the
//! declared tier and oversight class demand, so a payload cannot weaken a
//! two-checker Annex III panel into a single checker on the way to the shell.
//!
//! # Why the payload is typed rather than prose
//!
//! The imported sketch carries the proposed action and the target as free
//! strings. They are typed here instead, for two requirements at once. The gate
//! must cover every side-effecting path (REQ-GOV-03), so the action the shell
//! shows has to be the same closed set of action types the engine classified,
//! not a re-rendered sentence. And the shell has to present the request
//! accessibly (REQ-P06-08, export-004 `15831276a058`), which a consumer can
//! only do for values it can enumerate and label; a prose string leaves it
//! guessing. The accessibility obligation itself belongs to the Forum consumer,
//! typed at M16, not to this schema.
//!
//! No transport is implemented: this module opens no D-Bus connection and no
//! socket, and the Forum consumer itself is milestone M16 work.

use crate::contracts::graph::EdgeId;
use crate::contracts::{
    ContractError, Correlation, PayloadBuffer, SchemaId, decode_text, encode_into,
};
use crate::identity::{AgentId, Identity, MakerId, RequestId, TargetResource};
use crate::risk::{ActionType, OversightClass, RequiredApproval, RiskTier};
use crate::time::UnixSeconds;

/// Shortest approval window a decision request may declare, in seconds.
pub const MIN_DECISION_WINDOW_SECS: u32 = 1;

/// Longest approval window a decision request may declare, in seconds.
///
/// One day. A window longer than that is a standing authorisation rather than
/// a decision request, and the schema refuses to carry one.
pub const MAX_DECISION_WINDOW_SECS: u32 = 86_400;

/// The contract versions of the decision request this build admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum DecisionRequestVersion {
    /// Version 1, tagged `aegis.p06-p05.decision-request.v1`.
    #[serde(rename = "aegis.p06-p05.decision-request.v1")]
    V1,
}

/// One held action, handed to the shell for a human decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DecisionRequest {
    /// The contract version this payload claims.
    pub schema: DecisionRequestVersion,
    /// The subsystem-graph edge the payload travels on.
    pub edge: EdgeId,
    /// The identifier threading the proposal, this request and its record.
    pub correlation_id: Identity,
    /// Stable identifier of this approval request.
    pub request_id: RequestId,
    /// The agent process on whose behalf the action was proposed.
    pub agent_id: AgentId,
    /// The principal accountable for the proposal; it may not review itself.
    pub maker: MakerId,
    /// What the held action does.
    pub proposed_action: ActionType,
    /// The resource the held action touches.
    pub target: TargetResource,
    /// The tier the action was classified at.
    pub risk_tier: RiskTier,
    /// The regulatory oversight class of the held action.
    pub oversight: OversightClass,
    /// The approval the tier and class demand, restated for the shell.
    pub required_approval: RequiredApproval,
    /// When the request was opened.
    pub created_at: UnixSeconds,
    /// When the window closes. A closed window refuses; it never approves.
    pub due_at: UnixSeconds,
}

impl DecisionRequest {
    /// The contract this type instantiates.
    pub const SCHEMA: SchemaId = SchemaId::DecisionRequest;

    /// The edge the request travels on, kept from the graph of record.
    pub const EDGE: EdgeId = EdgeId::DispatchDecisionRequest;

    /// Returns what a refusal of this payload is about.
    #[must_use]
    pub const fn correlation(&self) -> Correlation {
        Correlation::new(Self::SCHEMA, Some(self.correlation_id))
    }

    /// Returns the declared approval window in seconds, zero if it is closed.
    #[must_use]
    pub const fn window_secs(&self) -> u64 {
        match self.due_at.get().checked_sub(self.created_at.get()) {
            Some(window) => window,
            None => 0,
        }
    }

    /// Checks the invariants the field types cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::Malformed`] for a payload naming another edge,
    /// [`ContractError::WindowOutOfRange`] when the window is outside the
    /// declared bounds, [`ContractError::NoApprovalRequired`] when the tier and
    /// class demand no human decision at all, and
    /// [`ContractError::ApprovalMismatch`] when the declared approval is not
    /// the demanded one.
    pub fn validate(&self) -> Result<(), ContractError> {
        let correlation = self.correlation();
        if self.edge != Self::EDGE {
            return Err(ContractError::Malformed { correlation });
        }
        self.validate_window(correlation)?;
        self.validate_approval(correlation)
    }

    /// Checks the declared window against the contract bounds.
    fn validate_window(&self, correlation: Correlation) -> Result<(), ContractError> {
        let window = self.window_secs();
        if window < u64::from(MIN_DECISION_WINDOW_SECS)
            || window > u64::from(MAX_DECISION_WINDOW_SECS)
        {
            return Err(ContractError::WindowOutOfRange {
                correlation,
                seconds: window,
                min: MIN_DECISION_WINDOW_SECS,
                max: MAX_DECISION_WINDOW_SECS,
            });
        }
        Ok(())
    }

    /// Checks the declared approval against the tier and oversight class.
    fn validate_approval(&self, correlation: Correlation) -> Result<(), ContractError> {
        let demanded = RequiredApproval::for_action(self.risk_tier, self.oversight);
        if !demanded.needs_human() {
            return Err(ContractError::NoApprovalRequired { correlation });
        }
        if self.required_approval != demanded {
            return Err(ContractError::ApprovalMismatch {
                correlation,
                declared: self.required_approval,
                demanded,
            });
        }
        Ok(())
    }

    /// Encodes a validated request into `buffer`.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::validate`], and returns
    /// [`ContractError::PayloadTooLong`] when the payload does not fit.
    pub fn encode_into<'b>(&self, buffer: &'b mut PayloadBuffer) -> Result<&'b str, ContractError> {
        self.validate()?;
        encode_into(self, self.correlation(), buffer)
    }

    /// Decodes and validates one decision-request payload.
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
