// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The library's own input: one proposed action as text.
//!
//! A caller that does not link Rust (the WebAssembly binding, and through it a
//! Go program) hands the engine a proposal as one JSON object. This module is
//! that object's schema. It carries exactly the seven fields
//! [`IntentSpec`] has and a version tag, and nothing a single consumer needs:
//!
//! | Key | Value | Bound | Becomes |
//! | :-- | :-- | :-- | :-- |
//! | `schema` | [`PROPOSAL_SCHEMA`] | fixed | the version check |
//! | `id` | identifier | [`crate::MAX_IDENTITY_LEN`] bytes | [`IntentSpec::id`] |
//! | `agent` | identifier | [`crate::MAX_IDENTITY_LEN`] bytes | [`IntentSpec::agent`] |
//! | `maker` | identifier | [`crate::MAX_IDENTITY_LEN`] bytes | [`IntentSpec::maker`] |
//! | `action` | an [`ActionType`] tag | fixed set | [`IntentSpec::action`] |
//! | `target` | resource name | [`crate::MAX_TARGET_LEN`] bytes | [`IntentSpec::target`] |
//! | `declared-tier` | a [`RiskTier`] tag | fixed set | [`IntentSpec::declared_tier`] |
//! | `oversight` | an [`OversightClass`] tag | fixed set | [`IntentSpec::oversight`] |
//!
//! Keys are in kebab case. An unknown key, a repeated key, a missing key and a
//! value outside its bound are all refused; nothing is truncated, defaulted or
//! skipped. Each field is validated during decoding by the constructor the
//! library already uses for it.
//!
//! # What is not in the schema
//!
//! An edge name, a call direction, a payload hash, a proposal time and a seal
//! belong to the envelope one system puts around a proposal. Such an envelope
//! is a schema of that system's adapter, built from [`crate::encoding`]: the
//! adapter checks it and then maps to this one. The engine reads none of those
//! fields.
//!
//! # Refusals
//!
//! A text that is not a proposal is refused with a [`ProposalError`] naming one
//! cause: too long, another version, or malformed. The two parse refusals carry
//! the proposal's `id` when it could still be read, so a refused text can be
//! tied to its caller without echoing the text into a log. The `schema` and
//! `id` fields are read independently of each other and of the rest of the
//! text, so a damaged version tag does not hide a readable identifier.

use crate::identity::{AgentId, Identity, IntentId, MakerId, TargetResource};
use crate::intent::{ActionIntent, IntentError, IntentSpec};
use crate::risk::{ActionType, OversightClass, RiskTier};

/// The version tag a proposal's `schema` field carries.
pub const PROPOSAL_SCHEMA: &str = "amussis.decision.proposal.v1";

/// Scalar upper bound, in bytes, on one proposal text.
///
/// The longest admissible proposal is well under a kilobyte when written
/// plainly; the bound leaves room for a text that spells its characters as JSON
/// escapes. A longer text is refused before it is parsed.
pub const MAX_PROPOSAL_BYTES: usize = 4096;

/// The proposal versions this build admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ProposalVersion {
    /// Version 1, tagged [`PROPOSAL_SCHEMA`].
    #[serde(rename = "amussis.decision.proposal.v1")]
    V1,
}

/// Reasons a proposal text is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProposalError {
    /// The text is longer than [`MAX_PROPOSAL_BYTES`]; it was not parsed.
    #[error("a proposal of {actual} bytes exceeds the bound of {max}")]
    TooLong {
        /// Inclusive upper bound in bytes.
        max: usize,
        /// Observed length in bytes.
        actual: usize,
    },
    /// The text names a proposal version this build does not admit.
    #[error("the proposal names a version this build does not admit")]
    UnknownVersion {
        /// The proposal's identifier, when it could be read.
        id: Option<IntentId>,
    },
    /// The text is not a well-formed proposal of the admitted version.
    #[error("the text is not a well-formed proposal")]
    Malformed {
        /// The proposal's identifier, when it could be read.
        id: Option<IntentId>,
    },
}

/// One proposed action, as a caller writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Proposal {
    /// The version this text claims.
    pub schema: ProposalVersion,
    /// Stable identifier of this proposal.
    pub id: IntentId,
    /// The agent process proposing the action.
    pub agent: AgentId,
    /// The principal accountable for the proposal.
    pub maker: MakerId,
    /// What the action does.
    pub action: ActionType,
    /// The resource the action touches.
    pub target: TargetResource,
    /// The tier the caller declares. The engine may only raise it.
    pub declared_tier: RiskTier,
    /// The regulatory oversight class the caller declares.
    pub oversight: OversightClass,
}

impl Proposal {
    /// Wraps the fields of a proposed action in the current version.
    #[must_use]
    pub const fn from_spec(spec: IntentSpec) -> Self {
        Self {
            schema: ProposalVersion::V1,
            id: spec.id,
            agent: spec.agent,
            maker: spec.maker,
            action: spec.action,
            target: spec.target,
            declared_tier: spec.declared_tier,
            oversight: spec.oversight,
        }
    }

    /// Decodes one proposal text.
    ///
    /// # Errors
    ///
    /// Returns [`ProposalError::TooLong`] past [`MAX_PROPOSAL_BYTES`],
    /// [`ProposalError::UnknownVersion`] for a text naming another version and
    /// [`ProposalError::Malformed`] for anything else the schema refuses.
    pub fn decode(text: &str) -> Result<Self, ProposalError> {
        if text.len() > MAX_PROPOSAL_BYTES {
            return Err(ProposalError::TooLong {
                max: MAX_PROPOSAL_BYTES,
                actual: text.len(),
            });
        }
        match serde_json::from_str::<Self>(text) {
            Ok(proposal) => Ok(proposal),
            Err(_) => Err(classify(text)),
        }
    }

    /// Returns the fields of the proposed action.
    #[must_use]
    pub const fn spec(&self) -> IntentSpec {
        IntentSpec {
            id: self.id,
            agent: self.agent,
            maker: self.maker,
            action: self.action,
            declared_tier: self.declared_tier,
            oversight: self.oversight,
            target: self.target,
        }
    }

    /// Validates the proposal into the intent the engine decides on.
    ///
    /// # Errors
    ///
    /// Returns [`IntentError::TierDowngrade`] when the declared tier is below
    /// the floor the action type imposes.
    pub fn intent(&self) -> Result<ActionIntent, IntentError> {
        ActionIntent::new(self.spec())
    }
}

/// The lenient view of a text's `schema` field, and of nothing else.
#[derive(serde::Deserialize)]
struct PeekSchema {
    #[serde(default)]
    schema: Option<Identity>,
}

/// The lenient view of a text's `id` field, and of nothing else.
///
/// A second type on purpose: one view with both fields would lose a readable
/// identifier whenever the version tag fails to parse.
#[derive(serde::Deserialize)]
struct PeekId {
    #[serde(default)]
    id: Option<IntentId>,
}

/// Names the cause of a failed decode.
fn classify(text: &str) -> ProposalError {
    let id = serde_json::from_str::<PeekId>(text)
        .ok()
        .and_then(|row| row.id);
    let claimed = serde_json::from_str::<PeekSchema>(text)
        .ok()
        .and_then(|row| row.schema);
    match claimed {
        Some(tag) if tag.as_bytes() != PROPOSAL_SCHEMA.as_bytes() => {
            ProposalError::UnknownVersion { id }
        }
        _ => ProposalError::Malformed { id },
    }
}
