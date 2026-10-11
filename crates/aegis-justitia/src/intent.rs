// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! A validated proposal to act.

use crate::identity::{AgentId, IntentId, MakerId, TargetResource};
use crate::risk::{ActionType, OversightClass, RiskTier};

/// Reasons a proposed action is refused before classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IntentError {
    /// The declared tier is below the floor the action type imposes.
    #[error("declared tier {declared:?} is below the floor {minimum:?} for this action")]
    TierDowngrade {
        /// The tier the caller declared.
        declared: RiskTier,
        /// The floor the action type imposes.
        minimum: RiskTier,
    },
}

/// The caller-supplied fields of a proposed action.
///
/// Passed as one value so the validating constructor stays within the
/// argument bound declared in `clippy.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentSpec {
    /// Stable identifier of this proposal.
    pub id: IntentId,
    /// The agent process proposing the action.
    pub agent: AgentId,
    /// The principal accountable for the proposal.
    pub maker: MakerId,
    /// What the action does.
    pub action: ActionType,
    /// The tier the caller declares.
    pub declared_tier: RiskTier,
    /// The regulatory oversight class.
    pub oversight: OversightClass,
    /// The resource the action touches.
    pub target: TargetResource,
}

/// A validated proposal to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionIntent {
    id: IntentId,
    agent: AgentId,
    maker: MakerId,
    action: ActionType,
    declared_tier: RiskTier,
    oversight: OversightClass,
    target: TargetResource,
}

impl ActionIntent {
    /// Validates `spec` into an intent.
    ///
    /// # Errors
    ///
    /// Returns [`IntentError::TierDowngrade`] when the declared tier is below
    /// the floor the action type imposes. The floor resolves upward only.
    pub fn new(spec: IntentSpec) -> Result<Self, IntentError> {
        let minimum = spec.action.minimum_tier();
        if spec.declared_tier < minimum {
            return Err(IntentError::TierDowngrade {
                declared: spec.declared_tier,
                minimum,
            });
        }
        Ok(Self {
            id: spec.id,
            agent: spec.agent,
            maker: spec.maker,
            action: spec.action,
            declared_tier: spec.declared_tier,
            oversight: spec.oversight,
            target: spec.target,
        })
    }

    /// Returns the intent identifier.
    #[must_use]
    pub const fn id(&self) -> &IntentId {
        &self.id
    }

    /// Returns the proposing agent.
    #[must_use]
    pub const fn agent(&self) -> &AgentId {
        &self.agent
    }

    /// Returns the accountable maker.
    #[must_use]
    pub const fn maker(&self) -> &MakerId {
        &self.maker
    }

    /// Returns the action type.
    #[must_use]
    pub const fn action(&self) -> ActionType {
        self.action
    }

    /// Returns the tier the caller declared.
    #[must_use]
    pub const fn declared_tier(&self) -> RiskTier {
        self.declared_tier
    }

    /// Returns the oversight class.
    #[must_use]
    pub const fn oversight(&self) -> OversightClass {
        self.oversight
    }

    /// Returns the target resource.
    #[must_use]
    pub const fn target(&self) -> &TargetResource {
        &self.target
    }

    /// Returns the tier the engine classifies at: the declared tier raised to
    /// the action type's floor.
    #[must_use]
    pub fn effective_tier(&self) -> RiskTier {
        core::cmp::max(self.declared_tier, self.action.minimum_tier())
    }
}
