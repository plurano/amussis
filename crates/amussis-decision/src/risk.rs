// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Risk classification and the approval it demands.
//!
//! `RiskTier` derives `Ord` in ascending severity, so "at least Tier B" is a
//! comparison rather than a match. The oversight class is a type, not a flag,
//! and it dominates the tier at classification time: an Annex III action
//! demands two distinct checkers at **every** tier, Tier C included. A routine,
//! bounded, reversible action that touches an Annex III high-risk use is
//! therefore held for a two-person panel, where the same action outside that
//! class would have been allowed outright. The escalation only ever raises the
//! demanded approval; there is no class that lowers it and no under-load
//! fallback from two checkers to one.

/// Severity of a proposed action, ascending.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum RiskTier {
    /// Routine and bounded; reversible without operator involvement.
    TierCRoutineBounded,
    /// Material but reversible.
    TierBMaterialReversible,
    /// Consequential; human oversight is mandatory.
    TierAConsequential,
}

/// Regulatory oversight class of a proposed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OversightClass {
    /// No sector-specific oversight obligation.
    Standard,
    /// An Annex III high-risk use, including biometric processing.
    AnnexIiiBiometric,
}

/// The kinds of action the engine classifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionType {
    /// Modifying the contents of an existing file.
    FileModification,
    /// Deleting a file.
    FileDeletion,
    /// Any outbound network request leaving the unit.
    ExternalNetworkRequest,
    /// Raising the privileges of a principal or process.
    PermissionEscalation,
    /// Changing system-level configuration.
    SystemConfigChange,
}

impl ActionType {
    /// Returns the lowest tier this action may ever be classified at.
    ///
    /// Deletion, privilege escalation and system configuration changes floor at
    /// Tier A. This resolves the one disagreement between the two imported
    /// proposal sketches, and it resolves it upward: the floor may raise a
    /// declared tier, never lower it.
    #[must_use]
    pub const fn minimum_tier(self) -> RiskTier {
        match self {
            Self::FileModification | Self::ExternalNetworkRequest => RiskTier::TierCRoutineBounded,
            Self::FileDeletion | Self::PermissionEscalation | Self::SystemConfigChange => {
                RiskTier::TierAConsequential
            }
        }
    }

    /// Returns the stable tag mixed into the canonical audit pre-image.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::FileModification => 1,
            Self::FileDeletion => 2,
            Self::ExternalNetworkRequest => 3,
            Self::PermissionEscalation => 4,
            Self::SystemConfigChange => 5,
        }
    }
}

/// The human oversight a classified action demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredApproval {
    /// No approval; the action may proceed.
    None,
    /// No approval, but the action is recorded and surfaced to the operator.
    MonitoredNotice,
    /// One checker, distinct from the maker.
    SingleChecker,
    /// Two distinct checkers, both distinct from the maker.
    DualDistinctCheckers,
}

impl RequiredApproval {
    /// Returns the approval demanded by a tier and oversight class.
    ///
    /// The table is total over both enums with no wildcard arm, so adding a
    /// tier or a class is a compile error at this decision site.
    #[must_use]
    pub const fn for_action(tier: RiskTier, class: OversightClass) -> Self {
        match (tier, class) {
            (RiskTier::TierCRoutineBounded, OversightClass::Standard) => Self::None,
            (
                RiskTier::TierCRoutineBounded
                | RiskTier::TierBMaterialReversible
                | RiskTier::TierAConsequential,
                OversightClass::AnnexIiiBiometric,
            ) => Self::DualDistinctCheckers,
            (RiskTier::TierBMaterialReversible, OversightClass::Standard) => Self::MonitoredNotice,
            (RiskTier::TierAConsequential, OversightClass::Standard) => Self::SingleChecker,
        }
    }

    /// Returns the number of distinct checkers this approval demands.
    #[must_use]
    pub const fn checker_count(self) -> usize {
        match self {
            Self::None | Self::MonitoredNotice => 0,
            Self::SingleChecker => 1,
            Self::DualDistinctCheckers => 2,
        }
    }

    /// Returns `true` when the action must wait for a human decision.
    #[must_use]
    pub const fn needs_human(self) -> bool {
        self.checker_count() > 0
    }
}
