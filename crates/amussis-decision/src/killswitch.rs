// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! A one-way halt latch.
//!
//! There is no `disengage`: once engaged, the latch stays engaged for the life
//! of the value. The observed state is written into every audit record, so a
//! block is auditable after the fact.
//!
//! A halt has a time, a reason and a risk level: the level of the action it
//! answers, which its release is held to. Engaging an engaged latch keeps the
//! first time and never makes the halt weaker: the level only rises, and the
//! first reason stays unless the later halt is a compromised chain, which no
//! earlier reason hides.
//!
//! A latch is released in one place only: by
//! [`DecisionEngine::release_halt`](crate::DecisionEngine::release_halt), on
//! an engine that continued a chain and was handed its halt by that chain.
//! See [`crate::engine`] for the rule.

use crate::ledger::LedgerError;
use crate::oversight::OversightError;
use crate::risk::{RequiredApproval, RiskLevel};
use crate::time::{ClockError, UnixSeconds};

/// Why the system was halted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum HaltReason {
    /// A human operator stopped the system.
    OperatorStop,
    /// The audit path became unusable.
    AuditUnavailable,
    /// The audit chain failed verification.
    LedgerCompromised,
    /// The wall clock became unusable or moved backwards.
    ClockUnavailable,
}

impl HaltReason {
    /// Returns the stable tag mixed into the canonical audit pre-image.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::OperatorStop => 1,
            Self::AuditUnavailable => 2,
            Self::LedgerCompromised => 3,
            Self::ClockUnavailable => 4,
        }
    }

    /// Returns the reason a stable tag stands for, or `None` for a tag no
    /// reason has. The inverse of [`Self::tag`].
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::OperatorStop),
            2 => Some(Self::AuditUnavailable),
            3 => Some(Self::LedgerCompromised),
            4 => Some(Self::ClockUnavailable),
            _ => None,
        }
    }
}

/// Reasons a halt is not released. The latch stays engaged in every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReleaseError {
    /// The latch is armed; there is no halt to release.
    #[error("the halt latch is not engaged")]
    NotHalted,
    /// The chain is halted as compromised; that halt is not released.
    #[error("a chain halted as compromised is not released")]
    Compromised,
    /// The halt is this engine's own, or this engine halted again after it
    /// took over a halted chain. Only a halt the chain handed over at a
    /// continuation is released, so a release takes a new engine.
    #[error("only a halt handed over by a continued chain is released")]
    NotInherited,
    /// The level the halt stands at demands checkers beside the releasing
    /// person, and no panel was given.
    #[error("the halted level demands {required:?} and no panel was given")]
    ApprovalMissing {
        /// The approval the halted level demands.
        required: RequiredApproval,
    },
    /// The panel does not satisfy the approval rule: it names the releasing
    /// person, or it is smaller than the halted level demands.
    #[error("approval: {0}")]
    Approval(#[from] OversightError),
    /// The clock is unusable, so the release has no time to be recorded at.
    #[error("clock: {0}")]
    Clock(#[from] ClockError),
    /// The release could not be written into the audit chain. A release that
    /// is not in the chain did not happen.
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
}

/// The latch state observed at one decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillswitchState {
    /// The system is running.
    Armed,
    /// The system is halted.
    Engaged {
        /// When the latch was first engaged.
        at: UnixSeconds,
        /// Why the system is halted: the first reason, or a compromised
        /// chain found since.
        reason: HaltReason,
        /// The risk level the halt stands at: the strictest level of the
        /// actions it answered.
        level: RiskLevel,
    },
}

impl KillswitchState {
    /// Returns `true` when the system is halted.
    #[must_use]
    pub const fn is_engaged(self) -> bool {
        matches!(self, Self::Engaged { .. })
    }

    /// Returns the halt reason, if any.
    #[must_use]
    pub const fn reason(self) -> Option<HaltReason> {
        match self {
            Self::Armed => None,
            Self::Engaged { reason, .. } => Some(reason),
        }
    }

    /// Returns the risk level the halt stands at, if there is a halt.
    #[must_use]
    pub const fn level(self) -> Option<RiskLevel> {
        match self {
            Self::Armed => None,
            Self::Engaged { level, .. } => Some(level),
        }
    }

    /// Returns the time the latch engaged, if it did.
    #[must_use]
    pub const fn engaged_at(self) -> Option<UnixSeconds> {
        match self {
            Self::Armed => None,
            Self::Engaged { at, .. } => Some(at),
        }
    }
}

/// The one-way halt latch itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Killswitch {
    state: KillswitchState,
}

impl Default for Killswitch {
    fn default() -> Self {
        Self::new()
    }
}

impl Killswitch {
    /// Builds an armed latch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: KillswitchState::Armed,
        }
    }

    /// Builds a latch in the state a chain was left in.
    ///
    /// This is how an engine that continues a chain starts halted when the
    /// chain ends halted, and armed when it does not; `state` comes from the
    /// anchor of the chain.
    #[must_use]
    pub const fn from_state(state: KillswitchState) -> Self {
        Self { state }
    }

    /// Engages the latch at a risk level.
    ///
    /// On an engaged latch the first time stays, the level becomes the
    /// stricter of the two, and the reason stays the first one unless
    /// `reason` is [`HaltReason::LedgerCompromised`]: a compromised chain
    /// found under another halt is not hidden by it.
    pub fn engage(&mut self, at: UnixSeconds, reason: HaltReason, level: RiskLevel) {
        self.state = match self.state {
            KillswitchState::Armed => KillswitchState::Engaged { at, reason, level },
            KillswitchState::Engaged {
                at: first,
                reason: held,
                level: stood,
            } => KillswitchState::Engaged {
                at: first,
                reason: match reason {
                    HaltReason::LedgerCompromised => reason,
                    _ => held,
                },
                level: stood.stricter(level),
            },
        };
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> KillswitchState {
        self.state
    }

    /// Returns `true` when the system is halted.
    #[must_use]
    pub const fn is_engaged(&self) -> bool {
        self.state.is_engaged()
    }
}
