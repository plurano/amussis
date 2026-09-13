// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! A one-way halt latch.
//!
//! There is no `disengage` in milestone M02: once engaged, the latch stays
//! engaged for the life of the value, and re-engaging preserves the first
//! reason and time. The observed state is written into every audit record, so a
//! block is auditable after the fact.

use crate::time::UnixSeconds;

/// Why the system was halted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        /// Why the latch was first engaged.
        reason: HaltReason,
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

    /// Engages the latch. Idempotent: a second call keeps the first reason and
    /// time, so the audit trail records why the system first halted.
    pub const fn engage(&mut self, at: UnixSeconds, reason: HaltReason) {
        if let KillswitchState::Armed = self.state {
            self.state = KillswitchState::Engaged { at, reason };
        }
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
