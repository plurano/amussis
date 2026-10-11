// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! What the engine returns for one intercepted action.
//!
//! Every payload is an enum, never a `String`: no variant owns heap memory, so
//! returning an outcome cannot allocate, and a test asserts on a variant rather
//! than on prose.
//!
//! # Four variants against the three the requirements name
//!
//! `docs/roadmap/requirements.md` records the M02 behavioural contract as
//! "Allow, Block or Escalate(DecisionRequest)". This crate ships four variants,
//! and the fourth is a recorded refinement rather than a drift:
//!
//! * [`InterceptorOutcome::RequireApproval`] is the requirement's `Escalate`,
//!   renamed for what it does to the action (it is held, not forwarded) and
//!   carrying an [`ApprovalTicket`] in place of the unpinned `DecisionRequest`
//!   schema, which M14 versions.
//! * [`InterceptorOutcome::Warn`] splits the requirement's `Allow`. The
//!   requirements also mandate a Tier B monitored notice; folding that into
//!   `Allow` would leave the notice untyped, so the only way a caller could
//!   honour it would be to re-derive the tier, duplicating the classification
//!   the engine just performed. `Warn` and `Allow` are both permissive
//!   ([`InterceptorOutcome::permits_execution`] returns `true` for both), so the
//!   refinement adds an obligation and removes no permission.
//!
//! M14 takes the four-value vocabulary into the versioned consumer schema.

use crate::killswitch::HaltReason;
use crate::oversight::ApprovalTicket;

/// A non-blocking advisory attached to an allowed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningCode {
    /// A Tier B action proceeded under monitoring.
    MonitoredTierB,
}

/// Why an action was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum BlockReason {
    /// The halt latch was engaged.
    KillswitchEngaged(HaltReason),
    /// The audit record could not be sealed or stored.
    AuditUnavailable,
    /// The wall clock was unusable or moved backwards.
    ClockUnavailable,
    /// The approval window could not be opened without overflow.
    DeadlineOverflow,
    /// The audit chain failed verification.
    LedgerCompromised,
    /// No capacity remained to hold another pending request.
    RegistryFull,
    /// The request could not be formed from the supplied intent.
    RequestMalformed,
    /// An approval request with the same identifier is already held and live.
    RequestAlreadyPending,
}

impl BlockReason {
    /// Returns the stable tag mixed into the canonical audit pre-image.
    ///
    /// Zero is reserved for "no refusal", so a recorded reason never collides
    /// with the absence of one.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::KillswitchEngaged(_) => 1,
            Self::AuditUnavailable => 2,
            Self::ClockUnavailable => 3,
            Self::DeadlineOverflow => 4,
            Self::LedgerCompromised => 5,
            Self::RegistryFull => 6,
            Self::RequestMalformed => 7,
            Self::RequestAlreadyPending => 8,
        }
    }

    /// Returns the halt tag carried by [`Self::KillswitchEngaged`], else zero.
    #[must_use]
    pub const fn halt_tag(self) -> u8 {
        match self {
            Self::KillswitchEngaged(reason) => reason.tag(),
            Self::AuditUnavailable
            | Self::ClockUnavailable
            | Self::DeadlineOverflow
            | Self::LedgerCompromised
            | Self::RegistryFull
            | Self::RequestMalformed
            | Self::RequestAlreadyPending => 0,
        }
    }

    /// Returns the stable name used in records and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::KillswitchEngaged(_) => "killswitch-engaged",
            Self::AuditUnavailable => "audit-unavailable",
            Self::ClockUnavailable => "clock-unavailable",
            Self::DeadlineOverflow => "deadline-overflow",
            Self::LedgerCompromised => "ledger-compromised",
            Self::RegistryFull => "registry-full",
            Self::RequestMalformed => "request-malformed",
            Self::RequestAlreadyPending => "request-already-pending",
        }
    }
}

/// The decision for one intercepted action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "the approval ticket is stored inline on purpose. HISS-03 forbids \
              heap allocation on the decision path, so boxing it to even the \
              variant sizes would trade a rule for a byte count."
)]
pub enum InterceptorOutcome {
    /// The action may proceed.
    Allow,
    /// The action may proceed, with an advisory recorded.
    Warn {
        /// The advisory.
        code: WarningCode,
    },
    /// The action is held for human review.
    RequireApproval(ApprovalTicket),
    /// The action is refused.
    Block {
        /// Why it was refused.
        reason: BlockReason,
    },
}

impl InterceptorOutcome {
    /// Returns `true` only for [`Self::Allow`] and [`Self::Warn`].
    ///
    /// [`Self::RequireApproval`] is deliberately not permissive: a held action
    /// must not execute before a checker decides.
    #[must_use]
    pub const fn permits_execution(&self) -> bool {
        matches!(self, Self::Allow | Self::Warn { .. })
    }

    /// Returns the block reason, if the action was refused.
    #[must_use]
    pub const fn block_reason(&self) -> Option<BlockReason> {
        match self {
            Self::Block { reason } => Some(*reason),
            Self::Allow | Self::Warn { .. } | Self::RequireApproval(_) => None,
        }
    }

    /// Returns the approval ticket, if the action was held.
    #[must_use]
    pub const fn ticket(&self) -> Option<&ApprovalTicket> {
        match self {
            Self::RequireApproval(ticket) => Some(ticket),
            Self::Allow | Self::Warn { .. } | Self::Block { .. } => None,
        }
    }
}
