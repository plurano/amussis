// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Maker-checker oversight.
//!
//! [`CheckerSet::dual`] refuses a duplicate panel, so a two-checker set with one
//! principal is unrepresentable. [`VerifiedCheckerSet`] has no public
//! constructor: its only producer is [`CheckerSet::verify_against_maker`], which
//! checks both slots. A value of that type is therefore a proof that the panel
//! was separated from the maker.

use crate::identity::{AgentId, CheckerId, MakerId, RequestId};
use crate::risk::{ActionType, RequiredApproval};
use crate::time::Deadline;

/// Reasons an oversight step is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OversightError {
    /// A two-checker panel named the same principal twice.
    #[error("a two-checker panel must name two distinct principals")]
    DuplicateChecker,
    /// The maker appeared in the checker panel.
    #[error("the maker may not review its own proposal")]
    MakerIsChecker,
    /// A single-checker panel was offered where two are required.
    #[error("this request requires two distinct checkers")]
    AnnexIiiRequiresTwoCheckers,
    /// A checker panel was offered for a request that needs no approval.
    #[error("this request does not admit a checker decision")]
    NoApprovalRequired,
    /// The approval window closed before the decision arrived.
    #[error("the approval window closed before the decision arrived")]
    ApprovalExpired,
    /// The request identifier is not held by the engine.
    #[error("no pending request with that identifier")]
    UnknownRequest,
    /// The request already reached a terminal state.
    #[error("the request already reached a terminal state")]
    AlreadyDecided,
    /// The killswitch was engaged when the decision arrived.
    #[error("the system is halted; no decision can be accepted")]
    SystemHalted,
}

/// A panel of one or two checkers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckerSet {
    /// One checker.
    Single(CheckerId),
    /// Two distinct checkers.
    Dual {
        /// The first checker.
        first: CheckerId,
        /// The second checker, distinct from the first.
        second: CheckerId,
    },
}

impl CheckerSet {
    /// Builds a single-checker panel.
    #[must_use]
    pub const fn single(checker: CheckerId) -> Self {
        Self::Single(checker)
    }

    /// Builds a two-checker panel.
    ///
    /// # Errors
    ///
    /// Returns [`OversightError::DuplicateChecker`] when both slots name the
    /// same principal.
    pub fn dual(first: CheckerId, second: CheckerId) -> Result<Self, OversightError> {
        if first == second {
            return Err(OversightError::DuplicateChecker);
        }
        Ok(Self::Dual { first, second })
    }

    /// Returns the number of distinct checkers in the panel.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Dual { .. } => 2,
        }
    }

    /// Returns `false`; a panel always names at least one checker.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Returns the first checker of the panel.
    #[must_use]
    pub const fn primary(&self) -> CheckerId {
        match self {
            Self::Single(checker) | Self::Dual { first: checker, .. } => *checker,
        }
    }

    /// Proves the panel is separated from `maker`.
    ///
    /// # Errors
    ///
    /// Returns [`OversightError::MakerIsChecker`] when the maker appears in
    /// either slot. Both slots are checked; the imported sketch checked only
    /// the first.
    pub fn verify_against_maker(
        self,
        maker: &MakerId,
    ) -> Result<VerifiedCheckerSet, OversightError> {
        let clash = match self {
            Self::Single(checker) => maker.is_same_principal(&checker),
            Self::Dual { first, second } => {
                maker.is_same_principal(&first) || maker.is_same_principal(&second)
            }
        };
        if clash {
            return Err(OversightError::MakerIsChecker);
        }
        Ok(VerifiedCheckerSet { inner: self })
    }
}

/// A checker panel proved distinct from the maker of the request it reviews.
///
/// There is no public constructor. The only producer is
/// [`CheckerSet::verify_against_maker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedCheckerSet {
    inner: CheckerSet,
}

impl VerifiedCheckerSet {
    /// Returns the underlying panel.
    #[must_use]
    pub const fn panel(&self) -> CheckerSet {
        self.inner
    }

    /// Returns the first checker of the panel.
    #[must_use]
    pub const fn primary(&self) -> CheckerId {
        self.inner.primary()
    }

    /// Checks the panel against the approval a request demands.
    ///
    /// # Errors
    ///
    /// Returns [`OversightError::AnnexIiiRequiresTwoCheckers`] when a single
    /// checker is offered where two are required, and
    /// [`OversightError::NoApprovalRequired`] when the request admits no
    /// checker decision at all. There is no under-load fallback.
    pub const fn satisfies(&self, required: RequiredApproval) -> Result<(), OversightError> {
        match required {
            RequiredApproval::None | RequiredApproval::MonitoredNotice => {
                Err(OversightError::NoApprovalRequired)
            }
            RequiredApproval::SingleChecker => Ok(()),
            RequiredApproval::DualDistinctCheckers => match self.inner {
                CheckerSet::Dual { .. } => Ok(()),
                CheckerSet::Single(_) => Err(OversightError::AnnexIiiRequiresTwoCheckers),
            },
        }
    }
}

/// The ticket the engine issues when it holds an action for human review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalTicket {
    request_id: RequestId,
    maker: MakerId,
    agent: AgentId,
    action: ActionType,
    required: RequiredApproval,
    deadline: Deadline,
}

impl ApprovalTicket {
    /// Builds a ticket.
    #[must_use]
    pub const fn new(
        request_id: RequestId,
        maker: MakerId,
        agent: AgentId,
        action: ActionType,
        required: RequiredApproval,
        deadline: Deadline,
    ) -> Self {
        Self {
            request_id,
            maker,
            agent,
            action,
            required,
            deadline,
        }
    }

    /// Returns the agent that proposed the held action.
    #[must_use]
    pub const fn agent(&self) -> &AgentId {
        &self.agent
    }

    /// Returns the action type of the held action.
    #[must_use]
    pub const fn action(&self) -> ActionType {
        self.action
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the maker the panel must be separated from.
    #[must_use]
    pub const fn maker(&self) -> &MakerId {
        &self.maker
    }

    /// Returns the approval the request demands.
    #[must_use]
    pub const fn required(&self) -> RequiredApproval {
        self.required
    }

    /// Returns the approval window.
    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }
}

/// A checker's vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vote {
    /// The checker approves the proposal.
    Approve,
    /// The checker rejects the proposal.
    Reject,
}

/// The outcome of a human review. A rejection is a decision, never an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adjudication {
    /// The proposal was approved.
    Approved {
        /// The checker that recorded the decision.
        by: CheckerId,
        /// When the decision was recorded.
        at: crate::time::UnixSeconds,
    },
    /// The proposal was rejected.
    Rejected {
        /// The checker that recorded the decision.
        by: CheckerId,
        /// When the decision was recorded.
        at: crate::time::UnixSeconds,
    },
}
