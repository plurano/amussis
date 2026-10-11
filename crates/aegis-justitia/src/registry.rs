// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The bounded registry of approval requests the engine still holds.
//!
//! The imported sketch built its decision request and dropped it, so the maker
//! identity compared against at review time was whatever the caller supplied.
//! Retaining the ticket the engine issued makes that identity authoritative and
//! closes the replay hole: an unknown identifier is refused.
//!
//! # Reclamation: why the bound is a concurrency bound
//!
//! A [`RequestId`] is derived deterministically from the [`crate::IntentId`], so
//! a legitimate retry of an action reuses the identifier of the attempt before
//! it. A registry that never released an entry would therefore turn `bound` into
//! a lifetime cap on distinct intents: once `bound` requests had ever been
//! opened, every further hold would be refused for ever, and every retry of a
//! finished request would collide with its own corpse.
//!
//! [`PendingRegistry::reclaim`] drops two classes of dead entry:
//!
//! * **decided** -- the checker voted, so the ticket has served its purpose;
//! * **expired** -- the approval window closed at or before `now`, so no vote
//!   can be accepted against it any more ([`Deadline::status`] treats
//!   `now == due_at` as closed, the fail-closed reading).
//!
//! [`PendingRegistry::insert`] reclaims before it tests the bound, so the bound counts
//! live requests only and a retry after reclamation succeeds. A decided entry
//! stays queryable until the next reclamation, which is what lets
//! [`PendingRegistry::pending`] distinguish [`RegistryError::AlreadyDecided`] from
//! [`RegistryError::Unknown`] for an immediate replay.
//!
//! Reclamation uses `Vec::retain`, which compacts in place: it never allocates
//! and never shrinks the reserved capacity, so HISS-03 still holds.

use crate::identity::RequestId;
use crate::ledger::RecordStatus;
use crate::oversight::ApprovalTicket;
use crate::time::{Deadline, DeadlineStatus, UnixSeconds};

/// Reasons the registry refuses an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// No capacity remained after reclamation.
    #[error("the pending-request registry is full at its bound of {limit} live requests")]
    Full {
        /// The scalar capacity bound.
        limit: usize,
    },
    /// The identifier is not held.
    #[error("no pending request with that identifier")]
    Unknown,
    /// The identifier is already held by a live request.
    #[error("a live approval request with that identifier is already held")]
    AlreadyPending,
    /// The identifier already reached a terminal state.
    #[error("the request already reached a terminal state")]
    AlreadyDecided,
}

/// The lifecycle state of one held request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// Awaiting a checker decision.
    Pending,
    /// Decided; the terminal record status is carried for the audit trail.
    Decided(RecordStatus),
}

/// A bounded set of approval requests the engine still holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRegistry {
    entries: Vec<(ApprovalTicket, RequestState)>,
    bound: usize,
}

impl PendingRegistry {
    /// Builds a registry with an explicit scalar bound on live requests.
    ///
    /// The entry list is reserved to `bound` here, once, so that
    /// [`PendingRegistry::insert`] never reallocates. The name is `with_bound`, not
    /// `with_capacity`: the std convention is that `with_capacity` reserves
    /// without capping, and this argument does both.
    #[must_use]
    pub fn with_bound(bound: usize) -> Self {
        Self {
            entries: Vec::with_capacity(bound),
            bound,
        }
    }

    /// Returns the scalar bound on live requests.
    #[must_use]
    pub const fn bound(&self) -> usize {
        self.bound
    }

    /// Returns the capacity reserved at construction.
    ///
    /// HISS-03 evidence: this value must not change while the registry is in
    /// use.
    #[must_use]
    pub fn reserved(&self) -> usize {
        self.entries.capacity()
    }

    /// Returns the number of held entries, decided ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no request is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of entries that are still live at `now`.
    #[must_use]
    pub fn live(&self, now: UnixSeconds) -> usize {
        self.entries
            .iter()
            .take(self.bound)
            .filter(|entry| is_live(entry, now))
            .count()
    }

    /// Drops every decided entry and every entry whose window closed at `now`,
    /// and returns how many were dropped.
    ///
    /// The scan is bounded: `entries.len()` never exceeds `bound`, which
    /// [`PendingRegistry::insert`] enforces before every push.
    pub fn reclaim(&mut self, now: UnixSeconds) -> usize {
        let before = self.entries.len();
        self.entries.retain(|entry| is_live(entry, now));
        before.saturating_sub(self.entries.len())
    }

    /// Holds `ticket`, reclaiming dead entries first.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::AlreadyPending`] when a live request already
    /// holds the identifier, and [`RegistryError::Full`] when the bound is
    /// reached after reclamation.
    pub fn insert(
        &mut self,
        ticket: ApprovalTicket,
        now: UnixSeconds,
    ) -> Result<(), RegistryError> {
        let _reclaimed = self.reclaim(now);
        if self.find(ticket.request_id()).is_some() {
            return Err(RegistryError::AlreadyPending);
        }
        if self.entries.len() >= self.bound {
            return Err(RegistryError::Full { limit: self.bound });
        }
        self.entries.push((ticket, RequestState::Pending));
        Ok(())
    }

    /// Returns the position of `id`, scanning at most the bound.
    fn find(&self, id: &RequestId) -> Option<usize> {
        self.entries
            .iter()
            .take(self.bound)
            .position(|(ticket, _)| ticket.request_id() == id)
    }

    /// Returns the held ticket and its state.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unknown`] when the identifier is not held.
    pub fn get(&self, id: &RequestId) -> Result<(ApprovalTicket, RequestState), RegistryError> {
        let index = self.find(id).ok_or(RegistryError::Unknown)?;
        let entry = self.entries.get(index).ok_or(RegistryError::Unknown)?;
        Ok(*entry)
    }

    /// Returns the ticket of a request that is still pending.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unknown`] when the identifier is not held and
    /// [`RegistryError::AlreadyDecided`] when it already reached a terminal
    /// state and has not been reclaimed yet.
    pub fn pending(&self, id: &RequestId) -> Result<ApprovalTicket, RegistryError> {
        match self.get(id)? {
            (ticket, RequestState::Pending) => Ok(ticket),
            (_, RequestState::Decided(_)) => Err(RegistryError::AlreadyDecided),
        }
    }

    /// Marks a held request terminal, making it reclaimable.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unknown`] when the identifier is not held and
    /// [`RegistryError::AlreadyDecided`] when it is already terminal.
    pub fn mark_decided(
        &mut self,
        id: &RequestId,
        status: RecordStatus,
    ) -> Result<(), RegistryError> {
        let index = self.find(id).ok_or(RegistryError::Unknown)?;
        let entry = self.entries.get_mut(index).ok_or(RegistryError::Unknown)?;
        if let RequestState::Decided(_) = entry.1 {
            return Err(RegistryError::AlreadyDecided);
        }
        entry.1 = RequestState::Decided(status);
        Ok(())
    }

    /// Drops a held request outright, recording no decision.
    ///
    /// The engine calls this when it opened a ticket and then could not seal
    /// the decision: the action was refused, so the hold must not survive and
    /// consume the bound.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unknown`] when the identifier is not held.
    pub fn release(&mut self, id: &RequestId) -> Result<ApprovalTicket, RegistryError> {
        let index = self.find(id).ok_or(RegistryError::Unknown)?;
        if index >= self.entries.len() {
            return Err(RegistryError::Unknown);
        }
        let (ticket, _state) = self.entries.remove(index);
        Ok(ticket)
    }
}

/// Returns `true` when an entry is still pending and its window is still open.
fn is_live(entry: &(ApprovalTicket, RequestState), now: UnixSeconds) -> bool {
    match entry.1 {
        RequestState::Decided(_) => false,
        RequestState::Pending => window_open(entry.0.deadline(), now),
    }
}

/// Returns `true` when `window` is still open at `now`.
fn window_open(window: Deadline, now: UnixSeconds) -> bool {
    matches!(window.status(now), DeadlineStatus::Open)
}

impl Default for PendingRegistry {
    fn default() -> Self {
        Self::with_bound(crate::MAX_PENDING_REQUESTS)
    }
}
