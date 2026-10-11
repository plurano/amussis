// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The decision engine.
//!
//! [`JustitiaEngine::decide`] is total: it returns an [`InterceptorOutcome`] for
//! every input and has no error channel. A clock fault, a deadline overflow, a
//! saturated registry, a seal failure and a compromised ledger all map to
//! [`InterceptorOutcome::Block`], so there is no path on which a fault degrades
//! into an allow.
//!
//! [`JustitiaEngine::adjudicate`] does return a `Result`, because an expired
//! window, an undersized panel, an unknown or already-decided request and a
//! halted system are conditions a human overseer must be able to distinguish.
//!
//! Both entry points match the halt latch first, before any tier logic, so the
//! killswitch blocks a Tier C action by construction rather than by ordering.
//!
//! # Every refusal is audited
//!
//! `decide` writes exactly one audit record per call, on every arm:
//!
//! | arm | status | recorded reason |
//! | :-- | :-- | :-- |
//! | halt latch engaged | [`RecordStatus::Halted`] | `KillswitchEngaged` |
//! | clock fault | [`RecordStatus::Blocked`] | `ClockUnavailable` |
//! | engine refusal | [`RecordStatus::Blocked`] | the refusal reason |
//! | released or held | `Approved` or `PendingApproval` | none |
//!
//! The single exception is a record that cannot itself be written. That cannot
//! be papered over -- there is nowhere to write it -- so it escalates instead:
//! the engine engages the halt latch with the matching [`HaltReason`] and every
//! later call blocks on the latch. A refusal is therefore never silent: it is
//! either in the chain or the engine is visibly halted.
//!
//! # The clock
//!
//! The engine owns a [`Clock`] and reads it itself; no caller passes a
//! timestamp in. Each reading goes through a [`MonotonicGuard`], so a source
//! that errors and a source that steps backwards are both faults, and both fail
//! closed: the latch engages with [`HaltReason::ClockUnavailable`] and the
//! action is blocked with [`BlockReason::ClockUnavailable`].
//!
//! # Allocation
//!
//! After [`JustitiaEngine::new`] returns, neither entry point allocates. The
//! registry, the ledger's record list and the sink's record list are reserved
//! to their scalar bounds at construction and refuse a push at the bound;
//! reclamation compacts in place. See the crate documentation and
//! `tests/allocation_bounds.rs`.

use crate::identity::{IntentId, RequestId};
use crate::intent::ActionIntent;
use crate::killswitch::{HaltReason, Killswitch, KillswitchState};
use crate::ledger::hash::LedgerHasher;
use crate::ledger::signer::{RecordSigner, SignerBinding};
use crate::ledger::{AuditLedger, IoDeadline, LedgerError, LedgerSink, RecordDraft, RecordStatus};
use crate::outcome::{BlockReason, InterceptorOutcome, WarningCode};
use crate::oversight::{
    Adjudication, ApprovalTicket, CheckerSet, OversightError, VerifiedCheckerSet, Vote,
};
use crate::registry::{PendingRegistry, RegistryError};
use crate::risk::{OversightClass, RequiredApproval};
use crate::time::{Clock, ClockError, Deadline, DeadlineStatus, MonotonicGuard, Ttl, UnixSeconds};
use crate::{DEFAULT_APPROVAL_TTL_SECS, JustitiaError, MAX_LEDGER_RECORDS, MAX_PENDING_REQUESTS};

/// Tunable bounds of one engine instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfig {
    /// Approval window for a standard request that needs a checker.
    pub approval_ttl: Ttl,
    /// Approval window for an Annex III request.
    pub annex_iii_ttl: Ttl,
    /// Scalar bound on concurrently live pending requests.
    pub max_pending: usize,
    /// Scalar bound on retained audit records.
    pub max_audit_records: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        // The fallback is unreachable: `DEFAULT_APPROVAL_TTL_SECS` is a non-zero
        // constant. It is written out because HISS-07 forbids `expect`.
        let ttl = Ttl::from_secs(DEFAULT_APPROVAL_TTL_SECS)
            .unwrap_or(Ttl::new(core::num::NonZeroU32::MIN));
        Self {
            approval_ttl: ttl,
            annex_iii_ttl: ttl,
            max_pending: MAX_PENDING_REQUESTS,
            max_audit_records: MAX_LEDGER_RECORDS,
        }
    }
}

/// The P06 decision engine.
#[derive(Debug, Clone)]
pub struct JustitiaEngine<H: LedgerHasher, S: RecordSigner, K: LedgerSink, C: Clock> {
    config: EngineConfig,
    killswitch: Killswitch,
    registry: PendingRegistry,
    ledger: AuditLedger<H, S, K>,
    clock: C,
    guard: MonotonicGuard,
}

impl<H: LedgerHasher, S: RecordSigner, K: LedgerSink, C: Clock> JustitiaEngine<H, S, K, C> {
    /// Builds an engine over a signer binding, a sink and a clock.
    ///
    /// Every bounded buffer is reserved here, so nothing on the decision path
    /// allocates afterwards.
    #[must_use]
    pub fn new(
        config: EngineConfig,
        signer: SignerBinding<S>,
        sink: K,
        io_deadline: IoDeadline,
        clock: C,
    ) -> Self {
        Self {
            registry: PendingRegistry::with_bound(config.max_pending),
            ledger: AuditLedger::with_bound(signer, sink, io_deadline, config.max_audit_records),
            config,
            killswitch: Killswitch::new(),
            clock,
            guard: MonotonicGuard::new(),
        }
    }

    /// Returns the engine configuration.
    #[must_use]
    pub const fn config(&self) -> EngineConfig {
        self.config
    }

    /// Returns the audit ledger.
    #[must_use]
    pub const fn ledger(&self) -> &AuditLedger<H, S, K> {
        &self.ledger
    }

    /// Returns the pending-request registry.
    #[must_use]
    pub const fn registry(&self) -> &PendingRegistry {
        &self.registry
    }

    /// Returns the halt-latch state.
    #[must_use]
    pub const fn killswitch(&self) -> KillswitchState {
        self.killswitch.state()
    }

    /// Returns the clock the engine reads.
    #[must_use]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    /// Returns the clock mutably, so a replay harness can advance it.
    pub const fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    /// Returns the most recent accepted clock reading, if there is one.
    #[must_use]
    pub const fn last_reading(&self) -> Option<UnixSeconds> {
        self.guard.last()
    }

    /// Engages the halt latch. There is no way to disengage it.
    ///
    /// The time is taken from the engine's own clock, falling back to the last
    /// accepted reading when the clock is the thing that failed: halting must
    /// never itself fail.
    pub fn halt(&mut self, reason: HaltReason) {
        let at = self.best_effort_now();
        self.killswitch.engage(at, reason);
    }

    /// Re-walks the audit chain, halting the engine if it is compromised.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] on the first broken link, having first engaged
    /// the halt latch with [`HaltReason::LedgerCompromised`].
    pub fn verify_ledger(&mut self) -> Result<(), LedgerError> {
        match self.ledger.verify() {
            Ok(_) => Ok(()),
            Err(error) => {
                let at = self.last_known_time();
                self.killswitch.engage(at, HaltReason::LedgerCompromised);
                Err(error)
            }
        }
    }

    /// Reads the clock through the monotonic guard.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError`] when the source is unusable or stepped backwards.
    pub fn now(&mut self) -> Result<UnixSeconds, ClockError> {
        let observed = self.clock.now()?;
        self.guard.observe(observed)
    }

    /// Returns the last accepted reading, or the epoch before the first one.
    const fn last_known_time(&self) -> UnixSeconds {
        match self.guard.last() {
            Some(at) => at,
            None => UnixSeconds::EPOCH,
        }
    }

    /// Reads the clock, falling back to the last accepted reading.
    fn best_effort_now(&mut self) -> UnixSeconds {
        match self.now() {
            Ok(at) => at,
            Err(_) => self.last_known_time(),
        }
    }

    /// Decides one intercepted action. Total: every input yields exactly one
    /// outcome, exactly one audit attempt, and nothing panics.
    pub fn decide(&mut self, intent: &ActionIntent) -> InterceptorOutcome {
        let observed = self.killswitch.state();
        if let KillswitchState::Engaged { reason, .. } = observed {
            return self.refuse_halted(intent, reason, observed);
        }
        let Ok(now) = self.now() else {
            return self.refuse_clock_fault(intent);
        };
        let required = RequiredApproval::for_action(intent.effective_tier(), intent.oversight());
        match self.plan(intent, required, now) {
            Ok((candidate, status)) => self.seal_and_release(intent, candidate, status, now),
            Err(reason) => self.refuse(intent, reason, now),
        }
    }

    /// Records and returns the refusal a halted system owes the caller.
    fn refuse_halted(
        &mut self,
        intent: &ActionIntent,
        halt: HaltReason,
        observed: KillswitchState,
    ) -> InterceptorOutcome {
        let reason = BlockReason::KillswitchEngaged(halt);
        let at = self.best_effort_now();
        let draft = draft_for(intent, RecordStatus::Halted, observed, at, Some(reason));
        // A halted system still records the refusal. A seal failure cannot make
        // the block any weaker, and the latch is already engaged, so there is
        // nothing left to escalate to.
        let _sealed = self.ledger.append(draft);
        InterceptorOutcome::Block { reason }
    }

    /// Fails closed on a clock fault: halts, records, and blocks.
    fn refuse_clock_fault(&mut self, intent: &ActionIntent) -> InterceptorOutcome {
        let at = self.last_known_time();
        self.killswitch.engage(at, HaltReason::ClockUnavailable);
        let reason = BlockReason::ClockUnavailable;
        let observed = self.killswitch.state();
        let draft = draft_for(intent, RecordStatus::Blocked, observed, at, Some(reason));
        let _sealed = self.ledger.append(draft);
        InterceptorOutcome::Block { reason }
    }

    /// Records an engine refusal before returning it.
    fn refuse(
        &mut self,
        intent: &ActionIntent,
        reason: BlockReason,
        now: UnixSeconds,
    ) -> InterceptorOutcome {
        let observed = self.killswitch.state();
        let draft = draft_for(intent, RecordStatus::Blocked, observed, now, Some(reason));
        match self.ledger.append(draft) {
            Ok(_) => InterceptorOutcome::Block { reason },
            Err(error) => self.escalate_audit_failure(&error),
        }
    }

    /// Halts on an unrecordable decision and reports why.
    fn escalate_audit_failure(&mut self, error: &LedgerError) -> InterceptorOutcome {
        let reason = block_reason_for(error);
        if let Some(halt) = halt_reason_for(reason) {
            let at = self.last_known_time();
            self.killswitch.engage(at, halt);
        }
        InterceptorOutcome::Block { reason }
    }

    /// Chooses the candidate outcome and the status that will be recorded.
    fn plan(
        &mut self,
        intent: &ActionIntent,
        required: RequiredApproval,
        now: UnixSeconds,
    ) -> Result<(InterceptorOutcome, RecordStatus), BlockReason> {
        match required {
            RequiredApproval::None => Ok((InterceptorOutcome::Allow, RecordStatus::Approved)),
            RequiredApproval::MonitoredNotice => Ok((
                InterceptorOutcome::Warn {
                    code: WarningCode::MonitoredTierB,
                },
                RecordStatus::Approved,
            )),
            RequiredApproval::SingleChecker | RequiredApproval::DualDistinctCheckers => {
                let ticket = self.open_ticket(intent, required, now)?;
                Ok((
                    InterceptorOutcome::RequireApproval(ticket),
                    RecordStatus::PendingApproval,
                ))
            }
        }
    }

    /// Opens and registers an approval ticket for a held action.
    fn open_ticket(
        &mut self,
        intent: &ActionIntent,
        required: RequiredApproval,
        now: UnixSeconds,
    ) -> Result<ApprovalTicket, BlockReason> {
        let ttl = match intent.oversight() {
            OversightClass::Standard => self.config.approval_ttl,
            OversightClass::AnnexIiiBiometric => self.config.annex_iii_ttl,
        };
        let deadline = Deadline::open(now, ttl).map_err(|_| BlockReason::DeadlineOverflow)?;
        let request_id = RequestId::from_identity(*intent.id().identity());
        let ticket = ApprovalTicket::new(
            request_id,
            *intent.maker(),
            *intent.agent(),
            intent.action(),
            required,
            deadline,
        );
        self.registry
            .insert(ticket, now)
            .map_err(registry_block_reason)?;
        Ok(ticket)
    }

    /// Seals the decision before releasing it. A seal failure discards the
    /// candidate outcome, releases any hold it opened, and blocks; nothing is
    /// released unaudited and no dead hold survives to consume the bound.
    fn seal_and_release(
        &mut self,
        intent: &ActionIntent,
        candidate: InterceptorOutcome,
        status: RecordStatus,
        now: UnixSeconds,
    ) -> InterceptorOutcome {
        let observed = self.killswitch.state();
        let draft = draft_for(intent, status, observed, now, None);
        match self.ledger.append(draft) {
            Ok(_) => candidate,
            Err(error) => {
                if let Some(ticket) = candidate.ticket() {
                    let held = *ticket.request_id();
                    let _released = self.registry.release(&held);
                }
                self.escalate_audit_failure(&error)
            }
        }
    }

    /// Records a checker decision on a held request.
    ///
    /// The maker the panel is separated from is the one the engine issued the
    /// ticket for, taken from the registry, never one the caller supplies. The
    /// decision time is the engine's own clock reading, never a caller value.
    ///
    /// # Errors
    ///
    /// Returns [`JustitiaError`] when the system is halted, the clock is
    /// unusable, the request is unknown or already decided, the approval window
    /// has closed, the panel includes the maker or is undersized, or the
    /// decision cannot be sealed.
    pub fn adjudicate(
        &mut self,
        request: &RequestId,
        panel: CheckerSet,
        vote: Vote,
    ) -> Result<Adjudication, JustitiaError> {
        if self.killswitch.is_engaged() {
            return Err(OversightError::SystemHalted.into());
        }
        let now = match self.now() {
            Ok(now) => now,
            Err(error) => {
                self.killswitch
                    .engage(self.last_known_time(), HaltReason::ClockUnavailable);
                return Err(error.into());
            }
        };
        let ticket = self.registry.pending(request).map_err(map_registry)?;
        if ticket.deadline().status(now) == DeadlineStatus::Closed {
            return Err(OversightError::ApprovalExpired.into());
        }
        let verified = Self::verify_panel(&ticket, panel)?;
        self.record_vote(&ticket, verified, vote, now)
    }

    /// Proves the panel against the registered maker and the required approval.
    fn verify_panel(
        ticket: &ApprovalTicket,
        panel: CheckerSet,
    ) -> Result<VerifiedCheckerSet, JustitiaError> {
        let verified = panel.verify_against_maker(ticket.maker())?;
        verified.satisfies(ticket.required())?;
        Ok(verified)
    }

    /// Marks the request terminal and seals the decision.
    ///
    /// The append is the commit point, exactly as it is in
    /// [`Self::seal_and_release`]. If it fails there is nowhere to put the
    /// vote, so the decision must not be left half-applied: the hold is
    /// released outright and the halt latch engages. A human decision is
    /// therefore either in the chain or the unit is visibly halted, and the
    /// registry is never left believing a lost decision was taken.
    fn record_vote(
        &mut self,
        ticket: &ApprovalTicket,
        verified: VerifiedCheckerSet,
        vote: Vote,
        now: UnixSeconds,
    ) -> Result<Adjudication, JustitiaError> {
        let status = match vote {
            Vote::Approve => RecordStatus::Approved,
            Vote::Reject => RecordStatus::Rejected,
        };
        self.registry
            .mark_decided(ticket.request_id(), status)
            .map_err(map_registry)?;
        let by = verified.primary();
        let draft = RecordDraft {
            intent_id: IntentId::from_identity(*ticket.request_id().identity()),
            agent: *ticket.agent(),
            action_type: ticket.action(),
            status,
            block_reason: None,
            killswitch: self.killswitch.state(),
            at: now,
        };
        if let Err(error) = self.ledger.append(draft) {
            return Err(self.escalate_unrecorded_vote(ticket.request_id(), &error));
        }
        Ok(match vote {
            Vote::Approve => Adjudication::Approved { by, at: now },
            Vote::Reject => Adjudication::Rejected { by, at: now },
        })
    }

    /// Halts on an unrecordable human decision and reports why.
    ///
    /// The hold is released rather than left marked decided: a vote that is not
    /// in the chain did not happen, and a dead hold would consume the registry
    /// bound for nothing. Every [`LedgerError`] maps to a systemic refusal
    /// through [`block_reason_for`], so this always engages the latch.
    fn escalate_unrecorded_vote(
        &mut self,
        request: &RequestId,
        error: &LedgerError,
    ) -> JustitiaError {
        let _released = self.registry.release(request);
        if let Some(halt) = halt_reason_for(block_reason_for(error)) {
            let at = self.last_known_time();
            self.killswitch.engage(at, halt);
        }
        JustitiaError::Ledger(*error)
    }
}

/// Projects an intent onto the record it will be audited as.
fn draft_for(
    intent: &ActionIntent,
    status: RecordStatus,
    killswitch: KillswitchState,
    at: UnixSeconds,
    block_reason: Option<BlockReason>,
) -> RecordDraft {
    RecordDraft {
        intent_id: *intent.id(),
        agent: *intent.agent(),
        action_type: intent.action(),
        status,
        block_reason,
        killswitch,
        at,
    }
}

/// Maps a ledger failure onto the fail-closed block reason it implies.
fn block_reason_for(error: &LedgerError) -> BlockReason {
    match error {
        LedgerError::NonMonotonicTimestamp { .. } => BlockReason::ClockUnavailable,
        LedgerError::AlgorithmMismatch { .. }
        | LedgerError::PreviousHashMismatch { .. }
        | LedgerError::DigestMismatch { .. }
        | LedgerError::SequenceGap { .. } => BlockReason::LedgerCompromised,
        LedgerError::LengthBoundExceeded { .. }
        | LedgerError::Preimage(_)
        | LedgerError::Hash(_)
        | LedgerError::Sign(_)
        | LedgerError::Sink(_) => BlockReason::AuditUnavailable,
    }
}

/// Maps a refusal onto the systemic halt it implies, if it implies one.
///
/// A per-request refusal (an overflowing window, a saturated registry, a
/// malformed or duplicated request) is not a fault of the unit and must not
/// halt it. A refusal that means the audit path, the clock or the chain itself
/// is unusable is.
const fn halt_reason_for(reason: BlockReason) -> Option<HaltReason> {
    match reason {
        BlockReason::AuditUnavailable => Some(HaltReason::AuditUnavailable),
        BlockReason::ClockUnavailable => Some(HaltReason::ClockUnavailable),
        BlockReason::LedgerCompromised => Some(HaltReason::LedgerCompromised),
        BlockReason::KillswitchEngaged(_)
        | BlockReason::DeadlineOverflow
        | BlockReason::RegistryFull
        | BlockReason::RequestMalformed
        | BlockReason::RequestAlreadyPending => None,
    }
}

/// Maps a registry refusal onto the block reason the caller sees.
const fn registry_block_reason(error: RegistryError) -> BlockReason {
    match error {
        RegistryError::Full { .. } => BlockReason::RegistryFull,
        RegistryError::AlreadyPending => BlockReason::RequestAlreadyPending,
        RegistryError::Unknown | RegistryError::AlreadyDecided => BlockReason::RequestMalformed,
    }
}

/// Maps a registry failure onto the oversight error a human overseer sees.
fn map_registry(error: RegistryError) -> JustitiaError {
    match error {
        RegistryError::Unknown => OversightError::UnknownRequest.into(),
        RegistryError::AlreadyDecided => OversightError::AlreadyDecided.into(),
        RegistryError::AlreadyPending | RegistryError::Full { .. } => {
            JustitiaError::Registry(error)
        }
    }
}
