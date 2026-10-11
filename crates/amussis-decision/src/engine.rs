// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The decision engine.
//!
//! [`DecisionEngine::decide`] is total: it returns an [`InterceptorOutcome`] for
//! every input and has no error channel. A clock fault, a deadline overflow, a
//! saturated registry, a seal failure and a compromised ledger all map to
//! [`InterceptorOutcome::Block`], so there is no path on which a fault degrades
//! into an allow.
//!
//! [`DecisionEngine::adjudicate`] does return a `Result`, because an expired
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
//! # A halt is a record
//!
//! [`DecisionEngine::halt`] engages the latch and writes one record of the
//! halt itself ([`RecordStatus::HaltEngaged`]), which names no action and
//! names the person who halted. The latch is engaged in every case; the call
//! reports whether the record was written.
//! [`DecisionEngine::halt_unnamed`] is the same halt with no person to name.
//! The engine's own halts do the same where they can: a clock fault
//! while adjudicating, a chain that fails its re-walk, a record that could
//! not be written. For the last of these the halt record usually cannot be
//! written either, and the halt then reaches the chain with the next record
//! that is: every record carries the latch state. A clock fault in `decide`
//! writes no halt record of its own, because the refusal it records carries
//! the engaged latch already.
//!
//! The chain holds one halt record per state of the halt: once a record
//! carries the engaged latch, another call of `halt` writes nothing, unless
//! it made the halt stricter (a higher risk level, or a compromised chain
//! found under another reason), which is written as a record of its own.
//!
//! A halt stands at a risk level, written into the latch block of every
//! record: the level [`DecisionEngine::halt`] is given, and for the engine's
//! own halts the level of the action in hand, or [`RiskLevel::HIGHEST`] where
//! there is none.
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
//! After [`DecisionEngine::new`] returns, neither entry point allocates. The
//! registry, the ledger's record list and the sink's record list are reserved
//! to their scalar bounds at construction and refuse a push at the bound;
//! reclamation compacts in place. See the crate documentation and
//! `tests/allocation_bounds.rs`.
//!
//! # Running past the audit window
//!
//! The ledger holds a bounded window of the chain, and a decision that finds
//! the window full cannot be recorded: it blocks and engages the halt latch,
//! as every unrecordable decision does. An engine that runs longer than one
//! window rotates before that point. [`DecisionEngine::audit_room`] is the
//! number of decisions the window still takes; each call of `decide` or
//! `adjudicate` uses at most one. [`DecisionEngine::rotate_ledger`] re-walks
//! the window, has the sink flush, and drops the window. The chain goes on
//! unbroken: the next record links onto the last one dropped.
//!
//! # Continuing a chain in a new engine
//!
//! [`DecisionEngine::continue_from`] builds an engine on a chain an earlier
//! engine value wrote, from the [`ChainAnchor`] of its last stored record.
//! Three things carry over, all read from that record:
//!
//! * the chain position: the first record links to the head digest and
//!   carries the next sequence number;
//! * the time: a clock reading earlier than the head record is a clock fault,
//!   from the first reading on;
//! * the halt latch: an engine that continues a chain that ends halted starts
//!   halted, with the time, reason and risk level the head record carries.
//!
//! Open holds do not carry over. A held action of the earlier engine cannot
//! be adjudicated in the new one; it stays unreleased.
//!
//! # Releasing the halt latch
//!
//! An engine that halted stays halted for its life, and rotating the window
//! changes nothing about that. The one release is
//! [`DecisionEngine::release_halt`], and it works only on an engine that was
//! continued from a chain that ends halted and has not halted anything
//! itself since: a release takes a new engine on the stored chain. The
//! release is one record of its own ([`RecordStatus::HaltReleased`]), and it
//! is the commit point: when the record cannot be written, the engine stays
//! halted. A chain halted as compromised is not released.
//!
//! A release is approved the way an action is. The halt stands at a risk
//! level, and the release asks the approval rule of that level
//! ([`RiskLevel::required_approval`]) with the releasing person in the place
//! of the maker: a level whose actions need no checker is released by that
//! person alone, a level whose actions need one or two checkers is released
//! only with that many, none of them the releasing person. There is no
//! second rule.
//!
//! The release record states that the halt was released and when, the level
//! the halt stood at, the releasing person and the checkers who approved
//! ([`RecordPrincipals`]). A reader of the chain holds the release to the
//! approval rule with that record alone.
//!
//! # Who the records name
//!
//! Every record that decides an action names the maker of the proposal, and
//! the record of a vote names the panel that cast it. The engine writes the
//! identities it was given, byte for byte; it neither hashes them nor reads
//! them. The record of a halt names the person whose call engaged the halt or
//! made it stricter ([`DecisionEngine::halt`]). A halt no person called names
//! nobody: a fault the engine found, or [`DecisionEngine::halt_unnamed`].
//!
//! A halt whose record could not be written, and under which nothing was
//! recorded afterwards, is not in the stored chain. An engine continued from
//! that chain starts armed; the caller of [`DecisionEngine::halt`] is told
//! so by the error the call returns.

use crate::identity::{IntentId, MakerId, RequestId};
use crate::intent::ActionIntent;
use crate::killswitch::{HaltReason, Killswitch, KillswitchState, ReleaseError};
use crate::ledger::anchor::ChainAnchor;
use crate::ledger::hash::{Digest32, LedgerHasher};
use crate::ledger::signer::{RecordSigner, SignerBinding};
use crate::ledger::{
    AuditLedger, IoDeadline, LedgerError, LedgerSink, RecordDraft, RecordPrincipals, RecordStatus,
    RecordSubject,
};
use crate::outcome::{BlockReason, InterceptorOutcome, WarningCode};
use crate::oversight::{
    Adjudication, ApprovalTicket, CheckerSet, OversightError, VerifiedCheckerSet, Vote,
};
use crate::registry::{PendingRegistry, RegistryError};
use crate::risk::{OversightClass, RequiredApproval, RiskLevel};
use crate::time::{Clock, ClockError, Deadline, DeadlineStatus, MonotonicGuard, Ttl, UnixSeconds};
use crate::{DEFAULT_APPROVAL_TTL_SECS, DecisionError, MAX_LEDGER_RECORDS, MAX_PENDING_REQUESTS};

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

/// The decision engine.
#[derive(Debug, Clone)]
pub struct DecisionEngine<H: LedgerHasher, S: RecordSigner, K: LedgerSink, C: Clock> {
    config: EngineConfig,
    killswitch: Killswitch,
    registry: PendingRegistry,
    ledger: AuditLedger<H, S, K>,
    clock: C,
    guard: MonotonicGuard,
    /// Whether a record of the chain carries the halt the latch is engaged
    /// with.
    halt_recorded: bool,
    /// Whether the engaged latch is the one the continued chain handed over,
    /// with no halt of this engine's own on top of it.
    halt_inherited: bool,
    /// The person whose halt no record of the chain names yet: the one whose
    /// call engaged the latch or made it stricter, kept until the record of
    /// the halt is written.
    halt_operator: Option<MakerId>,
}

impl<H: LedgerHasher, S: RecordSigner, K: LedgerSink, C: Clock> DecisionEngine<H, S, K, C> {
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
            halt_recorded: false,
            halt_inherited: false,
            halt_operator: None,
        }
    }

    /// Builds an engine that continues the chain whose last stored record
    /// `anchor` names.
    ///
    /// The engine starts in the halt-latch state the anchor carries, its
    /// clock guard starts at the time of the head record, and its registry
    /// starts empty. See the module documentation.
    #[must_use]
    pub fn continue_from(
        config: EngineConfig,
        signer: SignerBinding<S>,
        sink: K,
        io_deadline: IoDeadline,
        clock: C,
        anchor: &ChainAnchor,
    ) -> Self {
        Self {
            registry: PendingRegistry::with_bound(config.max_pending),
            ledger: AuditLedger::continue_from(
                signer,
                sink,
                io_deadline,
                config.max_audit_records,
                anchor,
            ),
            config,
            killswitch: Killswitch::from_state(anchor.killswitch()),
            clock,
            guard: MonotonicGuard::after(anchor.at()),
            halt_recorded: anchor.killswitch().is_engaged(),
            halt_inherited: anchor.killswitch().is_engaged(),
            halt_operator: None,
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

    /// Engages the halt latch as the stop of the person `operator`, and
    /// writes the halt into the audit chain.
    ///
    /// The latch is engaged in every case, whatever this returns: halting
    /// never itself fails. The time is taken from the engine's own clock,
    /// falling back to the last accepted reading when the clock is the thing
    /// that failed. `level` is the risk level the halt stands at, which its
    /// release is held to; a caller that does not know it gives
    /// [`RiskLevel::HIGHEST`]. An engine that is halted already keeps its
    /// first time and its first reason and is never made weaker: see
    /// [`Killswitch::engage`].
    ///
    /// The record of the halt names `operator` when this call engaged the
    /// latch or made it stricter: the person named is the one whose call the
    /// halt stands on. A call that changes nothing about the halt writes no
    /// record, unless the record of an earlier call is still owed, which it
    /// then writes with the person of that earlier call.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the halt record cannot be written. The
    /// engine is halted all the same. The stored chain does not show the halt
    /// until a later record is written, and does not name `operator` until
    /// this engine is halted again: that call writes the record owed.
    pub fn halt(&mut self, operator: &MakerId, level: RiskLevel) -> Result<(), LedgerError> {
        let at = self.best_effort_now();
        let stricter = self.latch(at, HaltReason::OperatorStop, level);
        if stricter {
            self.halt_operator = Some(*operator);
        }
        self.record_halt()
    }

    /// Engages the halt latch for `reason` with no person to name, and
    /// writes the halt into the audit chain: a fault the caller found, or a
    /// stop whose person the caller cannot name. The record names nobody.
    ///
    /// Everything else is as for [`Self::halt`], which is the call for a
    /// person's stop.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the halt record cannot be written. The
    /// engine is halted all the same, and the stored chain does not show it
    /// until a later record is written: a decision refused under the halt, or
    /// this call repeated.
    pub fn halt_unnamed(
        &mut self,
        reason: HaltReason,
        level: RiskLevel,
    ) -> Result<(), LedgerError> {
        let at = self.best_effort_now();
        self.latch(at, reason, level);
        self.record_halt()
    }

    /// Releases a halt the continued chain handed over, and writes the
    /// release into the audit chain. Returns the digest of that record.
    ///
    /// This is the only release of a halt latch the library has. The record
    /// is the commit point: the latch is armed only once the record is
    /// written.
    ///
    /// The release is held to the approval rule actions are held to, asked
    /// for the risk level the halt stands at, with `releaser` in the place of
    /// the maker. Where that level demands no checker, `releaser` alone
    /// releases and `panel` may be `None`. Where it demands checkers, `panel`
    /// names them, and none of them is `releaser`. A panel given where none
    /// is demanded is still refused when it names `releaser`.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::NotHalted`] for an armed latch,
    /// [`ReleaseError::Compromised`] for a halt with
    /// [`HaltReason::LedgerCompromised`], [`ReleaseError::NotInherited`] when
    /// the halt is not one this engine took over at
    /// [`Self::continue_from`], or when the engine halted again since,
    /// [`ReleaseError::ApprovalMissing`] when the level demands checkers and
    /// no panel is given, [`ReleaseError::Approval`] when the panel names the
    /// releaser or is smaller than the level demands,
    /// [`ReleaseError::Clock`] when the clock is unusable, and
    /// [`ReleaseError::Ledger`] when the record cannot be written. The engine
    /// stays halted in every one of them.
    pub fn release_halt(
        &mut self,
        releaser: &MakerId,
        panel: Option<CheckerSet>,
    ) -> Result<Digest32, ReleaseError> {
        let level = self.releasable_level()?;
        approve_release(level, releaser, panel)?;
        let at = self.now()?;
        let named = RecordPrincipals {
            level,
            maker: *releaser,
            checkers: panel,
        };
        let draft = RecordDraft::of_release(named, at);
        let sealed = self.ledger.append(draft)?;
        self.killswitch = Killswitch::new();
        self.halt_recorded = false;
        self.halt_inherited = false;
        Ok(sealed)
    }

    /// Returns the risk level of the halt when it is one a release may undo.
    fn releasable_level(&self) -> Result<RiskLevel, ReleaseError> {
        let KillswitchState::Engaged { reason, level, .. } = self.killswitch.state() else {
            return Err(ReleaseError::NotHalted);
        };
        if reason == HaltReason::LedgerCompromised {
            return Err(ReleaseError::Compromised);
        }
        if !self.halt_inherited {
            return Err(ReleaseError::NotInherited);
        }
        Ok(level)
    }

    /// Engages the latch as this engine's own halt.
    ///
    /// An inherited halt stops being one here, also when the latch was
    /// engaged already and keeps its first reason: a release must not undo a
    /// halt it does not know of. A halt this call made stricter is one the
    /// chain does not carry yet, and one no earlier person stands for.
    /// Returns whether the call engaged the latch or made it stricter.
    fn latch(&mut self, at: UnixSeconds, reason: HaltReason, level: RiskLevel) -> bool {
        let before = self.killswitch.state();
        self.halt_inherited = false;
        self.killswitch.engage(at, reason, level);
        let stricter = self.killswitch.state() != before;
        if stricter {
            self.halt_recorded = false;
            self.halt_operator = None;
        }
        stricter
    }

    /// Writes the record of the halt, unless the chain carries the halt
    /// already and no person waits to be named for it.
    ///
    /// The record names the person who waits, at the level the halt stands
    /// at when the record is written.
    fn record_halt(&mut self) -> Result<(), LedgerError> {
        if self.halt_recorded && self.halt_operator.is_none() {
            return Ok(());
        }
        let state = self.killswitch.state();
        let at = self.last_known_time();
        let draft = match (self.halt_operator, state) {
            (Some(maker), KillswitchState::Engaged { level, .. }) => {
                let operator = RecordPrincipals {
                    level,
                    maker,
                    checkers: None,
                };
                RecordDraft::of_halt_by(state, operator, at)
            }
            _ => RecordDraft::of_halt(state, at),
        };
        self.append(&draft)?;
        self.halt_operator = None;
        Ok(())
    }

    /// Engages the latch for a fault the engine found itself and writes the
    /// halt record where that is possible.
    fn halt_on_fault(&mut self, reason: HaltReason, level: RiskLevel) {
        let _stricter = self.latch(self.last_known_time(), reason, level);
        // The fault is often the audit path itself, and then this record
        // cannot be written either. The latch is engaged all the same, and
        // the next record that is written carries it.
        let _unrecorded = self.record_halt();
    }

    /// Seals `draft`, and notes when the chain then carries the halt.
    fn append(&mut self, draft: &RecordDraft) -> Result<Digest32, LedgerError> {
        let sealed = self.ledger.append(*draft)?;
        if draft.killswitch.is_engaged() {
            self.halt_recorded = true;
        }
        Ok(sealed)
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
                self.halt_on_fault(HaltReason::LedgerCompromised, RiskLevel::HIGHEST);
                Err(error)
            }
        }
    }

    /// Returns how many more decisions the audit window takes.
    ///
    /// At zero the next decision cannot be recorded: it blocks and engages
    /// the halt latch. A caller that calls [`Self::rotate_ledger`] while this
    /// is above zero never reaches that point. A halt and a release use one
    /// record each, as a decision does.
    #[must_use]
    pub fn audit_room(&self) -> usize {
        self.ledger.remaining()
    }

    /// Drops the audit window once it has been re-walked and the sink has
    /// flushed, and returns the number of records dropped.
    ///
    /// The halt latch is not touched by a rotation that succeeds: a halted
    /// engine stays halted.
    ///
    /// # Errors
    ///
    /// Returns the first broken link of the window, having first engaged the
    /// halt latch with [`HaltReason::LedgerCompromised`], or
    /// [`LedgerError::Sink`] when the sink cannot flush. A failed flush keeps
    /// the window and does not halt: no decision is lost by it, and a
    /// decision that then finds the window full halts as before.
    pub fn rotate_ledger(&mut self) -> Result<usize, LedgerError> {
        let rotated = self.ledger.rotate();
        if let Err(error) = &rotated
            && block_reason_for(error) == BlockReason::LedgerCompromised
        {
            self.halt_on_fault(HaltReason::LedgerCompromised, RiskLevel::HIGHEST);
        }
        rotated
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
        let required = intent.level().required_approval();
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
        let _sealed = self.append(&draft);
        InterceptorOutcome::Block { reason }
    }

    /// Fails closed on a clock fault: halts, records, and blocks.
    fn refuse_clock_fault(&mut self, intent: &ActionIntent) -> InterceptorOutcome {
        let at = self.last_known_time();
        self.latch(at, HaltReason::ClockUnavailable, intent.level());
        let reason = BlockReason::ClockUnavailable;
        let observed = self.killswitch.state();
        let draft = draft_for(intent, RecordStatus::Blocked, observed, at, Some(reason));
        // The refusal carries the engaged latch, so it is the record of this
        // halt as well; no halt record is written beside it.
        let _sealed = self.append(&draft);
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
        match self.append(&draft) {
            Ok(_) => InterceptorOutcome::Block { reason },
            Err(error) => self.escalate_audit_failure(&error, intent.level()),
        }
    }

    /// Halts on an unrecordable decision, at the level of the action it was
    /// taken on, and reports why.
    fn escalate_audit_failure(
        &mut self,
        error: &LedgerError,
        level: RiskLevel,
    ) -> InterceptorOutcome {
        let reason = block_reason_for(error);
        if let Some(halt) = halt_reason_for(reason) {
            self.halt_on_fault(halt, level);
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
                let ticket = self.open_ticket(intent, now)?;
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
            intent.level(),
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
        match self.append(&draft) {
            Ok(_) => candidate,
            Err(error) => {
                if let Some(ticket) = candidate.ticket() {
                    let held = *ticket.request_id();
                    let _released = self.registry.release(&held);
                }
                self.escalate_audit_failure(&error, intent.level())
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
    /// Returns [`DecisionError`] when the system is halted, the clock is
    /// unusable, the request is unknown or already decided, the approval window
    /// has closed, the panel includes the maker or is undersized, or the
    /// decision cannot be sealed.
    pub fn adjudicate(
        &mut self,
        request: &RequestId,
        panel: CheckerSet,
        vote: Vote,
    ) -> Result<Adjudication, DecisionError> {
        if self.killswitch.is_engaged() {
            return Err(OversightError::SystemHalted.into());
        }
        let now = match self.now() {
            Ok(now) => now,
            Err(error) => {
                // The level of the held action, or the highest when the
                // request names none.
                let level = self
                    .registry
                    .pending(request)
                    .map_or(RiskLevel::HIGHEST, |held| held.level());
                self.halt_on_fault(HaltReason::ClockUnavailable, level);
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
    ) -> Result<VerifiedCheckerSet, DecisionError> {
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
    ) -> Result<Adjudication, DecisionError> {
        let status = match vote {
            Vote::Approve => RecordStatus::Approved,
            Vote::Reject => RecordStatus::Rejected,
        };
        self.registry
            .mark_decided(ticket.request_id(), status)
            .map_err(map_registry)?;
        let by = verified.primary();
        let draft = RecordDraft {
            subject: Some(RecordSubject {
                intent_id: IntentId::from_identity(*ticket.request_id().identity()),
                agent: *ticket.agent(),
                action_type: ticket.action(),
            }),
            principals: Some(RecordPrincipals {
                level: ticket.level(),
                maker: *ticket.maker(),
                checkers: Some(verified.panel()),
            }),
            status,
            block_reason: None,
            killswitch: self.killswitch.state(),
            at: now,
        };
        if let Err(error) = self.append(&draft) {
            return Err(self.escalate_unrecorded_vote(ticket, &error));
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
        ticket: &ApprovalTicket,
        error: &LedgerError,
    ) -> DecisionError {
        let _released = self.registry.release(ticket.request_id());
        if let Some(halt) = halt_reason_for(block_reason_for(error)) {
            self.halt_on_fault(halt, ticket.level());
        }
        DecisionError::Ledger(*error)
    }
}

/// Holds the release of a halt to the approval rule of its level, with the
/// releasing person in the place of the maker.
fn approve_release(
    level: RiskLevel,
    releaser: &MakerId,
    panel: Option<CheckerSet>,
) -> Result<(), ReleaseError> {
    let required = level.required_approval();
    match panel {
        Some(panel) => {
            let verified = panel.verify_against_maker(releaser)?;
            if required.needs_human() {
                verified.satisfies(required)?;
            }
            Ok(())
        }
        None if required.needs_human() => Err(ReleaseError::ApprovalMissing { required }),
        None => Ok(()),
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
        subject: Some(RecordSubject {
            intent_id: *intent.id(),
            agent: *intent.agent(),
            action_type: intent.action(),
        }),
        principals: Some(RecordPrincipals {
            level: intent.level(),
            maker: *intent.maker(),
            checkers: None,
        }),
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
fn map_registry(error: RegistryError) -> DecisionError {
    match error {
        RegistryError::Unknown => OversightError::UnknownRequest.into(),
        RegistryError::AlreadyDecided => OversightError::AlreadyDecided.into(),
        RegistryError::AlreadyPending | RegistryError::Full { .. } => {
            DecisionError::Registry(error)
        }
    }
}
