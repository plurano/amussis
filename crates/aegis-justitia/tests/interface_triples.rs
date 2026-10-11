// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! HISS-15: an explicit positive, negative and boundary case for every public
//! interface that epics E02-2 and E02-3 do not already name.

mod common;

use aegis_justitia::{
    ActionIntent, ActionType, AgentId, ApprovalTicket, CheckerId, CheckerSet, Clock, ClockError,
    Deadline, DeadlineError, DeadlineStatus, Digest32, FixedClock, HaltReason, HashError, Identity,
    IdentityError, InMemorySink, IntentError, IntentId, IntentSpec, IoDeadline, JustitiaError,
    Killswitch, KillswitchState, LedgerSink, MAX_IDENTITY_LEN, MAX_SIGNATURE_BYTES, MAX_TARGET_LEN,
    MakerId, MonotonicGuard, OversightClass, OversightError, PendingRegistry, RecordStatus,
    RegistryError, RequestId, RequestState, RequiredApproval, RiskTier, SignError, Signature,
    SignerBinding, SignerKeyId, SinkError, TargetResource, Ttl, UnavailableSink, UnixSeconds,
};

use common::{FIXTURE_AUDIT_BOUND, Fallible, FixtureError, FixtureSigner, io_deadline};

// --- Identity -------------------------------------------------------------

/// Identity: one byte is accepted, the bound is accepted, one past it is
/// refused, and nothing is ever truncated or sanitised.
#[test]
fn identity_positive_negative_and_boundary() -> Fallible<()> {
    let one = Identity::parse("a")?;
    assert_eq!(one.len(), 1);
    assert_eq!(one.as_bytes(), b"a");

    let at_bound = "x".repeat(MAX_IDENTITY_LEN);
    let bounded = Identity::parse(&at_bound)?;
    assert_eq!(bounded.len(), MAX_IDENTITY_LEN);

    let past_bound = "x".repeat(MAX_IDENTITY_LEN.saturating_add(1));
    assert_eq!(
        Identity::parse(&past_bound),
        Err(IdentityError::TooLong {
            max: MAX_IDENTITY_LEN,
            actual: MAX_IDENTITY_LEN.saturating_add(1)
        }),
        "an over-long identity is refused, never truncated to the bound"
    );
    assert_eq!(Identity::parse(""), Err(IdentityError::Empty));
    assert_eq!(Identity::parse("bad name"), Err(IdentityError::Charset));
    assert_eq!(Identity::parse("bad\0name"), Err(IdentityError::Charset));
    assert_eq!(Identity::parse("ok.name-1_2:3@4/5")?.len(), 17);
    assert_eq!(Identity::parse("round-trip")?.to_string(), "round-trip");
    Ok(())
}

/// Role wrappers keep a maker and a checker apart at the type level, and the
/// only cross-role comparison is explicit.
#[test]
fn role_wrappers_positive_negative_and_boundary() -> Fallible<()> {
    let maker = MakerId::parse("principal-a")?;
    assert!(maker.is_same_principal(&CheckerId::parse("principal-a")?));
    assert!(!maker.is_same_principal(&CheckerId::parse("principal-b")?));
    assert_eq!(MakerId::parse(""), Err(IdentityError::Empty));
    assert_eq!(
        RequestId::parse("r")?.identity(),
        &Identity::parse("r")?,
        "a role wrapper carries the untagged identity unchanged"
    );
    Ok(())
}

/// Target resources carry their own, larger bound.
#[test]
fn target_resource_positive_negative_and_boundary() -> Fallible<()> {
    assert_eq!(TargetResource::parse("/etc/aegis")?.len(), 10);
    let at_bound = "y".repeat(MAX_TARGET_LEN);
    assert_eq!(TargetResource::parse(&at_bound)?.len(), MAX_TARGET_LEN);
    assert_eq!(
        TargetResource::parse(&"y".repeat(MAX_TARGET_LEN.saturating_add(1))),
        Err(IdentityError::TooLong {
            max: MAX_TARGET_LEN,
            actual: MAX_TARGET_LEN.saturating_add(1)
        })
    );
    Ok(())
}

// --- Deadlines and clocks --------------------------------------------------

/// Deadline: 1299 is open, 1300 is closed, 1301 is closed, and a window that
/// would overflow is refused rather than wrapped.
#[test]
fn deadline_positive_negative_and_boundary() -> Fallible<()> {
    let ttl = Ttl::from_secs(300).ok_or(FixtureError::BadConstant("fixture value"))?;
    let window = Deadline::open(UnixSeconds::new(1_000), ttl)?;
    assert_eq!(window.opened_at().get(), 1_000);
    assert_eq!(window.due_at().get(), 1_300);
    assert_eq!(window.status(UnixSeconds::new(1_299)), DeadlineStatus::Open);
    assert_eq!(
        window.status(UnixSeconds::new(1_300)),
        DeadlineStatus::Closed,
        "now equal to the due time is closed"
    );
    assert_eq!(
        window.status(UnixSeconds::new(1_301)),
        DeadlineStatus::Closed
    );

    assert_eq!(
        Deadline::open(UnixSeconds::new(u64::MAX), ttl),
        Err(DeadlineError::Overflow),
        "the window addition is checked and never wraps"
    );
    assert_eq!(
        Ttl::from_secs(0),
        None,
        "a zero-width window cannot be built"
    );
    assert_eq!(
        Ttl::from_secs(1)
            .ok_or(FixtureError::BadConstant("fixture value"))?
            .seconds(),
        1,
        "one second is the smallest representable window"
    );
    Ok(())
}

/// A fixed clock reports exactly what it was pinned to, and can be moved.
#[test]
fn fixed_clock_positive_negative_and_boundary() -> Fallible<()> {
    let mut clock = FixedClock::new(UnixSeconds::new(42));
    assert_eq!(clock.now()?, UnixSeconds::new(42));
    assert_eq!(clock.at(), UnixSeconds::new(42));
    clock.set(UnixSeconds::new(43));
    assert_eq!(clock.now()?, UnixSeconds::new(43));
    clock.set(UnixSeconds::new(1));
    assert_eq!(
        clock.now()?,
        UnixSeconds::new(1),
        "the clock itself reports a backwards step; the guard, not the clock, refuses it"
    );
    assert_eq!(FixedClock::new(UnixSeconds::EPOCH).now()?.get(), 0);
    assert_eq!(
        FixedClock::new(UnixSeconds::new(u64::MAX)).now()?.get(),
        u64::MAX
    );
    Ok(())
}

/// The monotonic guard accepts a forward step, accepts an equal reading, and
/// refuses a backwards one. It is the only producer of `ClockError::NonMonotonic`.
#[test]
fn monotonic_guard_positive_negative_and_boundary() -> Fallible<()> {
    let mut guard = MonotonicGuard::new();
    assert_eq!(guard.last(), None);
    assert_eq!(guard.observe(UnixSeconds::new(10))?, UnixSeconds::new(10));
    assert_eq!(guard.last(), Some(UnixSeconds::new(10)));
    assert_eq!(guard.observe(UnixSeconds::new(11))?, UnixSeconds::new(11));

    assert_eq!(
        guard.observe(UnixSeconds::new(11))?,
        UnixSeconds::new(11),
        "the boundary reading, equal to the last one, is not a fault"
    );
    assert_eq!(
        guard.observe(UnixSeconds::new(10)),
        Err(ClockError::NonMonotonic {
            last: 11,
            observed: 10
        }),
        "one second before the last reading is a fault"
    );
    assert_eq!(
        guard.last(),
        Some(UnixSeconds::new(11)),
        "a refused reading does not become the new baseline"
    );
    assert_eq!(
        MonotonicGuard::default().observe(UnixSeconds::EPOCH)?,
        UnixSeconds::EPOCH,
        "the first reading is always accepted, the epoch included"
    );
    Ok(())
}

// --- Checker panels --------------------------------------------------------

/// A checker panel is refused when it duplicates a principal, and a verified
/// panel refuses the maker in either slot.
#[test]
fn checker_sets_positive_negative_and_boundary() -> Fallible<()> {
    let maker = MakerId::parse("maker-a")?;
    let bob = CheckerId::parse("checker-b")?;
    let carol = CheckerId::parse("checker-c")?;
    let maker_as_checker = CheckerId::parse("maker-a")?;

    let dual = CheckerSet::dual(bob, carol)?;
    assert_eq!(dual.len(), 2);
    let verified = dual.verify_against_maker(&maker)?;
    assert_eq!(verified.primary(), bob);
    verified.satisfies(RequiredApproval::DualDistinctCheckers)?;
    verified.satisfies(RequiredApproval::SingleChecker)?;

    assert_eq!(
        CheckerSet::dual(bob, bob),
        Err(OversightError::DuplicateChecker)
    );
    assert_eq!(
        CheckerSet::dual(bob, maker_as_checker)?.verify_against_maker(&maker),
        Err(OversightError::MakerIsChecker),
        "the maker must be caught in the second slot, not only the first"
    );
    assert_eq!(
        CheckerSet::dual(maker_as_checker, bob)?.verify_against_maker(&maker),
        Err(OversightError::MakerIsChecker)
    );

    let single = CheckerSet::single(bob).verify_against_maker(&maker)?;
    assert_eq!(
        single.satisfies(RequiredApproval::DualDistinctCheckers),
        Err(OversightError::AnnexIiiRequiresTwoCheckers),
        "there is no under-load fallback to a single checker"
    );
    assert_eq!(
        single.satisfies(RequiredApproval::None),
        Err(OversightError::NoApprovalRequired)
    );
    Ok(())
}

// --- Killswitch ------------------------------------------------------------

/// The latch is one-way and idempotent: re-engaging keeps the first reason.
#[test]
fn killswitch_positive_negative_and_boundary() {
    let mut latch = Killswitch::new();
    assert!(!latch.is_engaged());
    assert_eq!(latch.state(), KillswitchState::Armed);
    assert_eq!(latch.state().reason(), None);

    latch.engage(UnixSeconds::new(10), HaltReason::OperatorStop);
    assert!(latch.is_engaged());
    assert_eq!(latch.state().reason(), Some(HaltReason::OperatorStop));

    latch.engage(UnixSeconds::new(20), HaltReason::LedgerCompromised);
    assert_eq!(
        latch.state(),
        KillswitchState::Engaged {
            at: UnixSeconds::new(10),
            reason: HaltReason::OperatorStop
        },
        "a second engage keeps the first time and reason"
    );
    assert_eq!(latch.state().engaged_at(), Some(UnixSeconds::new(10)));
}

// --- Classification --------------------------------------------------------

/// The full classification table is asserted, including the boundary where the
/// oversight class dominates the tier.
#[test]
fn required_approval_table_is_total() {
    assert_eq!(
        RequiredApproval::for_action(RiskTier::TierCRoutineBounded, OversightClass::Standard),
        RequiredApproval::None
    );
    assert_eq!(
        RequiredApproval::for_action(RiskTier::TierBMaterialReversible, OversightClass::Standard),
        RequiredApproval::MonitoredNotice
    );
    assert_eq!(
        RequiredApproval::for_action(RiskTier::TierAConsequential, OversightClass::Standard),
        RequiredApproval::SingleChecker
    );
}

/// The boundary of the classification table: the oversight class dominates the
/// tier, so Annex III demands two checkers even at Tier C.
#[test]
fn annex_iii_escalates_at_every_tier() {
    for tier in [
        RiskTier::TierCRoutineBounded,
        RiskTier::TierBMaterialReversible,
        RiskTier::TierAConsequential,
    ] {
        assert_eq!(
            RequiredApproval::for_action(tier, OversightClass::AnnexIiiBiometric),
            RequiredApproval::DualDistinctCheckers,
            "an Annex III use escalates at classification time, at every tier"
        );
    }
    assert_eq!(RequiredApproval::None.checker_count(), 0);
    assert!(!RequiredApproval::MonitoredNotice.needs_human());
    assert!(RequiredApproval::SingleChecker.needs_human());
    assert_eq!(RequiredApproval::DualDistinctCheckers.checker_count(), 2);
    assert!(RiskTier::TierCRoutineBounded < RiskTier::TierAConsequential);
}

/// The action-type floor resolves upward only.
#[test]
fn action_type_floor_resolves_upward() -> Fallible<()> {
    assert_eq!(
        ActionType::FileModification.minimum_tier(),
        RiskTier::TierCRoutineBounded
    );
    assert_eq!(
        ActionType::FileDeletion.minimum_tier(),
        RiskTier::TierAConsequential
    );
    let spec = IntentSpec {
        id: IntentId::parse("intent-floor")?,
        agent: AgentId::parse("agent-01")?,
        maker: MakerId::parse("maker-a")?,
        action: ActionType::SystemConfigChange,
        declared_tier: RiskTier::TierCRoutineBounded,
        oversight: OversightClass::Standard,
        target: TargetResource::parse("/etc/aegis")?,
    };
    assert_eq!(
        ActionIntent::new(spec),
        Err(IntentError::TierDowngrade {
            declared: RiskTier::TierCRoutineBounded,
            minimum: RiskTier::TierAConsequential
        })
    );
    let raised = IntentSpec {
        declared_tier: RiskTier::TierAConsequential,
        ..spec
    };
    assert_eq!(
        ActionIntent::new(raised)?.effective_tier(),
        RiskTier::TierAConsequential
    );
    let network = IntentSpec {
        action: ActionType::ExternalNetworkRequest,
        declared_tier: RiskTier::TierBMaterialReversible,
        ..spec
    };
    assert_eq!(
        ActionIntent::new(network)?.effective_tier(),
        RiskTier::TierBMaterialReversible,
        "a declared tier above the floor is kept"
    );
    Ok(())
}

// --- Digests ---------------------------------------------------------------

/// Digest parsing accepts exactly one lower-case 64-character digest.
#[test]
fn digest_hex_positive_negative_and_boundary() -> Fallible<()> {
    let text = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    let digest = Digest32::parse_hex(text)?;
    assert_eq!(digest.to_string(), text);
    let mut buffer = [0u8; 64];
    assert_eq!(digest.encode_hex(&mut buffer)?, text);

    assert_eq!(
        Digest32::parse_hex(""),
        Err(HashError::Width {
            expected: 32,
            actual: 0
        })
    );
    assert_eq!(Digest32::parse_hex("zz"), Err(HashError::Encoding));
    assert_eq!(
        Digest32::parse_hex(&text.to_uppercase()),
        Err(HashError::Encoding),
        "only lower-case hexadecimal is admitted"
    );
    assert_eq!(
        Digest32::parse_hex(&format!("{text}00")),
        Err(HashError::Encoding),
        "a digest one byte too long is refused"
    );
    assert_eq!(Digest32::parse_hex(&"0".repeat(64))?, Digest32::GENESIS);
    Ok(())
}

// --- Signatures ------------------------------------------------------------

/// A signature is bounded and is never truncated.
#[test]
fn signature_positive_negative_and_boundary() -> Fallible<()> {
    let key = SignerKeyId::parse("key-a")?;
    let short = Signature::new(key, b"abc")?;
    assert_eq!(short.len(), 3);
    assert_eq!(short.as_bytes(), b"abc");
    assert_eq!(short.key_id(), &key);

    let at_bound = vec![0x5au8; MAX_SIGNATURE_BYTES];
    assert_eq!(Signature::new(key, &at_bound)?.len(), MAX_SIGNATURE_BYTES);

    let past_bound = vec![0x5au8; MAX_SIGNATURE_BYTES.saturating_add(1)];
    assert_eq!(
        Signature::new(key, &past_bound),
        Err(SignError::TooLong {
            max: MAX_SIGNATURE_BYTES,
            actual: MAX_SIGNATURE_BYTES.saturating_add(1)
        })
    );
    let empty = Signature::new(key, b"")?;
    assert!(empty.is_empty());
    Ok(())
}

/// An unbound signer binding always errors; that is the M20 deferral proof.
#[test]
fn signer_binding_positive_negative_and_boundary() -> Fallible<()> {
    let bound: SignerBinding<FixtureSigner> = SignerBinding::Bound(FixtureSigner::new()?);
    assert!(bound.is_bound());
    assert!(bound.sign(&Digest32::GENESIS).is_ok());

    let unbound: SignerBinding<FixtureSigner> = SignerBinding::unbound();
    assert!(!unbound.is_bound());
    assert_eq!(
        unbound.sign(&Digest32::GENESIS),
        Err(SignError::Unavailable)
    );
    Ok(())
}

// --- Pending registry ------------------------------------------------------

/// Builds a fixture approval ticket for `id`, opened at 1000 for `ttl_secs`.
fn fixture_ticket(id: &str, ttl_secs: u32) -> Fallible<ApprovalTicket> {
    let ttl = Ttl::from_secs(ttl_secs).ok_or(FixtureError::BadConstant("ttl"))?;
    Ok(ApprovalTicket::new(
        RequestId::parse(id)?,
        MakerId::parse("maker-a")?,
        AgentId::parse("agent-01")?,
        ActionType::PermissionEscalation,
        RequiredApproval::SingleChecker,
        Deadline::open(UnixSeconds::new(1_000), ttl)?,
    ))
}

/// The registry holds, bounds and labels: a live duplicate is a duplicate and a
/// distinct request past the bound is full.
#[test]
fn pending_registry_positive_negative_and_boundary() -> Fallible<()> {
    let now = UnixSeconds::new(1_000);
    let first = fixture_ticket("request-1", 60)?;
    let second = fixture_ticket("request-2", 60)?;

    let mut registry = PendingRegistry::with_bound(1);
    assert!(registry.is_empty());
    assert_eq!(registry.bound(), 1);
    registry.insert(first, now)?;
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.live(now), 1);
    assert_eq!(registry.pending(first.request_id())?, first);

    assert_eq!(
        registry.insert(first, now),
        Err(RegistryError::AlreadyPending),
        "a second insert of a still-pending identifier is a duplicate, not a decision"
    );
    assert_eq!(
        registry.insert(second, now),
        Err(RegistryError::Full { limit: 1 }),
        "a distinct request is refused at a bound of one"
    );
    assert_eq!(
        registry.pending(second.request_id()),
        Err(RegistryError::Unknown)
    );
    Ok(())
}

/// A decided entry stays queryable until it is reclaimed, then frees the bound.
#[test]
fn pending_registry_decision_reclaims_the_bound() -> Fallible<()> {
    let now = UnixSeconds::new(1_000);
    let first = fixture_ticket("request-1", 60)?;
    let second = fixture_ticket("request-2", 60)?;
    let mut registry = PendingRegistry::with_bound(1);
    registry.insert(first, now)?;

    registry.mark_decided(first.request_id(), RecordStatus::Approved)?;
    assert_eq!(
        registry.get(first.request_id())?.1,
        RequestState::Decided(RecordStatus::Approved)
    );
    assert_eq!(
        registry.pending(first.request_id()),
        Err(RegistryError::AlreadyDecided)
    );
    assert_eq!(
        registry.mark_decided(first.request_id(), RecordStatus::Rejected),
        Err(RegistryError::AlreadyDecided)
    );
    assert_eq!(registry.live(now), 0, "a decided entry is no longer live");

    registry.insert(second, now)?;
    assert_eq!(
        registry.len(),
        1,
        "the decided entry was reclaimed to make room, so the bound held"
    );
    assert_eq!(
        registry.pending(first.request_id()),
        Err(RegistryError::Unknown),
        "the reclaimed entry is gone, so a retry of that identifier is free"
    );
    Ok(())
}

/// Reclamation drops expired entries at the closed boundary, not one second
/// later, and `release` drops a live entry outright.
#[test]
fn registry_reclamation_positive_negative_and_boundary() -> Fallible<()> {
    let opened = UnixSeconds::new(1_000);
    let held = fixture_ticket("request-expiry", 10)?;
    assert_eq!(held.deadline().due_at().get(), 1_010);

    let mut registry = PendingRegistry::with_bound(4);
    registry.insert(held, opened)?;
    assert_eq!(
        registry.reclaim(UnixSeconds::new(1_009)),
        0,
        "one second before the due time the window is still open"
    );
    assert_eq!(registry.len(), 1);
    assert_eq!(
        registry.reclaim(UnixSeconds::new(1_010)),
        1,
        "now equal to the due time is closed, so the entry is reclaimed"
    );
    assert!(registry.is_empty());
    assert_eq!(
        registry.reclaim(UnixSeconds::new(2_000)),
        0,
        "reclaiming an empty registry drops nothing"
    );

    registry.insert(held, opened)?;
    assert_eq!(registry.release(held.request_id())?, held);
    assert_eq!(
        registry.release(held.request_id()),
        Err(RegistryError::Unknown),
        "releasing twice is refused"
    );
    Ok(())
}

// --- Sinks -----------------------------------------------------------------

/// The in-memory sink is bounded, refuses a record past its bound, refuses a
/// deadline shorter than its service time, and never reallocates.
#[test]
fn in_memory_sink_positive_negative_and_boundary() -> Fallible<()> {
    let mut ledger: aegis_justitia::AuditLedger<
        aegis_justitia::Sha256Hasher,
        FixtureSigner,
        InMemorySink,
    > = aegis_justitia::AuditLedger::with_bound(
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(1),
        io_deadline(),
        FIXTURE_AUDIT_BOUND,
    );
    let draft = |id: &str, at: u64| -> Result<aegis_justitia::RecordDraft, JustitiaError> {
        Ok(aegis_justitia::RecordDraft {
            intent_id: IntentId::parse(id)?,
            agent: AgentId::parse("agent-01")?,
            action_type: ActionType::FileModification,
            status: RecordStatus::Approved,
            block_reason: None,
            killswitch: KillswitchState::Armed,
            at: UnixSeconds::new(at),
        })
    };
    ledger.append(draft("intent-1", 100)?)?;
    assert_eq!(
        ledger.append(draft("intent-2", 101)?),
        Err(aegis_justitia::LedgerError::Sink(SinkError::Full {
            max: 1
        })),
        "a full sink refuses the record and the ledger commits nothing"
    );
    assert_eq!(ledger.len(), 1, "the refused record was not committed");
    assert_eq!(
        ledger.sink().reserved(),
        ledger.sink().bound(),
        "the sink reserved its bound once and never grew"
    );

    let mut sink = InMemorySink::with_bound(0);
    assert_eq!(sink.syncs(), 0);
    sink.sync(io_deadline())?;
    assert_eq!(sink.syncs(), 1);
    assert_eq!(IoDeadline::try_from_millis(0), None);
    assert_eq!(
        IoDeadline::try_from_millis(1)
            .ok_or(FixtureError::BadConstant("io deadline"))?
            .millis(),
        1
    );
    Ok(())
}

/// The sink honours the HISS-02 deadline: exactly its service time is accepted,
/// one millisecond less is refused rather than allowed to block.
#[test]
fn sink_service_time_positive_negative_and_boundary() -> Fallible<()> {
    let service = IoDeadline::try_from_millis(5).ok_or(FixtureError::BadConstant("service"))?;
    let mut sink = InMemorySink::with_service_time(4, service);
    assert_eq!(sink.service_time().millis(), 5);

    let at_bound = IoDeadline::try_from_millis(5).ok_or(FixtureError::BadConstant("deadline"))?;
    sink.sync(at_bound)?;
    assert_eq!(sink.syncs(), 1);

    let too_short = IoDeadline::try_from_millis(4).ok_or(FixtureError::BadConstant("deadline"))?;
    assert_eq!(
        sink.sync(too_short),
        Err(SinkError::WouldBlock {
            needed: 5,
            offered: 4
        }),
        "a deadline one millisecond under the service time is refused"
    );
    assert_eq!(sink.syncs(), 1, "a refused flush is not counted");

    let generous = IoDeadline::try_from_millis(5_000).ok_or(FixtureError::BadConstant("wide"))?;
    sink.sync(generous)?;
    assert_eq!(sink.syncs(), 2);
    Ok(())
}

/// The unavailable sink refuses everything, on both trait methods.
#[test]
fn unavailable_sink_positive_negative_and_boundary() -> Fallible<()> {
    let mut sink = UnavailableSink::new();
    assert_eq!(sink, UnavailableSink);
    assert_eq!(sink.sync(io_deadline()), Err(SinkError::Unavailable));
    let short = IoDeadline::try_from_millis(1).ok_or(FixtureError::BadConstant("deadline"))?;
    assert_eq!(
        sink.sync(short),
        Err(SinkError::Unavailable),
        "the refusal does not depend on the deadline offered"
    );
    Ok(())
}

// --- Chain verification ----------------------------------------------------

/// A chain longer than its scalar bound is refused before it is walked.
#[test]
fn verify_chain_bound_positive_negative_and_boundary() -> Fallible<()> {
    let mut ledger: aegis_justitia::AuditLedger<
        aegis_justitia::Sha256Hasher,
        FixtureSigner,
        InMemorySink,
    > = aegis_justitia::AuditLedger::with_bound(
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FIXTURE_AUDIT_BOUND,
    );
    for step in 0u64..3 {
        ledger.append(aegis_justitia::RecordDraft {
            intent_id: IntentId::parse("intent-bound")?,
            agent: AgentId::parse("agent-01")?,
            action_type: ActionType::FileModification,
            status: RecordStatus::Approved,
            block_reason: None,
            killswitch: KillswitchState::Armed,
            at: UnixSeconds::new(step.saturating_add(100)),
        })?;
    }
    assert_eq!(ledger.len(), 3);
    aegis_justitia::verify_chain_bounded::<aegis_justitia::Sha256Hasher>(ledger.records(), 3)?;
    assert_eq!(
        aegis_justitia::verify_chain_bounded::<aegis_justitia::Sha256Hasher>(ledger.records(), 2),
        Err(aegis_justitia::LedgerError::LengthBoundExceeded { max: 2 }),
        "the bound is checked before the walk, so an oversized chain is never traversed"
    );
    assert_eq!(
        aegis_justitia::verify_chain_bounded::<aegis_justitia::Sha256Hasher>(&[], 0)?,
        Digest32::GENESIS
    );
    Ok(())
}

// --- Canonical pre-image ---------------------------------------------------

/// The pre-image buffer is length-prefixed, exactly bounded, and overflows with
/// an error rather than truncating.
#[test]
fn canonical_buffer_positive_negative_and_boundary() -> Fallible<()> {
    let mut split_a = aegis_justitia::CanonicalBuffer::new();
    assert!(split_a.is_empty());
    split_a.write_framed(b"ab")?;
    split_a.write_framed(b"c")?;

    let mut split_b = aegis_justitia::CanonicalBuffer::new();
    split_b.write_framed(b"a")?;
    split_b.write_framed(b"bc")?;
    assert_ne!(
        split_a.as_slice(),
        split_b.as_slice(),
        "length prefixes make a re-split field boundary a different pre-image"
    );
    assert_eq!(
        split_a.len(),
        11,
        "each field costs a four-byte length prefix"
    );

    let mut exact = aegis_justitia::CanonicalBuffer::new();
    exact.write_raw(&[0u8; aegis_justitia::MAX_PREIMAGE_BYTES])?;
    assert_eq!(exact.len(), aegis_justitia::MAX_PREIMAGE_BYTES);
    assert_eq!(
        exact.write_u8(0),
        Err(aegis_justitia::PreimageError::Overflow {
            max: aegis_justitia::MAX_PREIMAGE_BYTES
        }),
        "one byte past the bound is refused, never truncated"
    );

    let mut over = aegis_justitia::CanonicalBuffer::new();
    assert_eq!(
        over.write_raw(&[0u8; aegis_justitia::MAX_PREIMAGE_BYTES + 1]),
        Err(aegis_justitia::PreimageError::Overflow {
            max: aegis_justitia::MAX_PREIMAGE_BYTES
        })
    );
    assert_eq!(over.len(), 0);

    let mut tagged = aegis_justitia::CanonicalBuffer::new();
    tagged.write_tag(aegis_justitia::AUDIT_DOMAIN)?;
    tagged.write_u64(u64::MAX)?;
    tagged.write_digest(&Digest32::GENESIS)?;
    assert_eq!(
        tagged.len(),
        aegis_justitia::AUDIT_DOMAIN.len() + 8 + 32,
        "the encoding is exactly the concatenation of its fields"
    );
    Ok(())
}
