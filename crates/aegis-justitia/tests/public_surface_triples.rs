// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Triples for the public items the epic test files do not already reach.
//!
//! `public_surface.rs` sweeps the crate's public surface and fails on any item
//! no integration test names. This file closes that sweep: each test below is a
//! positive, negative and boundary case for one group of items the sweep
//! reported, so the surface is covered by intent rather than by coincidence.
//!
//! Two items are structurally unreachable in milestone M02 and are covered as
//! such rather than pretended to be exercised:
//! [`LedgerError::AlgorithmMismatch`], because `HashAlgorithm` admits exactly
//! one algorithm, and [`BlockReason::RequestMalformed`], because every registry
//! refusal `decide` can reach maps to a different reason. Both are asserted on
//! their stable encodings, which is what a persisted record depends on.

mod common;

use aegis_justitia::effects::SystemClock;
use aegis_justitia::{
    ActionType, AgentId, AuditLedger, AuditRecord, BlockReason, CONTRACT_VERSION, CheckerId,
    CheckerSet, Clock, ClockError, DEFAULT_APPROVAL_TTL_SECS, DEFAULT_SINK_SERVICE_MILLIS,
    DIGEST_LEN, Digest32, EngineConfig, HaltReason, HashAlgorithm, HashError, Identity,
    InMemorySink, IntentError, IntentId, InterceptorOutcome, IoDeadline, JustitiaError,
    KillswitchState, LedgerError, LedgerHasher, LedgerSink, MAX_IDENTITY_LEN, MAX_PREIMAGE_BYTES,
    OversightClass, OversightError, PreimageError, RecordBody, RecordDraft, RecordStatus,
    RegistryError, RequestId, RequestState, RequiredApproval, RiskTier, Sequence, Sha256Hasher,
    Sha256Ledger, SignError, SignerBinding, SinkError, Ttl, UnavailableSink, UnixSeconds,
    VerifiedCheckerSet, Vote, verify_chain,
};

use common::{
    FIXTURE_AUDIT_BOUND, Fallible, FixtureError, FixtureSigner, START, engine, intent, io_deadline,
};

/// Builds an empty fixture ledger through the concrete SHA-256 alias.
fn ledger() -> Result<Sha256Ledger<FixtureSigner, InMemorySink>, JustitiaError> {
    Ok(AuditLedger::with_bound(
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FIXTURE_AUDIT_BOUND,
    ))
}

/// Builds an approved draft for `id` at `at` seconds.
fn sample_draft(id: &str, at: u64) -> Result<RecordDraft, JustitiaError> {
    Ok(RecordDraft {
        intent_id: IntentId::parse(id)?,
        agent: AgentId::parse("agent-01")?,
        action_type: ActionType::FileModification,
        status: RecordStatus::Approved,
        block_reason: None,
        killswitch: KillswitchState::Armed,
        at: UnixSeconds::new(at),
    })
}

/// Seals one record and returns it.
fn one_record() -> Fallible<AuditRecord> {
    let mut chain = ledger()?;
    chain.append(sample_draft("intent-surface", 100)?)?;
    Ok(*chain.records().first().ok_or(FixtureError::NoRecord)?)
}

/// Returns `true` when `haystack` contains `needle` as a contiguous run.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

// --- Record bodies, sequences and the contract version --------------------

/// `RecordBody`, `canonical_preimage`, `CONTRACT_VERSION`, `Sequence` and
/// `Sequence::FIRST`: the pre-image commits to the contract version and to the
/// chain position, so neither can change without changing every later digest.
#[test]
fn the_canonical_preimage_commits_to_the_version_and_the_position() -> Fallible<()> {
    let draft = sample_draft("intent-preimage", 100)?;
    let body = RecordBody::from_parts(
        Sequence::FIRST,
        Digest32::GENESIS,
        HashAlgorithm::Sha256,
        draft,
    );
    let preimage = body.canonical_preimage()?;

    // Positive: the version is inside the pre-image and fixes the digest.
    assert!(contains_bytes(
        preimage.as_slice(),
        CONTRACT_VERSION.as_bytes()
    ));
    assert_eq!(
        body.digest::<Sha256Hasher>()?,
        Sha256Hasher::digest(preimage.as_slice())?,
        "the body digest is the digest of its own canonical pre-image"
    );

    // Negative: the same draft at a different position is a different record.
    let moved = RecordBody::from_parts(
        Sequence::new(2),
        Digest32::GENESIS,
        HashAlgorithm::Sha256,
        draft,
    );
    assert_ne!(
        body.digest::<Sha256Hasher>()?,
        moved.digest::<Sha256Hasher>()?
    );
    assert_eq!(body.draft(), &draft);

    // Boundary: the first position is one, and the pre-image fits its bound.
    assert_eq!(Sequence::FIRST, Sequence::new(1));
    assert_eq!(Sequence::FIRST.get(), 1);
    assert_eq!(Sequence::FIRST.next(), Some(Sequence::new(2)));
    assert_eq!(Sequence::new(u64::MAX).next(), None);
    assert!(preimage.len() <= MAX_PREIMAGE_BYTES);
    Ok(())
}

/// `Sha256Ledger`: the concrete alias is the shape M02 ships, and a record
/// sealed through it starts at [`Sequence::FIRST`].
#[test]
fn the_sha256_alias_seals_a_chain_from_the_first_position() -> Fallible<()> {
    let mut chain = ledger()?;
    assert!(chain.is_empty());
    chain.append(sample_draft("intent-alias", 100)?)?;
    let record = chain.records().first().ok_or(FixtureError::NoRecord)?;
    assert_eq!(record.body().sequence(), Sequence::FIRST);
    assert_eq!(record.body().algorithm(), Sha256Hasher::ALGORITHM);
    assert_eq!(chain.len(), 1);
    Ok(())
}

/// `DIGEST_LEN`: the width is the one constant every digest obeys.
#[test]
fn every_digest_is_exactly_the_declared_width() -> Fallible<()> {
    let digest = Sha256Hasher::digest(b"abc")?;
    assert_eq!(digest.to_bytes().len(), DIGEST_LEN);
    assert_eq!(Digest32::GENESIS.as_bytes().len(), DIGEST_LEN);

    let mut buffer = [0u8; 64];
    let text = digest.encode_hex(&mut buffer)?.to_owned();
    assert_eq!(text.len(), DIGEST_LEN.saturating_mul(2));
    assert_eq!(Digest32::parse_hex(&text)?, digest);
    assert_eq!(
        Digest32::parse_hex("00"),
        Err(HashError::Width {
            expected: DIGEST_LEN,
            actual: 1
        }),
        "a short but well-formed digest is a width refusal, not an encoding one"
    );
    assert_eq!(
        Digest32::parse_hex(&text.to_uppercase()),
        Err(HashError::Encoding),
        "only lower-case hexadecimal parses, so a digest has one rendering"
    );
    Ok(())
}

// --- Engine and sink defaults ---------------------------------------------

/// `DEFAULT_APPROVAL_TTL_SECS`: the default configuration uses it for both
/// windows, and a zero-width window stays unrepresentable.
#[test]
fn the_default_configuration_uses_the_declared_window() {
    let config = EngineConfig::default();
    assert_eq!(config.approval_ttl.seconds(), DEFAULT_APPROVAL_TTL_SECS);
    assert_eq!(config.annex_iii_ttl.seconds(), DEFAULT_APPROVAL_TTL_SECS);
    assert_eq!(Ttl::from_secs(0), None);
    assert_eq!(
        Ttl::from_secs(DEFAULT_APPROVAL_TTL_SECS).map(Ttl::seconds),
        Some(DEFAULT_APPROVAL_TTL_SECS),
        "the declared default is a window a validating constructor accepts"
    );
}

/// `DEFAULT_SINK_SERVICE_MILLIS` and `LedgerSink::append_record`: the sink
/// refuses a deadline shorter than the service time it declares, accepts one
/// exactly at it, and the unavailable sink accepts nothing at all.
#[test]
fn the_sink_admits_a_record_only_within_its_declared_service_time() -> Fallible<()> {
    let record = one_record()?;
    let mut sink = InMemorySink::with_bound(1);
    assert_eq!(sink.service_time().millis(), DEFAULT_SINK_SERVICE_MILLIS);

    // Boundary: a deadline exactly at the service time is admitted.
    let exact = IoDeadline::try_from_millis(DEFAULT_SINK_SERVICE_MILLIS)
        .ok_or(FixtureError::BadConstant("service millis"))?;
    assert_eq!(sink.append_record(&record, exact), Ok(()));
    assert_eq!(sink.accepted().len(), 1);

    // Negative: one record past the bound, and a sink that is simply unusable.
    assert_eq!(
        sink.append_record(&record, exact),
        Err(SinkError::Full { max: 1 })
    );
    assert_eq!(
        UnavailableSink::new().append_record(&record, io_deadline()),
        Err(SinkError::Unavailable)
    );
    assert_eq!(
        UnavailableSink::new().sync(io_deadline()),
        Err(SinkError::Unavailable)
    );
    Ok(())
}

// --- The host clock and the engine's reading of it -------------------------

/// `SystemClock`: the host clock reads, reads monotonically, and is refused by
/// a guard that has already seen a later time.
#[test]
fn the_host_clock_reads_and_is_still_guarded() -> Fallible<()> {
    let clock = SystemClock::new();
    let first = clock.now()?;
    assert!(
        first.get() > 1_600_000_000,
        "the host clock reads a plausible wall-clock time, not the epoch"
    );
    let second = clock.now()?;
    assert!(second >= first, "two readings do not go backwards");

    let mut guard = aegis_justitia::MonotonicGuard::new();
    let future = UnixSeconds::new(u64::MAX);
    assert_eq!(guard.observe(future), Ok(future));
    assert_eq!(
        guard.observe(first),
        Err(ClockError::NonMonotonic {
            last: future.get(),
            observed: first.get()
        }),
        "the host clock is still subject to the guard, not trusted directly"
    );
    Ok(())
}

/// `JustitiaEngine::last_reading`: nothing is remembered before the first
/// decision, the reading appears after it, and it does not move on its own.
#[test]
fn the_engine_remembers_only_readings_it_actually_took() -> Fallible<()> {
    let mut unit = engine(600, 2)?;
    assert_eq!(unit.last_reading(), None, "nothing has been read yet");

    let proposal = intent(
        "intent-reading",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    assert!(unit.decide(&proposal).permits_execution());
    assert_eq!(unit.last_reading(), Some(START));

    let again = intent(
        "intent-reading-2",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let _outcome = unit.decide(&again);
    assert_eq!(
        unit.last_reading(),
        Some(START),
        "the pinned clock did not move, so neither did the remembered reading"
    );
    Ok(())
}

/// `UnixSeconds::checked_add`: the window addition is checked, not wrapped.
#[test]
fn adding_a_window_is_checked_at_the_representable_edge() -> Fallible<()> {
    let ttl = Ttl::from_secs(2).ok_or(FixtureError::BadConstant("ttl"))?;
    assert_eq!(
        UnixSeconds::new(10).checked_add(ttl),
        Some(UnixSeconds::new(12))
    );
    assert_eq!(UnixSeconds::new(u64::MAX).checked_add(ttl), None);
    let last_fit = UnixSeconds::new(u64::MAX.saturating_sub(2));
    assert_eq!(last_fit.checked_add(ttl), Some(UnixSeconds::new(u64::MAX)));
    assert_eq!(
        UnixSeconds::new(u64::MAX.saturating_sub(1)).checked_add(ttl),
        None,
        "one second past the edge is refused rather than wrapped to the epoch"
    );
    Ok(())
}

/// `from_identity`: a role identifier derived from an identity carries it
/// unchanged, and distinct identities stay distinct.
#[test]
fn a_role_identifier_derived_from_an_identity_round_trips() -> Fallible<()> {
    let raw = Identity::parse("principal-one")?;
    let request = RequestId::from_identity(raw);
    assert_eq!(request.identity(), &raw);
    assert_eq!(IntentId::from_identity(raw).identity(), &raw);

    let other = Identity::parse("principal-two")?;
    assert_ne!(RequestId::from_identity(other), request);

    let at_bound = Identity::parse(&"x".repeat(MAX_IDENTITY_LEN))?;
    assert_eq!(
        RequestId::from_identity(at_bound).identity().len(),
        MAX_IDENTITY_LEN
    );
    Ok(())
}

// --- Outcome and refusal encodings ----------------------------------------

/// `BlockReason::halt_tag`: only a killswitch refusal carries a halt tag, and
/// zero is reserved for the rest.
#[test]
fn only_a_killswitch_refusal_carries_a_halt_tag() {
    let halted = BlockReason::KillswitchEngaged(HaltReason::LedgerCompromised);
    assert_eq!(halted.halt_tag(), HaltReason::LedgerCompromised.tag());
    assert_ne!(halted.halt_tag(), 0);
    assert_eq!(BlockReason::AuditUnavailable.halt_tag(), 0);
    assert_eq!(BlockReason::RegistryFull.halt_tag(), 0);
    for reason in [
        HaltReason::OperatorStop,
        HaltReason::AuditUnavailable,
        HaltReason::LedgerCompromised,
        HaltReason::ClockUnavailable,
    ] {
        assert_ne!(
            BlockReason::KillswitchEngaged(reason).halt_tag(),
            0,
            "zero is reserved for the absence of a halt reason"
        );
    }
}

/// `BlockReason::RequestMalformed`: unreachable from `decide` in M02, because
/// every registry refusal it can hit maps elsewhere, so it is pinned by its
/// stable encodings instead of by a path.
#[test]
fn the_malformed_request_reason_keeps_its_stable_encoding() {
    assert_eq!(BlockReason::RequestMalformed.name(), "request-malformed");
    assert_ne!(BlockReason::RequestMalformed.tag(), 0);
    assert_ne!(
        BlockReason::RequestMalformed.tag(),
        BlockReason::RequestAlreadyPending.tag()
    );
    assert_ne!(
        BlockReason::RequestMalformed,
        BlockReason::RequestAlreadyPending
    );
    assert_eq!(BlockReason::RequestMalformed.halt_tag(), 0);
}

/// `InterceptorOutcome::Block` and `InterceptorOutcome::RequireApproval`: the
/// four outcome variants are matched by shape, not by accessor, so a new
/// variant cannot slip past the tests that only read `block_reason`.
#[test]
fn every_outcome_variant_is_matched_by_shape() -> Fallible<()> {
    let mut unit = engine(600, 2)?;
    let held = intent(
        "intent-shape-hold",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let outcome = unit.decide(&held);
    assert!(
        matches!(outcome, InterceptorOutcome::RequireApproval(ticket)
            if ticket.required() == RequiredApproval::SingleChecker),
        "a Tier A action must be held on a single-checker ticket, found {outcome:?}"
    );

    unit.halt(HaltReason::OperatorStop);
    let after = intent(
        "intent-shape-block",
        "maker-alice",
        ActionType::FileModification,
        RiskTier::TierCRoutineBounded,
        OversightClass::Standard,
    )?;
    let refused = unit.decide(&after);
    assert!(
        matches!(refused, InterceptorOutcome::Block { reason }
            if reason == BlockReason::KillswitchEngaged(HaltReason::OperatorStop)),
        "a halted unit must refuse on the latch, found {refused:?}"
    );
    assert!(
        !InterceptorOutcome::Block {
            reason: BlockReason::RegistryFull
        }
        .permits_execution()
    );
    Ok(())
}

// --- Oversight panels ------------------------------------------------------

/// Returns `true` when `panel` is a one-checker panel naming `only`.
fn is_single(panel: CheckerSet, only: CheckerId) -> bool {
    matches!(panel, CheckerSet::Single(named) if named == only)
}

/// Returns `true` when `panel` is a two-checker panel naming both, in order.
fn is_dual(panel: CheckerSet, one: CheckerId, two: CheckerId) -> bool {
    matches!(panel, CheckerSet::Dual { first, second } if first == one && second == two)
}

/// `CheckerSet::Single` and `CheckerSet::Dual`: a panel is matched by shape,
/// and a two-checker panel naming one principal twice is unrepresentable.
#[test]
fn a_panel_is_matched_by_shape() -> Fallible<()> {
    let ada = CheckerId::parse("checker-ada")?;
    let bo = CheckerId::parse("checker-bo")?;

    let one = CheckerSet::single(ada);
    assert!(is_single(one, ada));
    assert!(!is_dual(one, ada, bo));
    assert_eq!(one.len(), 1);

    let pair = CheckerSet::dual(ada, bo)?;
    assert!(
        is_dual(pair, ada, bo),
        "a dual panel keeps both slots in the order they were given"
    );
    assert!(!is_single(pair, ada));
    assert_eq!(pair.len(), 2);

    assert_eq!(
        CheckerSet::dual(ada, ada),
        Err(OversightError::DuplicateChecker),
        "one principal in both slots is refused rather than collapsed to one checker"
    );
    Ok(())
}

/// `VerifiedCheckerSet`: only a panel proved separate from the maker can be
/// tested against what a request demands, and a single checker never satisfies
/// an Annex III request.
#[test]
fn a_verified_panel_is_proof_of_separation_from_the_maker() -> Fallible<()> {
    let ada = CheckerId::parse("checker-ada")?;
    let bo = CheckerId::parse("checker-bo")?;
    let maker = aegis_justitia::MakerId::parse("maker-alice")?;
    let pair = CheckerSet::dual(ada, bo)?;

    let verified: VerifiedCheckerSet = pair.verify_against_maker(&maker)?;
    assert_eq!(verified.panel(), pair);
    assert_eq!(verified.primary(), ada);
    assert_eq!(
        verified.satisfies(RequiredApproval::DualDistinctCheckers),
        Ok(())
    );

    let single: VerifiedCheckerSet = CheckerSet::single(ada).verify_against_maker(&maker)?;
    assert_eq!(
        single.satisfies(RequiredApproval::DualDistinctCheckers),
        Err(OversightError::AnnexIiiRequiresTwoCheckers)
    );
    assert_eq!(
        single.satisfies(RequiredApproval::None),
        Err(OversightError::NoApprovalRequired),
        "a request that admits no checker decision admits no verified panel either"
    );

    let self_review = CheckerSet::single(CheckerId::parse("maker-alice")?);
    assert_eq!(
        self_review
            .verify_against_maker(&maker)
            .map(|set| set.primary()),
        Err(OversightError::MakerIsChecker),
        "there is no verified panel for a maker reviewing itself"
    );
    Ok(())
}

/// `RequestState::Pending`: a held request is pending until a vote lands, and
/// terminal afterwards, which is what distinguishes a replay from an unknown
/// identifier.
#[test]
fn a_held_request_is_pending_until_the_vote_lands() -> Fallible<()> {
    let mut unit = engine(600, 2)?;
    let proposal = intent(
        "intent-state",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let ticket = *unit
        .decide(&proposal)
        .ticket()
        .ok_or(FixtureError::NoTicket)?;
    let (held, state) = unit.registry().get(ticket.request_id())?;
    assert_eq!(state, RequestState::Pending);
    assert_eq!(held.request_id(), ticket.request_id());

    let panel = CheckerSet::single(CheckerId::parse("checker-bo")?);
    let _decision = unit.adjudicate(ticket.request_id(), panel, Vote::Approve)?;
    let (_, after) = unit.registry().get(ticket.request_id())?;
    assert_eq!(after, RequestState::Decided(RecordStatus::Approved));
    assert_ne!(after, RequestState::Pending);
    assert_eq!(
        unit.registry().pending(ticket.request_id()),
        Err(RegistryError::AlreadyDecided)
    );
    Ok(())
}

/// `OversightError::SystemHalted`: a halted unit accepts no human decision,
/// and says so rather than reporting the request as unknown.
#[test]
fn a_halted_unit_accepts_no_human_decision() -> Fallible<()> {
    let mut unit = engine(600, 2)?;
    let proposal = intent(
        "intent-halted-vote",
        "maker-alice",
        ActionType::PermissionEscalation,
        RiskTier::TierAConsequential,
        OversightClass::Standard,
    )?;
    let ticket = *unit
        .decide(&proposal)
        .ticket()
        .ok_or(FixtureError::NoTicket)?;
    unit.halt(HaltReason::OperatorStop);

    let panel = CheckerSet::single(CheckerId::parse("checker-bo")?);
    assert_eq!(
        unit.adjudicate(ticket.request_id(), panel, Vote::Approve),
        Err(JustitiaError::Oversight(OversightError::SystemHalted)),
        "the halt is reported as the halt, not as a missing request"
    );
    let unknown = RequestId::parse("intent-never-held")?;
    assert_eq!(
        unit.adjudicate(&unknown, panel, Vote::Approve),
        Err(JustitiaError::Oversight(OversightError::SystemHalted)),
        "the latch is matched before the registry, so a halt is never masked"
    );
    Ok(())
}

/// `SignerBinding::Unbound`: the milestone default is the unbound variant, it
/// reports itself unbound, and it seals nothing.
#[test]
fn the_default_binding_is_unbound_and_seals_nothing() -> Fallible<()> {
    let unbound: SignerBinding<FixtureSigner> = SignerBinding::unbound();
    assert_eq!(unbound, SignerBinding::Unbound);
    assert!(!unbound.is_bound());
    assert_eq!(
        unbound.sign(&Digest32::GENESIS),
        Err(SignError::Unavailable)
    );

    let bound = SignerBinding::Bound(FixtureSigner::new()?);
    assert!(bound.is_bound());
    assert_ne!(bound, SignerBinding::Unbound);
    assert!(bound.sign(&Digest32::GENESIS).is_ok());
    Ok(())
}

// --- Ledger and aggregate error encodings ----------------------------------

/// `LedgerError::PreviousHashMismatch`: a record that verifies on its own but
/// links to a different predecessor breaks the chain at its own position.
#[test]
fn a_foreign_predecessor_breaks_the_chain_at_that_position() -> Fallible<()> {
    let mut first = ledger()?;
    first.append(sample_draft("intent-a", 100)?)?;
    let foreign = *first.records().first().ok_or(FixtureError::NoRecord)?;

    let mut second = ledger()?;
    second.append(sample_draft("intent-b", 100)?)?;
    second.append(sample_draft("intent-c", 101)?)?;
    let tail = *second.records().get(1).ok_or(FixtureError::NoRecord)?;

    assert_eq!(
        verify_chain::<Sha256Hasher>(&[foreign, tail]),
        Err(LedgerError::PreviousHashMismatch { at: 2 }),
        "record two links to a predecessor that is not record one"
    );
    assert!(verify_chain::<Sha256Hasher>(second.records()).is_ok());
    assert_eq!(
        verify_chain::<Sha256Hasher>(&[foreign]).map(|head| head == foreign.digest()),
        Ok(true)
    );
    Ok(())
}

/// `LedgerError::AlgorithmMismatch`: unreachable while `HashAlgorithm` admits
/// exactly one algorithm, so it is pinned by its rendering, which is what a
/// persisted record and a diagnostic depend on.
#[test]
fn the_algorithm_mismatch_refusal_names_both_algorithms() -> Fallible<()> {
    let mismatch = LedgerError::AlgorithmMismatch {
        expected: HashAlgorithm::Sha256,
        found: HashAlgorithm::Sha256,
    };
    assert!(mismatch.to_string().contains(HashAlgorithm::Sha256.name()));
    assert_ne!(mismatch, LedgerError::DigestMismatch { at: 1 });

    let mut chain = ledger()?;
    chain.append(sample_draft("intent-algo", 100)?)?;
    assert_ne!(
        verify_chain::<Sha256Hasher>(chain.records()),
        Err(mismatch),
        "a chain sealed by the only shipped hasher never reports a mismatch"
    );
    Ok(())
}

/// `JustitiaError::Intent`, `::Registry`, `::Hash` and `::Preimage`, and
/// `LedgerError::Hash` and `::Preimage`: the aggregate error keeps each
/// boundary's error rather than flattening it, which is what lets a caller use
/// `?` across two boundaries without reaching for `unwrap`.
#[test]
fn the_aggregate_error_keeps_the_boundary_that_produced_it() {
    let downgrade = IntentError::TierDowngrade {
        declared: RiskTier::TierCRoutineBounded,
        minimum: RiskTier::TierAConsequential,
    };
    assert_eq!(
        JustitiaError::from(downgrade),
        JustitiaError::Intent(downgrade)
    );

    let full = RegistryError::Full { limit: 4 };
    assert_eq!(JustitiaError::from(full), JustitiaError::Registry(full));
    assert_ne!(JustitiaError::from(full), JustitiaError::Intent(downgrade));

    let width = HashError::Width {
        expected: DIGEST_LEN,
        actual: 16,
    };
    assert_eq!(JustitiaError::from(width), JustitiaError::Hash(width));
    assert_eq!(LedgerError::from(width), LedgerError::Hash(width));

    let overflow = PreimageError::Overflow {
        max: MAX_PREIMAGE_BYTES,
    };
    assert_eq!(
        JustitiaError::from(overflow),
        JustitiaError::Preimage(overflow)
    );
    assert_eq!(LedgerError::from(overflow), LedgerError::Preimage(overflow));
    assert!(
        JustitiaError::from(overflow)
            .to_string()
            .contains(&overflow.to_string()),
        "the wrapper carries the wrapped message rather than replacing it"
    );
}
