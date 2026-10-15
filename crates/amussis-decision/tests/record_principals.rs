// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! Who the records of the chain name.
//!
//! A record that decides an action names the maker of the proposal, the
//! record of a vote names the checkers who cast it, the record of a release
//! names the releasing person and the checkers who approved, and the record
//! of a halt names the person who halted. Each
//! states the risk level the approval rule was asked at, so the record alone
//! is held to that rule. The identities are the bytes the caller passed in.
//!
//! The planted cases are the ones that must be refused: a record without the
//! identities its status needs, a maker who is one of the checkers, two
//! checkers who are one, a record that names someone it must not, a stored
//! head in the layout without these fields, and a panel written as a literal
//! that names one checker twice.

mod common;

use amussis_decision::{
    ActionIntent, ActionType, AgentId, AnchorError, AuditLedger, AuditRecord, ChainAnchor,
    CheckerId, CheckerSet, DecisionEngine, DecisionError, Digest32, FixedClock, HaltReason,
    HashAlgorithm, InMemorySink, IntentId, InterceptorOutcome, KillswitchState, LedgerError,
    LedgerHasher, MAX_IDENTITY_LEN, MAX_PREIMAGE_BYTES, MakerId, OversightClass, OversightError,
    PreimageError, RecordBody, RecordDraft, RecordPrincipals, RecordSigner, RecordStatus,
    RecordSubject, ReleaseError, RiskLevel, RiskTier, Sequence, Sha256Hasher, SignerBinding,
    UnixSeconds, Vote, verify_chain,
};
use common::{
    FIXTURE_AUDIT_BOUND, Fallible, FixtureError, FixtureSigner, START, TestEngine, anchor_of,
    config, engine, filler, intent, io_deadline, one, stored_head, two,
};

/// A level whose actions pass with a notice and no checker.
const MONITORED: RiskLevel =
    RiskLevel::new(RiskTier::TierBMaterialReversible, OversightClass::Standard);

/// A level whose actions need one checker.
const SINGLE: RiskLevel = RiskLevel::new(RiskTier::TierAConsequential, OversightClass::Standard);

/// The lowest level that needs two checkers.
const DUAL: RiskLevel = RiskLevel::new(
    RiskTier::TierCRoutineBounded,
    OversightClass::AnnexIiiBiometric,
);

/// The bytes a record that names nobody ends on: no level, and three empty
/// fields.
const NOBODY: [u8; 13] = [0; 13];

/// The canonical pre-image of the largest record: a vote of two checkers,
/// every identity at its bound.
const LARGEST_PREIMAGE: usize = 454;

/// The maker every fixture action is proposed by.
const MAKER: &str = "maker-alice";

/// A panel written as a literal, which names what it is given.
fn literal(first: &str, second: &str) -> Fallible<CheckerSet> {
    Ok(CheckerSet::Dual {
        first: CheckerId::parse(first)?,
        second: CheckerId::parse(second)?,
    })
}

/// Who a record names: `maker` at `level`, beside `checkers`.
fn named(
    level: RiskLevel,
    maker: &str,
    checkers: Option<CheckerSet>,
) -> Fallible<RecordPrincipals> {
    Ok(RecordPrincipals {
        level,
        maker: MakerId::parse(maker)?,
        checkers,
    })
}

/// A record of `status` that decides the fixture action and names `who`.
fn decision(status: RecordStatus, who: Option<RecordPrincipals>) -> Fallible<RecordDraft> {
    Ok(RecordDraft {
        subject: Some(RecordSubject {
            intent_id: IntentId::parse("intent-named")?,
            agent: AgentId::parse("agent-01")?,
            action_type: ActionType::FileModification,
        }),
        principals: who,
        status,
        block_reason: None,
        killswitch: KillswitchState::Armed,
        at: START,
    })
}

/// The body `draft` has at the first chain position.
fn first_body(draft: &RecordDraft) -> RecordBody {
    RecordBody::from_parts(
        Sequence::FIRST,
        Digest32::GENESIS,
        HashAlgorithm::Sha256,
        *draft,
    )
}

/// The canonical pre-image of `draft` at the first chain position.
fn preimage_of(draft: &RecordDraft) -> Result<Vec<u8>, PreimageError> {
    let buffer = first_body(draft).canonical_preimage()?;
    Ok(buffer.as_slice().to_vec())
}

/// One field of the pre-image: its length, then its bytes.
fn framed(bytes: &[u8]) -> Fallible<Vec<u8>> {
    let mut field = u32::try_from(bytes.len())?.to_be_bytes().to_vec();
    field.extend_from_slice(bytes);
    Ok(field)
}

/// The bytes a record that names `who` ends on.
fn tail_of(who: &RecordPrincipals) -> Fallible<Vec<u8>> {
    let mut tail = vec![who.level.tag()];
    tail.extend(framed(who.maker.as_bytes())?);
    for checker in who.checkers() {
        let bytes = checker.as_ref().map_or(&[][..], CheckerId::as_bytes);
        tail.extend(framed(bytes)?);
    }
    Ok(tail)
}

/// Requires `draft` to be refused everywhere a record enters a chain: it is
/// not well formed, it has no pre-image, a ledger does not seal it, and a
/// stored record of its shape does not verify.
fn assert_refused(draft: &RecordDraft, why: &str) -> Fallible<()> {
    assert!(!draft.is_well_formed(), "{why}: {draft:?}");
    assert_eq!(preimage_of(draft), Err(PreimageError::Shape), "{why}");
    let mut ledger: AuditLedger<Sha256Hasher, FixtureSigner, InMemorySink> =
        AuditLedger::with_bound(
            SignerBinding::Bound(FixtureSigner::new()?),
            InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
            io_deadline(),
            FIXTURE_AUDIT_BOUND,
        );
    assert_eq!(
        ledger.append(*draft),
        Err(LedgerError::Preimage(PreimageError::Shape)),
        "{why}"
    );
    assert!(ledger.is_empty(), "{why}");
    let digest = Sha256Hasher::digest(why.as_bytes())?;
    let signature = FixtureSigner::new()?.sign(&digest)?;
    let stored = AuditRecord::from_parts(first_body(draft), signature, digest);
    assert_eq!(
        verify_chain::<Sha256Hasher>(&[stored]),
        Err(LedgerError::Preimage(PreimageError::Shape)),
        "{why}"
    );
    Ok(())
}

/// Requires `draft` to be well formed and to end on the bytes of `who`.
fn assert_names(draft: &RecordDraft, who: &RecordPrincipals, why: &str) -> Fallible<()> {
    assert!(draft.is_well_formed(), "{why}: {draft:?}");
    assert_eq!(draft.principals, Some(*who), "{why}");
    let preimage = preimage_of(draft)?;
    assert!(preimage.ends_with(&tail_of(who)?), "{why}");
    Ok(())
}

/// The last record in the engine's window.
fn last_draft(engine: &TestEngine) -> Fallible<RecordDraft> {
    let last = engine.ledger().records().last();
    Ok(*last.ok_or(FixtureError::NoRecord)?.body().draft())
}

/// An action of the fixture maker at `level`.
fn action(id: &str, level: RiskLevel) -> Fallible<ActionIntent> {
    let proposed = intent(
        id,
        MAKER,
        ActionType::FileModification,
        level.tier(),
        level.class(),
    )?;
    assert_eq!(
        proposed.level(),
        level,
        "the fixture action keeps its level"
    );
    Ok(proposed)
}

/// An engine that continues a chain an operator halted at `level`.
fn carried(level: RiskLevel) -> Fallible<TestEngine> {
    let mut halted = engine(600, 4)?;
    halted.halt_unnamed(HaltReason::OperatorStop, level)?;
    let anchor = anchor_of(&halted)?;
    Ok(DecisionEngine::continue_from(
        config(600, 4)?,
        SignerBinding::Bound(FixtureSigner::new()?),
        InMemorySink::with_bound(FIXTURE_AUDIT_BOUND),
        io_deadline(),
        FixedClock::new(START),
        &anchor,
    ))
}

/// Reads `bytes` as an anchor under the digest they really have, so that a
/// refusal is about the content and never about the digest.
fn read_under_own_digest(bytes: &[u8]) -> Fallible<Result<ChainAnchor, AnchorError>> {
    let digest = Sha256Hasher::digest(bytes)?;
    Ok(ChainAnchor::from_preimage::<Sha256Hasher>(bytes, &digest))
}

// --- Positive -------------------------------------------------------------

/// Positive: every record the engine writes on a proposal names its maker
/// and the level of the action, and no checker: passed, passed with a
/// notice, held, and refused under a halt.
#[test]
fn a_decision_record_names_the_maker_of_the_proposal() -> Fallible<()> {
    let cases = [
        (RiskLevel::LOWEST, RecordStatus::Approved),
        (MONITORED, RecordStatus::Approved),
        (SINGLE, RecordStatus::PendingApproval),
        (DUAL, RecordStatus::PendingApproval),
    ];
    let mut deciding = engine(600, 8)?;
    for (level, status) in cases {
        let _outcome = deciding.decide(&action(&format!("intent-{}", level.tag()), level)?);
        let draft = last_draft(&deciding)?;
        assert_eq!(draft.status, status);
        assert_names(&draft, &named(level, MAKER, None)?, "decided")?;
    }

    deciding.halt_unnamed(HaltReason::OperatorStop, SINGLE)?;
    let refused = deciding.decide(&action("intent-refused", DUAL)?);
    assert!(refused.block_reason().is_some());
    let draft = last_draft(&deciding)?;
    assert_eq!(draft.status, RecordStatus::Halted);
    assert_names(&draft, &named(DUAL, MAKER, None)?, "refused under a halt")
}

/// Positive: the record of a vote names the panel that cast it beside the
/// maker, for an approval, for a rejection and for a panel of two.
#[test]
fn the_record_of_a_vote_names_the_panel() -> Fallible<()> {
    let cases = [
        (SINGLE, one("checker-bob")?, Vote::Approve),
        (SINGLE, one("checker-bob")?, Vote::Reject),
        (DUAL, two("checker-bob", "checker-cara")?, Vote::Approve),
        (DUAL, two("checker-cara", "checker-bob")?, Vote::Reject),
    ];
    let mut deciding = engine(600, 8)?;
    for (step, (level, panel, vote)) in cases.into_iter().enumerate() {
        let held = deciding.decide(&action(&format!("intent-{step}"), level)?);
        let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
        deciding.adjudicate(ticket.request_id(), panel, vote)?;
        let draft = last_draft(&deciding)?;
        let status = match vote {
            Vote::Approve => RecordStatus::Approved,
            Vote::Reject => RecordStatus::Rejected,
        };
        assert_eq!(draft.status, status);
        assert_names(&draft, &named(level, MAKER, Some(panel))?, "voted")?;
    }
    Ok(())
}

/// Positive: the record of a release names the releasing person in the place
/// of the maker, the checkers who approved, and the level the halt stood at.
#[test]
fn the_record_of_a_release_names_the_releaser_and_the_approvers() -> Fallible<()> {
    let cases = [
        (RiskLevel::LOWEST, None),
        (MONITORED, None),
        (SINGLE, Some(one("checker-bob")?)),
        (DUAL, Some(two("checker-bob", "checker-cara")?)),
    ];
    for (level, panel) in cases {
        let mut continued = carried(level)?;
        continued.release_halt(&MakerId::parse("olga")?, panel)?;
        let draft = last_draft(&continued)?;
        assert_eq!(draft.status, RecordStatus::HaltReleased);
        assert_eq!(draft.subject, None);
        assert_names(&draft, &named(level, "olga", panel)?, "released")?;
    }
    Ok(())
}

/// Positive: the record of a halt a person called names that person in the
/// place of the maker, the level the halt stands at, and no checker.
#[test]
fn the_record_of_a_halt_names_the_person_who_halted() -> Fallible<()> {
    for level in [RiskLevel::LOWEST, MONITORED, SINGLE, DUAL] {
        let mut halted = engine(600, 4)?;
        halted.halt(&MakerId::parse("olga")?, level)?;
        let draft = last_draft(&halted)?;
        assert_eq!(draft.status, RecordStatus::HaltEngaged);
        assert_eq!(draft.subject, None);
        assert_names(&draft, &named(level, "olga", None)?, "halted")?;
        let head = preimage_of(&draft)?;
        assert!(read_under_own_digest(&head)?.is_ok(), "read as a head");
    }
    Ok(())
}

/// Positive: the record of a halt no person engaged names nobody, and says
/// so in its bytes.
#[test]
fn the_record_of_a_halt_no_person_engaged_names_nobody() -> Fallible<()> {
    let mut halted = engine(600, 4)?;
    halted.halt_unnamed(HaltReason::OperatorStop, DUAL)?;
    let draft = last_draft(&halted)?;
    assert_eq!(draft.status, RecordStatus::HaltEngaged);
    assert_eq!(draft.principals, None);
    assert!(draft.is_well_formed());
    assert!(preimage_of(&draft)?.ends_with(&NOBODY));
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative, planted: a record without the identities its status needs has
/// no pre-image. No decision and no release goes unnamed, and no vote or
/// release names fewer checkers than its level demands.
#[test]
fn a_record_without_the_identities_it_needs_is_refused() -> Fallible<()> {
    let decisions = [
        RecordStatus::PendingApproval,
        RecordStatus::Approved,
        RecordStatus::Rejected,
        RecordStatus::Blocked,
        RecordStatus::Halted,
    ];
    for status in decisions {
        assert_refused(&decision(status, None)?, "a decision that names nobody")?;
    }
    let alone = named(RiskLevel::LOWEST, "olga", None)?;
    let unnamed = RecordDraft {
        principals: None,
        ..RecordDraft::of_release(alone, START)
    };
    assert_refused(&unnamed, "a release that names nobody")?;

    let short = [
        (SINGLE, None),
        (DUAL, None),
        (DUAL, Some(one("checker-bob")?)),
        (RiskLevel::HIGHEST, Some(one("checker-bob")?)),
    ];
    for (level, panel) in short {
        let who = named(level, MAKER, panel)?;
        for voted in [RecordStatus::Approved, RecordStatus::Rejected] {
            assert_refused(&decision(voted, Some(who))?, "a vote of too few")?;
        }
        assert_refused(&RecordDraft::of_release(who, START), "a release of too few")?;
    }
    Ok(())
}

/// Negative, planted: a maker who is one of the checkers is refused, in
/// either place of the panel, and so are two checkers who are one. The
/// comparison is of bytes.
#[test]
fn a_maker_among_the_checkers_is_refused_by_byte_equality() -> Fallible<()> {
    let hashed = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let other = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a09";
    let third = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
    assert_eq!(hashed.len(), MAX_IDENTITY_LEN);
    let clashes = [
        (SINGLE, one(hashed)?),
        (DUAL, literal(hashed, other)?),
        (DUAL, literal(other, hashed)?),
        (DUAL, literal(other, other)?),
        (DUAL, literal(hashed, hashed)?),
    ];
    for (level, panel) in clashes {
        let who = named(level, hashed, Some(panel))?;
        assert!(!who.is_separated(), "{who:?}");
        for voted in [RecordStatus::Approved, RecordStatus::Rejected] {
            assert_refused(&decision(voted, Some(who))?, "a vote of the maker's own")?;
        }
        assert_refused(
            &RecordDraft::of_release(who, START),
            "a release of one's own",
        )?;
    }
    // A release no checker is asked for is still not approved by its releaser.
    let own = named(RiskLevel::LOWEST, hashed, Some(one(hashed)?))?;
    assert_refused(
        &RecordDraft::of_release(own, START),
        "the releaser as checker",
    )?;

    // One byte apart is another principal.
    let apart = [
        (SINGLE, one(other)?),
        (DUAL, two(other, third)?),
        (SINGLE, two(other, third)?),
    ];
    for (level, panel) in apart {
        let who = named(level, hashed, Some(panel))?;
        assert!(who.is_separated(), "{who:?}");
        for voted in [RecordStatus::Approved, RecordStatus::Rejected] {
            assert_names(&decision(voted, Some(who))?, &who, "a vote of others")?;
        }
        assert_names(&RecordDraft::of_release(who, START), &who, "a release")?;
    }
    Ok(())
}

/// Negative, planted: a record that names someone its status has no place
/// for is refused: a halt that names a person at another level than it
/// stands at, a halt anyone voted on, a vote where none was cast, and a hold
/// or a rejection at a level that holds nothing.
#[test]
fn a_record_that_names_someone_it_must_not_is_refused() -> Fallible<()> {
    let engaged = KillswitchState::Engaged {
        at: START,
        reason: HaltReason::OperatorStop,
        level: SINGLE,
    };
    let panel = Some(one("checker-bob")?);
    let halted = RecordDraft::of_halt_by(engaged, named(SINGLE, "olga", None)?, START);
    assert!(
        halted.is_well_formed(),
        "the person at the level it stands at"
    );
    for level in [RiskLevel::LOWEST, MONITORED, DUAL] {
        let elsewhere = RecordDraft::of_halt_by(engaged, named(level, "olga", None)?, START);
        assert_refused(&elsewhere, "a halt named at a level it does not stand at")?;
    }
    for checkers in [panel, Some(two("checker-bob", "checker-cara")?)] {
        let voted = RecordDraft::of_halt_by(engaged, named(SINGLE, "olga", checkers)?, START);
        assert_refused(&voted, "a halt somebody voted on")?;
    }
    let armed = RecordDraft {
        killswitch: KillswitchState::Armed,
        ..halted
    };
    assert_refused(&armed, "a named halt of an engine that is not halted")?;

    let unvoted = [
        (RecordStatus::PendingApproval, SINGLE),
        (RecordStatus::Blocked, SINGLE),
        (RecordStatus::Halted, SINGLE),
        (RecordStatus::Blocked, RiskLevel::LOWEST),
        (RecordStatus::Approved, RiskLevel::LOWEST),
        (RecordStatus::Approved, MONITORED),
    ];
    for (status, level) in unvoted {
        let who = named(level, MAKER, panel)?;
        assert_refused(&decision(status, Some(who))?, "a vote nobody cast")?;
    }
    for level in [RiskLevel::LOWEST, MONITORED] {
        for checkers in [None, panel] {
            let who = named(level, MAKER, checkers)?;
            assert_refused(
                &decision(RecordStatus::PendingApproval, Some(who))?,
                "a hold at a level that holds nothing",
            )?;
            assert_refused(
                &decision(RecordStatus::Rejected, Some(who))?,
                "a rejection at a level that holds nothing",
            )?;
        }
    }
    Ok(())
}

/// Negative, planted: a stored head in the layout without these fields is
/// not read as an anchor, and neither is one cut short or one with a byte
/// after its last field.
#[test]
fn a_head_in_the_layout_without_the_names_is_refused() -> Fallible<()> {
    let mut halted = engine(600, 4)?;
    halted.halt_unnamed(HaltReason::OperatorStop, SINGLE)?;
    let halt = stored_head(&halted)?.body().canonical_preimage()?;
    let halt = halt.as_slice();
    assert!(read_under_own_digest(halt)?.is_ok());
    let earlier = halt.len().saturating_sub(NOBODY.len());
    let cut = halt.get(..earlier).ok_or(FixtureError::NoRecord)?;
    assert_eq!(read_under_own_digest(cut)?, Err(AnchorError::Malformed));

    let mut deciding = engine(600, 4)?;
    let _allowed = deciding.decide(&action("intent-stored", RiskLevel::LOWEST)?);
    let decided = stored_head(&deciding)?.body().canonical_preimage()?;
    let decided = decided.as_slice();
    assert!(read_under_own_digest(decided)?.is_ok());
    let tail = tail_of(&named(RiskLevel::LOWEST, MAKER, None)?)?;
    for dropped in [tail.len(), 1] {
        let kept = decided.len().saturating_sub(dropped);
        let cut = decided.get(..kept).ok_or(FixtureError::NoRecord)?;
        assert_eq!(read_under_own_digest(cut)?, Err(AnchorError::Malformed));
    }
    let mut longer = decided.to_vec();
    longer.push(0);
    assert_eq!(read_under_own_digest(&longer)?, Err(AnchorError::Malformed));
    Ok(())
}

/// Negative, planted: a panel written as a literal that names one checker
/// twice is refused before anything is recorded. The hold stays open and the
/// engine does not halt on it.
#[test]
fn a_literal_panel_of_one_checker_twice_is_refused() -> Fallible<()> {
    let twice = literal("checker-bob", "checker-bob")?;
    assert_eq!(
        twice.verify_against_maker(&MakerId::parse(MAKER)?),
        Err(OversightError::DuplicateChecker)
    );

    let mut deciding = engine(600, 4)?;
    let held = deciding.decide(&action("intent-dual", DUAL)?);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    let before = deciding.ledger().len();
    assert_eq!(
        deciding.adjudicate(ticket.request_id(), twice, Vote::Approve),
        Err(DecisionError::Oversight(OversightError::DuplicateChecker))
    );
    assert_eq!(deciding.ledger().len(), before);
    assert_eq!(deciding.killswitch(), KillswitchState::Armed);
    let voted = two("checker-bob", "checker-cara")?;
    deciding.adjudicate(ticket.request_id(), voted, Vote::Approve)?;

    for level in [RiskLevel::LOWEST, DUAL] {
        let mut continued = carried(level)?;
        assert_eq!(
            continued.release_halt(&MakerId::parse("olga")?, Some(twice)),
            Err(ReleaseError::Approval(OversightError::DuplicateChecker))
        );
        assert!(continued.killswitch().is_engaged());
    }
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the largest record there is, a vote of two checkers with every
/// identity at its bound, has a pre-image of 454 bytes, inside the bound,
/// and it is read back as an anchor. The smallest, a halt, is those five
/// identities shorter.
#[test]
fn the_largest_record_fits_the_preimage_bound() -> Fallible<()> {
    let long = |seed: &str| format!("{seed}{}", filler(MAX_IDENTITY_LEN - seed.len()));
    let who = named(
        RiskLevel::HIGHEST,
        &long("m"),
        Some(two(&long("a"), &long("b"))?),
    )?;
    let largest = RecordDraft {
        subject: Some(RecordSubject {
            intent_id: IntentId::parse(&long("i"))?,
            agent: AgentId::parse(&long("g"))?,
            action_type: ActionType::SystemConfigChange,
        }),
        principals: Some(who),
        status: RecordStatus::Rejected,
        block_reason: None,
        killswitch: KillswitchState::Armed,
        at: UnixSeconds::new(u64::MAX),
    };
    let preimage = preimage_of(&largest)?;
    assert_eq!(preimage.len(), LARGEST_PREIMAGE);
    const { assert!(LARGEST_PREIMAGE <= MAX_PREIMAGE_BYTES) };
    assert_eq!(tail_of(&who)?.len(), 1 + 3 * (4 + MAX_IDENTITY_LEN));
    assert!(read_under_own_digest(&preimage)?.is_ok());

    let engaged = KillswitchState::Engaged {
        at: START,
        reason: HaltReason::OperatorStop,
        level: RiskLevel::HIGHEST,
    };
    let smallest = preimage_of(&RecordDraft::of_halt(engaged, START))?;
    assert_eq!(
        smallest.len(),
        LARGEST_PREIMAGE - 5 * MAX_IDENTITY_LEN,
        "five identities apart"
    );
    let operator = named(RiskLevel::HIGHEST, &long("o"), None)?;
    let halted = RecordDraft::of_halt_by(engaged, operator, START);
    assert_names(&halted, &operator, "a halt by the longest identity")?;
    let named_halt = preimage_of(&halted)?;
    assert_eq!(named_halt.len(), smallest.len() + MAX_IDENTITY_LEN);
    assert!(read_under_own_digest(&named_halt)?.is_ok());
    Ok(())
}

/// Boundary: a panel larger than the level demands is taken, and the record
/// names all of it; a release no checker is asked for may still name some.
#[test]
fn a_panel_larger_than_demanded_is_named_in_full() -> Fallible<()> {
    let panel = two("checker-bob", "checker-cara")?;
    let mut deciding = engine(600, 4)?;
    let held = deciding.decide(&action("intent-single", SINGLE)?);
    let ticket = held.ticket().copied().ok_or(FixtureError::NoTicket)?;
    deciding.adjudicate(ticket.request_id(), panel, Vote::Approve)?;
    let who = named(SINGLE, MAKER, Some(panel))?;
    assert_names(&last_draft(&deciding)?, &who, "two where one is demanded")?;
    assert_eq!(
        who.checkers(),
        [
            Some(CheckerId::parse("checker-bob")?),
            Some(CheckerId::parse("checker-cara")?)
        ]
    );
    assert_eq!(named(SINGLE, MAKER, None)?.checkers(), [None, None]);

    let mut continued = carried(MONITORED)?;
    continued.release_halt(&MakerId::parse("olga")?, Some(panel))?;
    let released = named(MONITORED, "olga", Some(panel))?;
    assert_names(
        &last_draft(&continued)?,
        &released,
        "a release with a panel",
    )?;
    assert_eq!(
        continued.decide(&action("intent-resumed", RiskLevel::LOWEST)?),
        InterceptorOutcome::Allow
    );
    Ok(())
}
