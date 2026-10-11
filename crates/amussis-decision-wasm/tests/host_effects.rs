// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The binding over test hosts: what a healthy host yields, and what each
//! failing effect yields.
//!
//! The planted cases are the point of this file. For each of the three
//! effects a host is planted that cannot deliver it, in every spelling the
//! interface admits, and the binding has to block, record nothing it could
//! not seal, and stay blocked once the host recovers. A binding that put a
//! default in the effect's place (a zero time, an empty signature, a record
//! counted as stored) fails here.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use amussis_decision::{
    AUDIT_DOMAIN, BlockReason, CONTRACT_VERSION, ChainAnchor, DEFAULT_APPROVAL_TTL_SECS,
    DIGEST_LEN, Digest32, HaltReason, KillswitchState, LedgerHasher, MAX_IDENTITY_LEN,
    MAX_LEDGER_RECORDS, MAX_PROPOSAL_BYTES, MAX_SIGNATURE_BYTES, RecordStatus, RiskLevel,
    Sha256Hasher, Vote,
};
use amussis_decision_wasm::{
    ABI_VERSION, AdjudicationParts, Binding, Class, Continuation, FRAME_VERSION, FrameParts,
    HOST_MODULE, HOST_UNAVAILABLE, HaltStatus, HostClock, HostSigner, HostSink, InitError,
    MAX_ADJUDICATION_BYTES, MAX_ADJUDICATION_CHECKERS, MAX_FRAME_BYTES, MAX_RELEASE_BYTES,
    MAX_RELEASE_PERSONS, OutcomeCode, Refusal, ReleaseParts, SINK_STORED, Unadjudicated,
    VOTE_APPROVE, VOTE_REJECT,
};

type Fallible<T> = Result<T, String>;

const KEY_ID: &str = "host-key-01";
const DEADLINE_MS: u32 = 250;
const START: i64 = 1_000;

/// Offset of the hash algorithm tag in a canonical pre-image.
const ALGORITHM_AT: usize = AUDIT_DOMAIN.len() + 4 + CONTRACT_VERSION.len();
/// Offset of the digest of the record before.
const PREVIOUS_AT: usize = ALGORITHM_AT + 1 + 8;
/// Offset of the record status, behind the previous digest and the time.
const STATUS_AT: usize = PREVIOUS_AT + DIGEST_LEN + 8;
/// Offset of the halt-latch flag; the halt reason is nine bytes behind it and
/// the risk level of the halt ten.
const LATCH_AT: usize = STATUS_AT + 4;
const REASON_AT: usize = LATCH_AT + 9;
const LEVEL_AT: usize = LATCH_AT + 10;

/// The proposal spellings of an action one checker approves and of one two
/// checkers approve.
const TIER_A: (&str, &str) = ("tier-c-routine-bounded", "tier-a-consequential");
const ANNEX_III: (&str, &str) = (
    r#""oversight":"standard""#,
    r#""oversight":"annex-iii-biometric""#,
);

const ROUTINE: &str = concat!(
    r#"{"schema":"amussis.decision.proposal.v1","id":"intent-0001","agent":"agent-01","#,
    r#""maker":"maker-alice","action":"file-modification","target":"/srv/data/report.txt","#,
    r#""declared-tier":"tier-c-routine-bounded","oversight":"standard"}"#
);

/// What the test host answers, and what it was handed.
#[derive(Debug)]
struct World {
    time: Cell<i64>,
    /// `None`: sign in earnest. `Some(n)`: answer `n` whatever was asked.
    sign_answer: Cell<Option<i32>>,
    sink_answer: Cell<i32>,
    stored: RefCell<Vec<Vec<u8>>>,
    offered: Cell<u32>,
    deadlines: RefCell<Vec<u32>>,
}

#[derive(Debug, Clone)]
struct Handle(Rc<World>);

impl HostClock for Handle {
    fn now(&self) -> i64 {
        self.0.time.get()
    }
}

impl HostSigner for Handle {
    fn sign(&self, digest: &[u8; DIGEST_LEN], out: &mut [u8; MAX_SIGNATURE_BYTES]) -> i32 {
        // The test signature is the digest read backwards: it depends on every
        // byte of the digest and cannot be mistaken for the digest itself.
        for (slot, byte) in out.iter_mut().zip(digest.iter().rev()) {
            *slot = *byte;
        }
        self.0
            .sign_answer
            .get()
            .unwrap_or_else(|| i32::try_from(DIGEST_LEN).unwrap_or(HOST_UNAVAILABLE))
    }
}

impl HostSink for Handle {
    fn append(&mut self, frame: &[u8], deadline_ms: u32) -> i32 {
        self.0.offered.set(self.0.offered.get().saturating_add(1));
        self.0.deadlines.borrow_mut().push(deadline_ms);
        let answer = self.0.sink_answer.get();
        if answer == SINK_STORED {
            self.0.stored.borrow_mut().push(frame.to_vec());
        }
        answer
    }
}

type TestBinding = Binding<Handle, Handle, Handle>;

fn world() -> Rc<World> {
    Rc::new(World {
        time: Cell::new(START),
        sign_answer: Cell::new(None),
        sink_answer: Cell::new(SINK_STORED),
        stored: RefCell::new(Vec::new()),
        offered: Cell::new(0),
        deadlines: RefCell::new(Vec::new()),
    })
}

fn binding(world: &Rc<World>) -> Fallible<TestBinding> {
    let handle = Handle(Rc::clone(world));
    Binding::new(
        KEY_ID.as_bytes(),
        DEADLINE_MS,
        handle.clone(),
        handle.clone(),
        handle,
    )
    .map_err(|error| format!("the binding was refused: {error:?}"))
}

fn routine_with(old: &str, new: &str) -> Fallible<String> {
    if ROUTINE.contains(old) {
        Ok(ROUTINE.replacen(old, new, 1))
    } else {
        Err(format!("the fixture does not contain {old}"))
    }
}

fn block(reason: BlockReason) -> (Class, u8, u8) {
    (Class::Block, reason.tag(), reason.halt_tag())
}

fn parts(code: OutcomeCode) -> (Class, u8, u8) {
    (code.class(), code.detail(), code.halt())
}

/// One frame, split into its parts; an error when a length runs past the end
/// or bytes are left over.
struct Parsed<'a> {
    version: u8,
    preimage: &'a [u8],
    digest: &'a [u8],
    key_id: &'a [u8],
    signature: &'a [u8],
}

fn take<'a>(rest: &mut &'a [u8], len: usize) -> Fallible<&'a [u8]> {
    let (head, tail) = rest
        .split_at_checked(len)
        .ok_or_else(|| format!("the frame ends {len} bytes early"))?;
    *rest = tail;
    Ok(head)
}

fn take_u16(rest: &mut &[u8]) -> Fallible<usize> {
    let raw = take(rest, 2)?;
    let pair: [u8; 2] = raw.try_into().map_err(|_| "two bytes".to_owned())?;
    Ok(usize::from(u16::from_le_bytes(pair)))
}

fn parse(frame: &[u8]) -> Fallible<Parsed<'_>> {
    let mut rest = frame;
    let version = *take(&mut rest, 1)?.first().ok_or("no version byte")?;
    let preimage_len = take_u16(&mut rest)?;
    let preimage = take(&mut rest, preimage_len)?;
    let digest = take(&mut rest, DIGEST_LEN)?;
    let key_len = usize::from(*take(&mut rest, 1)?.first().ok_or("no key length")?);
    let key_id = take(&mut rest, key_len)?;
    let signature_len = take_u16(&mut rest)?;
    let signature = take(&mut rest, signature_len)?;
    if rest.is_empty() {
        Ok(Parsed {
            version,
            preimage,
            digest,
            key_id,
            signature,
        })
    } else {
        Err(format!("{} bytes follow the frame", rest.len()))
    }
}

fn stored(world: &World, index: usize) -> Fallible<Vec<u8>> {
    world
        .stored
        .borrow()
        .get(index)
        .cloned()
        .ok_or_else(|| format!("the sink holds no record {index}"))
}

// --- Positive ---------------------------------------------------------------

/// Positive: a routine proposal is allowed, and its record is in the host's
/// sink, offered with the deadline the host set.
#[test]
fn a_routine_proposal_is_allowed_and_its_record_reaches_the_sink() -> Fallible<()> {
    let world = world();
    let mut binding = binding(&world)?;
    let code = binding.decide(ROUTINE.as_bytes());
    assert_eq!(parts(code), (Class::Allow, 0, 0));
    assert!(code.permits_execution());
    assert_eq!(code.to_u32(), 0);
    assert_eq!(world.stored.borrow().len(), 1);
    assert_eq!(*world.deadlines.borrow(), vec![DEADLINE_MS]);
    assert_eq!(binding.engine().ledger().len(), 1);
    Ok(())
}

/// Positive: the frame is enough to check the record. The digest is the hash
/// of the pre-image, the signature is the host's over that digest, and the
/// key identifier is the one the host named.
#[test]
fn a_frame_carries_what_a_reader_needs_to_check_it() -> Fallible<()> {
    let world = world();
    binding(&world)?.decide(ROUTINE.as_bytes());
    let frame = stored(&world, 0)?;
    let parsed = parse(&frame)?;
    assert_eq!(parsed.version, FRAME_VERSION);
    assert!(parsed.preimage.starts_with(AUDIT_DOMAIN));
    let digest = Sha256Hasher::digest(parsed.preimage).map_err(|error| error.to_string())?;
    assert_eq!(parsed.digest, digest.as_bytes());
    assert_eq!(parsed.key_id, KEY_ID.as_bytes());
    let expected: Vec<u8> = digest.as_bytes().iter().rev().copied().collect();
    assert_eq!(parsed.signature, expected.as_slice());
    assert!(frame.len() <= MAX_FRAME_BYTES);
    Ok(())
}

/// Positive: the second record names the first, so the host's copy is a chain.
#[test]
fn the_second_record_carries_the_digest_of_the_first() -> Fallible<()> {
    let world = world();
    let mut binding = binding(&world)?;
    binding.decide(ROUTINE.as_bytes());
    binding.decide(ROUTINE.as_bytes());
    let first = stored(&world, 0)?;
    let second = stored(&world, 1)?;
    let first_digest = parse(&first)?.digest.to_vec();
    let second_preimage = parse(&second)?.preimage.to_vec();
    assert!(
        second_preimage
            .windows(DIGEST_LEN)
            .any(|window| window == first_digest.as_slice()),
        "the second pre-image must contain the first digest"
    );
    Ok(())
}

/// Positive: each tier yields its class, and the class is the low byte.
#[test]
fn each_tier_yields_its_class() -> Fallible<()> {
    let world = world();
    let mut binding = binding(&world)?;
    let monitored = routine_with("tier-c-routine-bounded", "tier-b-material-reversible")?;
    let code = binding.decide(monitored.as_bytes());
    assert_eq!(parts(code), (Class::Warn, 1, 0));
    assert!(code.permits_execution());
    assert_eq!(code.to_u32(), 0x0101);
    let held = routine_with("tier-c-routine-bounded", "tier-a-consequential")?;
    let code = binding.decide(held.as_bytes());
    assert_eq!(parts(code), (Class::RequireApproval, 0, 0));
    assert!(!code.permits_execution());
    assert_eq!(code.to_u32(), 2);
    assert_eq!(world.stored.borrow().len(), 2);
    Ok(())
}

/// Positive: the constants a host is written against.
#[test]
fn the_interface_names_are_fixed() {
    assert_eq!(ABI_VERSION, 4);
    assert_eq!(HOST_MODULE, "amussis_host_v1");
    assert_eq!(SINK_STORED, 0);
    assert_eq!(HOST_UNAVAILABLE, -1);
    assert_eq!(FRAME_VERSION, 1);
    assert_eq!(MAX_FRAME_BYTES, 1126);
    assert_eq!(MAX_RELEASE_PERSONS, 3);
    assert_eq!(MAX_RELEASE_BYTES, 196);
}

// --- Planted: the clock -----------------------------------------------------

/// Planted: a host whose clock is unreadable. The action is blocked for the
/// clock, the halt latch is engaged, and a clock that reads again does not
/// lift it.
#[test]
fn an_unreadable_clock_blocks_and_stays_blocked() -> Fallible<()> {
    for reading in [-1, i64::MIN] {
        let world = world();
        let mut binding = binding(&world)?;
        world.time.set(reading);
        let code = binding.decide(ROUTINE.as_bytes());
        assert_eq!(parts(code), block(BlockReason::ClockUnavailable));
        assert!(!code.permits_execution());
        world.time.set(START);
        let after = binding.decide(ROUTINE.as_bytes());
        assert_eq!(
            parts(after),
            block(BlockReason::KillswitchEngaged(HaltReason::ClockUnavailable))
        );
    }
    Ok(())
}

/// Planted: a host whose clock steps backwards between two decisions.
#[test]
fn a_clock_that_steps_back_blocks() -> Fallible<()> {
    let world = world();
    let mut binding = binding(&world)?;
    assert_eq!(binding.decide(ROUTINE.as_bytes()).class(), Class::Allow);
    world.time.set(START.saturating_sub(1));
    let code = binding.decide(ROUTINE.as_bytes());
    assert_eq!(parts(code), block(BlockReason::ClockUnavailable));
    Ok(())
}

// --- Planted: the signer ----------------------------------------------------

/// Planted: a host that cannot sign, in every answer that is not a length
/// within the bound. The action is blocked, nothing unsigned is offered to
/// the sink, and a signer that works again does not lift the halt.
#[test]
fn a_signer_that_cannot_sign_blocks_and_nothing_is_stored() -> Fallible<()> {
    let past_bound = i32::try_from(MAX_SIGNATURE_BYTES)
        .map_err(|error| error.to_string())?
        .saturating_add(1);
    for answer in [0, HOST_UNAVAILABLE, i32::MIN, past_bound, i32::MAX] {
        let world = world();
        let mut binding = binding(&world)?;
        world.sign_answer.set(Some(answer));
        let code = binding.decide(ROUTINE.as_bytes());
        assert_eq!(
            parts(code),
            block(BlockReason::AuditUnavailable),
            "answer {answer}"
        );
        assert_eq!(world.offered.get(), 0, "answer {answer}");
        assert!(binding.engine().ledger().is_empty(), "answer {answer}");
        world.sign_answer.set(None);
        let after = binding.decide(ROUTINE.as_bytes());
        assert_eq!(
            parts(after),
            block(BlockReason::KillswitchEngaged(HaltReason::AuditUnavailable)),
            "answer {answer}"
        );
    }
    Ok(())
}

/// Boundary: a signature is taken at the length the host states, from one
/// byte to the bound.
#[test]
fn a_signature_is_taken_at_the_length_the_host_states() -> Fallible<()> {
    let bound = i32::try_from(MAX_SIGNATURE_BYTES).map_err(|error| error.to_string())?;
    for length in [1, 3, bound] {
        let world = world();
        let mut binding = binding(&world)?;
        world.sign_answer.set(Some(length));
        assert_eq!(binding.decide(ROUTINE.as_bytes()).class(), Class::Allow);
        let frame = stored(&world, 0)?;
        let expected = usize::try_from(length).map_err(|error| error.to_string())?;
        assert_eq!(parse(&frame)?.signature.len(), expected);
    }
    Ok(())
}

// --- Planted: the sink ------------------------------------------------------

/// Planted: a host that cannot store the record, in every answer but the one
/// that means stored. The action is blocked, the engine keeps no record the
/// host does not hold, and a sink that works again does not lift the halt.
/// The sink is offered two records: the one of the decision, and the one of
/// the halt that follows.
#[test]
fn a_sink_that_cannot_store_blocks_and_nothing_is_kept() -> Fallible<()> {
    for answer in [1, 2, HOST_UNAVAILABLE, i32::MIN, i32::MAX] {
        let world = world();
        let mut binding = binding(&world)?;
        world.sink_answer.set(answer);
        let code = binding.decide(ROUTINE.as_bytes());
        assert_eq!(
            parts(code),
            block(BlockReason::AuditUnavailable),
            "answer {answer}"
        );
        assert_eq!(world.offered.get(), 2, "answer {answer}");
        assert!(world.stored.borrow().is_empty(), "answer {answer}");
        assert!(binding.engine().ledger().is_empty(), "answer {answer}");
        world.sink_answer.set(SINK_STORED);
        let after = binding.decide(ROUTINE.as_bytes());
        assert_eq!(
            parts(after),
            block(BlockReason::KillswitchEngaged(HaltReason::AuditUnavailable)),
            "answer {answer}"
        );
    }
    Ok(())
}

// --- Negative: set-up and input ----------------------------------------------

/// Negative: a binding is not set up over a key identifier the engine would
/// not accept, or over a sink deadline of zero.
#[test]
fn set_up_refuses_a_bad_key_identifier_and_a_zero_deadline() {
    let handle = || Handle(world());
    let long = "k".repeat(MAX_IDENTITY_LEN.saturating_add(1));
    for key_id in [&b""[..], b"bad key!", &[0xff, 0xfe], long.as_bytes()] {
        let refused = Binding::new(key_id, DEADLINE_MS, handle(), handle(), handle());
        assert_eq!(refused.err(), Some(InitError::KeyId), "{key_id:?}");
    }
    let refused = Binding::new(KEY_ID.as_bytes(), 0, handle(), handle(), handle());
    assert_eq!(refused.err(), Some(InitError::Deadline));
}

/// Negative: input the binding refuses never reaches the engine, the signer
/// or the sink, and never permits the action.
#[test]
fn refused_input_reaches_no_effect() -> Fallible<()> {
    let world = world();
    let mut binding = binding(&world)?;
    let long = " ".repeat(MAX_PROPOSAL_BYTES.saturating_add(1));
    let other_version = routine_with("proposal.v1", "proposal.v2")?;
    let below_floor = routine_with("file-modification", "file-deletion")?;
    let cases: [(&[u8], Refusal); 5] = [
        (&[0xff, 0xfe, 0xfd], Refusal::NotUtf8),
        (long.as_bytes(), Refusal::TooLong),
        (other_version.as_bytes(), Refusal::UnknownVersion),
        (b"{", Refusal::Malformed),
        (below_floor.as_bytes(), Refusal::IntentRefused),
    ];
    for (text, why) in cases {
        let code = binding.decide(text);
        assert_eq!(code, OutcomeCode::refused(why));
        assert_eq!(parts(code), (Class::Refused, why as u8, 0));
        assert!(!code.permits_execution());
    }
    assert_eq!(OutcomeCode::refused(Refusal::Malformed).to_u32(), 0x0504);
    assert_eq!(world.offered.get(), 0);
    assert!(binding.engine().ledger().is_empty());
    Ok(())
}

/// Negative: the two refusals and the two set-up errors only the export file
/// produces keep their numbers.
#[test]
fn the_numbers_of_the_export_file_are_fixed() {
    assert_eq!(
        OutcomeCode::refused(Refusal::NotInitialised).to_u32(),
        0x0104
    );
    assert_eq!(OutcomeCode::refused(Refusal::Busy).to_u32(), 0x0704);
    assert_eq!(InitError::AlreadyInitialised as u32, 1);
    assert_eq!(InitError::KeyId as u32, 2);
    assert_eq!(InitError::Deadline as u32, 3);
    assert_eq!(InitError::Busy as u32, 4);
}

/// Negative: the set-up errors of a continuation keep their numbers.
#[test]
fn the_numbers_of_a_refused_continuation_are_fixed() {
    assert_eq!(InitError::Head as u32, 5);
    assert_eq!(InitError::HeadDigest as u32, 6);
    assert_eq!(InitError::Compromised as u32, 7);
    assert_eq!(InitError::Release as u32, 8);
    assert_eq!(InitError::NotHalted as u32, 9);
    assert_eq!(InitError::Approval as u32, 10);
    assert_eq!(InitError::ReleaseFailed as u32, 11);
}

// --- The chain past the window, and across a new engine ------------------------

/// One frame built from its parts, as the binding writes it.
fn framed(preimage: &[u8], digest: &[u8], key_id: &[u8], signature: &[u8]) -> Fallible<Vec<u8>> {
    let preimage_len = u16::try_from(preimage.len()).map_err(|error| error.to_string())?;
    let key_len = u8::try_from(key_id.len()).map_err(|error| error.to_string())?;
    let signature_len = u16::try_from(signature.len()).map_err(|error| error.to_string())?;
    Ok([
        &[FRAME_VERSION][..],
        &preimage_len.to_le_bytes(),
        preimage,
        digest,
        &[key_len],
        key_id,
        &signature_len.to_le_bytes(),
        signature,
    ]
    .concat())
}

/// The frame of `frame`'s record with one pre-image byte set and the digest
/// taken again: a record that hashes, with content the engine did not write.
fn rehashed(frame: &[u8], at: usize, value: u8) -> Fallible<Vec<u8>> {
    let parsed = parse(frame)?;
    let mut preimage = parsed.preimage.to_vec();
    *preimage.get_mut(at).ok_or("no such pre-image byte")? = value;
    let digest = Sha256Hasher::digest(&preimage).map_err(|error| error.to_string())?;
    framed(
        &preimage,
        digest.as_bytes(),
        parsed.key_id,
        parsed.signature,
    )
}

/// `frame` with the byte at `at` changed and nothing else.
fn edited(frame: &[u8], at: usize) -> Fallible<Vec<u8>> {
    let mut bytes = frame.to_vec();
    let byte = bytes.get_mut(at).ok_or("no such frame byte")?;
    *byte ^= 0x01;
    Ok(bytes)
}

fn last_stored(world: &World) -> Fallible<Vec<u8>> {
    world
        .stored
        .borrow()
        .last()
        .cloned()
        .ok_or_else(|| "the sink holds no record".to_owned())
}

/// The bytes of a release: the releasing person first, then the checkers.
fn release(persons: &[&str]) -> Fallible<Vec<u8>> {
    let count = u8::try_from(persons.len()).map_err(|error| error.to_string())?;
    let mut bytes = vec![count];
    for person in persons {
        bytes.push(u8::try_from(person.len()).map_err(|error| error.to_string())?);
        bytes.extend_from_slice(person.as_bytes());
    }
    Ok(bytes)
}

/// No release: the chain continues in the state its head carries.
const KEEP: &[u8] = &[];

/// A new binding over the same host, continuing from `head`.
fn continued(world: &Rc<World>, head: &[u8], release: &[u8]) -> Result<TestBinding, InitError> {
    let handle = Handle(Rc::clone(world));
    Binding::continue_from(
        KEY_ID.as_bytes(),
        DEADLINE_MS,
        Continuation::new(head, release),
        handle.clone(),
        handle.clone(),
        handle,
    )
}

fn resumed(world: &Rc<World>, head: &[u8], release: &[u8]) -> Fallible<TestBinding> {
    continued(world, head, release).map_err(|error| format!("the head was refused: {error:?}"))
}

/// What a release of the stored chain by `persons` yields.
fn released(world: &Rc<World>, persons: &[&str]) -> Fallible<Result<TestBinding, InitError>> {
    Ok(continued(world, &last_stored(world)?, &release(persons)?))
}

/// Walks the host's store as one chain: every record hashes to its digest,
/// counts one up from the record before it and names that record's digest.
fn walk_store(world: &World) -> Fallible<u64> {
    let mut previous = Digest32::GENESIS;
    let mut sequence = 0u64;
    for frame in world.stored.borrow().iter() {
        let parsed = parse(frame)?;
        let raw: [u8; DIGEST_LEN] = parsed.digest.try_into().map_err(|_| "digest width")?;
        let digest = Digest32::from_bytes(raw);
        let anchor = ChainAnchor::from_preimage::<Sha256Hasher>(parsed.preimage, &digest)
            .map_err(|error| error.to_string())?;
        sequence = sequence.saturating_add(1);
        let link = parsed
            .preimage
            .get(PREVIOUS_AT..PREVIOUS_AT.saturating_add(DIGEST_LEN));
        if anchor.sequence().get() != sequence || link != Some(previous.as_bytes().as_slice()) {
            return Err(format!("record {sequence} does not follow the one before"));
        }
        previous = digest;
    }
    Ok(sequence)
}

fn allow(binding: &mut TestBinding, count: usize) -> Fallible<()> {
    for index in 0..count {
        let class = binding.decide(ROUTINE.as_bytes()).class();
        if class != Class::Allow {
            return Err(format!("decision {index} gave {class:?}"));
        }
    }
    Ok(())
}

/// Boundary: the engine's window holds `MAX_LEDGER_RECORDS` records. The
/// binding decides that many with the window intact, drops the window at the
/// next decision and goes on; the host's copy stays one chain.
#[test]
fn the_chain_runs_past_the_window_as_one_chain() -> Fallible<()> {
    let world = world();
    let mut binding = binding(&world)?;
    allow(&mut binding, MAX_LEDGER_RECORDS)?;
    assert_eq!(binding.engine().ledger().len(), MAX_LEDGER_RECORDS);
    assert_eq!(binding.engine().audit_room(), 0);
    allow(&mut binding, 3)?;
    assert_eq!(binding.engine().ledger().len(), 3);
    assert_eq!(binding.engine().killswitch(), KillswitchState::Armed);
    let stored = u64::try_from(MAX_LEDGER_RECORDS.saturating_add(3)).map_err(|e| e.to_string())?;
    assert_eq!(walk_store(&world), Ok(stored));
    Ok(())
}

/// Positive: a new binding continues from the last stored frame, and the
/// store holds one chain across the two engines.
#[test]
fn a_new_binding_continues_the_chain_from_its_stored_head() -> Fallible<()> {
    let world = world();
    allow(&mut binding(&world)?, 3)?;
    let mut second = resumed(&world, &last_stored(&world)?, KEEP)?;
    assert!(second.engine().ledger().is_empty());
    allow(&mut second, 2)?;
    assert_eq!(walk_store(&world), Ok(5));
    Ok(())
}

/// Positive: the library reads back the frame it wrote, part by part.
#[test]
fn a_stored_frame_splits_into_the_parts_it_was_written_from() -> Fallible<()> {
    let world = world();
    allow(&mut binding(&world)?, 1)?;
    let frame = stored(&world, 0)?;
    let parsed = parse(&frame)?;
    let parts = FrameParts::split(&frame).ok_or("the frame was not read")?;
    assert_eq!(parts.preimage(), parsed.preimage);
    assert_eq!(parts.digest().as_slice(), parsed.digest);
    assert_eq!(parts.key_id(), KEY_ID.as_bytes());
    assert_eq!(parts.signature(), parsed.signature);
    Ok(())
}

/// Planted: a continuation from a record that is not the last one. The
/// binding cannot know the store, so it starts; the store then holds two
/// records with one sequence number and the walk refuses it.
#[test]
fn a_continuation_from_another_record_than_the_head_breaks_the_stored_chain() -> Fallible<()> {
    let world = world();
    allow(&mut binding(&world)?, 3)?;
    let not_the_head = stored(&world, 1)?;
    allow(&mut resumed(&world, &not_the_head, KEEP)?, 1)?;
    assert_eq!(
        walk_store(&world),
        Err("record 4 does not follow the one before".to_owned())
    );
    Ok(())
}

/// Planted: a head whose bytes were edited after it was stored, in the
/// pre-image and in the digest. No engine is set up over it.
#[test]
fn a_head_that_does_not_hash_to_its_digest_is_refused() -> Fallible<()> {
    let world = world();
    allow(&mut binding(&world)?, 1)?;
    let head = stored(&world, 0)?;
    let preimage_len = parse(&head)?.preimage.len();
    let first_digest_byte = preimage_len.saturating_add(3);
    for at in [
        3,
        LATCH_AT.saturating_add(3),
        preimage_len.saturating_add(2),
        first_digest_byte,
    ] {
        let refused = continued(&world, &edited(&head, at)?, KEEP);
        assert_eq!(refused.err(), Some(InitError::HeadDigest), "byte {at}");
    }
    assert_eq!(world.stored.borrow().len(), 1);
    Ok(())
}

/// Planted: bytes that are not one record frame of this contract, among them
/// records that hash and carry content the engine does not write.
#[test]
fn bytes_that_are_no_head_frame_are_refused() -> Fallible<()> {
    let world = world();
    allow(&mut binding(&world)?, 1)?;
    let head = stored(&world, 0)?;
    let parsed = parse(&head)?;
    let cases = [
        ("empty", Vec::new()),
        ("another frame version", edited(&head, 0)?),
        (
            "one byte short",
            head.get(..head.len().saturating_sub(1))
                .unwrap_or_default()
                .to_vec(),
        ),
        ("one byte long", [head.as_slice(), &[0]].concat()),
        (
            "no key identifier",
            framed(parsed.preimage, parsed.digest, b"", parsed.signature)?,
        ),
        (
            "no signature",
            framed(parsed.preimage, parsed.digest, parsed.key_id, b"")?,
        ),
        ("another hash algorithm", rehashed(&head, ALGORITHM_AT, 2)?),
        ("a latch flag that is none", rehashed(&head, LATCH_AT, 2)?),
        (
            "a halt reason that is none",
            rehashed(&rehashed(&head, LATCH_AT, 1)?, REASON_AT, 9)?,
        ),
    ];
    let olga = release(&["olga"])?;
    for (name, bytes) in cases {
        for asked in [KEEP, olga.as_slice()] {
            let refused = continued(&world, &bytes, asked);
            assert_eq!(refused.err(), Some(InitError::Head), "{name}");
        }
    }
    Ok(())
}

/// Boundary: the parts of a frame at their bounds are read, one past is not.
#[test]
fn a_frame_is_read_up_to_the_bounds_of_its_parts() -> Fallible<()> {
    let world = world();
    allow(&mut binding(&world)?, 1)?;
    let head = stored(&world, 0)?;
    let parsed = parse(&head)?;
    let key = [b'k'; MAX_IDENTITY_LEN + 1];
    let signature = [7u8; MAX_SIGNATURE_BYTES + 1];
    let fits = framed(
        parsed.preimage,
        parsed.digest,
        key.get(1..).unwrap_or_default(),
        signature.get(1..).unwrap_or_default(),
    )?;
    assert!(FrameParts::split(&fits).is_some());
    let long_key = framed(parsed.preimage, parsed.digest, &key, parsed.signature)?;
    assert_eq!(FrameParts::split(&long_key), None);
    let long_signature = framed(parsed.preimage, parsed.digest, parsed.key_id, &signature)?;
    assert_eq!(FrameParts::split(&long_signature), None);
    Ok(())
}

/// A host whose clock failed once, while the engine decided `proposal`: the
/// store ends on the record of that block, written with the halt latch
/// engaged at the risk level of that proposal.
fn halted_over(proposal: &str) -> Fallible<Rc<World>> {
    let world = world();
    let mut binding = binding(&world)?;
    allow(&mut binding, 1)?;
    world.time.set(-1);
    let code = binding.decide(proposal.as_bytes());
    world.time.set(START);
    if parts(code) == block(BlockReason::ClockUnavailable) && world.stored.borrow().len() == 2 {
        Ok(world)
    } else {
        Err(format!("the fixture did not halt with a record: {code:?}"))
    }
}

/// A chain halted at the lowest level: one person releases it.
fn halted_world() -> Fallible<Rc<World>> {
    halted_over(ROUTINE)
}

/// A chain halted at a level whose actions take `change` of the routine
/// proposal to spell.
fn halted_at(change: (&str, &str)) -> Fallible<Rc<World>> {
    halted_over(&routine_with(change.0, change.1)?)
}

/// The level byte of the last stored record.
fn stored_level(world: &World) -> Fallible<u8> {
    let head = last_stored(world)?;
    parse(&head)?
        .preimage
        .get(LEVEL_AT)
        .copied()
        .ok_or_else(|| "the record has no level byte".to_owned())
}

/// A host effect that fails: its name, what plants the fault, what mends it.
type Fault = (&'static str, fn(&World), fn(&World));

/// A refused release leaves the store as it was and the chain halted.
fn assert_still_halted(world: &Rc<World>, records: usize) -> Fallible<()> {
    assert_eq!(world.stored.borrow().len(), records);
    let kept = resumed(world, &last_stored(world)?, KEEP)?;
    assert_ne!(kept.engine().killswitch(), KillswitchState::Armed);
    Ok(())
}

/// Planted: a chain that ends halted. A new binding over it blocks as the old
/// one did; a restart is no release.
#[test]
fn a_chain_that_ends_halted_continues_halted() -> Fallible<()> {
    let world = halted_world()?;
    let mut binding = resumed(&world, &last_stored(&world)?, KEEP)?;
    let code = binding.decide(ROUTINE.as_bytes());
    assert_eq!(
        parts(code),
        block(BlockReason::KillswitchEngaged(HaltReason::ClockUnavailable))
    );
    assert!(!code.permits_execution());
    let again = resumed(&world, &last_stored(&world)?, KEEP)?;
    assert_ne!(again.engine().killswitch(), KillswitchState::Armed);
    Ok(())
}

/// Positive: the lowest level is released by one person. The release is a
/// record of its own, the engine decides again, and the store shows the halt,
/// the release and the next decision in one chain.
#[test]
fn the_lowest_level_is_released_by_one_person() -> Fallible<()> {
    let world = halted_world()?;
    assert_eq!(stored_level(&world)?, RiskLevel::LOWEST.tag());
    let mut binding = released(&world, &["olga"])?.map_err(|error| format!("{error:?}"))?;
    assert_eq!(binding.engine().killswitch(), KillswitchState::Armed);
    assert_eq!(world.stored.borrow().len(), 3);
    allow(&mut binding, 1)?;
    assert_eq!(walk_store(&world), Ok(4));
    let halted = stored(&world, 1)?;
    let release = stored(&world, 2)?;
    assert_eq!(parse(&halted)?.preimage.get(LATCH_AT), Some(&1));
    let release = parse(&release)?.preimage;
    assert_eq!(
        release.get(STATUS_AT),
        Some(&RecordStatus::HaltReleased.tag())
    );
    assert_eq!(release.get(LATCH_AT), Some(&0));
    Ok(())
}

/// Planted, both ways: a release without the approval the halted level
/// demands is refused, and the same release with it passes. One checker for
/// a level whose actions take one, two for a level whose actions take two;
/// the releasing person is no checker of the own release, and one person is
/// not two checkers.
#[test]
fn a_release_without_the_needed_approval_is_refused() -> Fallible<()> {
    let single: [&[&str]; 2] = [&["olga"], &["olga", "olga"]];
    let dual: [&[&str]; 5] = [
        &["olga"],
        &["olga", "petra"],
        &["olga", "petra", "petra"],
        &["olga", "petra", "olga"],
        &["olga", "olga", "petra"],
    ];
    let cases: [(_, &[&[&str]], &[&str]); 2] = [
        (TIER_A, &single, &["olga", "petra"]),
        (ANNEX_III, &dual, &["olga", "petra", "quinn"]),
    ];
    for (level, lacking, enough) in cases {
        let world = halted_at(level)?;
        for persons in lacking {
            let refused = released(&world, persons)?;
            assert_eq!(refused.err(), Some(InitError::Approval), "{persons:?}");
            assert_still_halted(&world, 2)?;
        }
        let mut binding = released(&world, enough)?.map_err(|error| format!("{error:?}"))?;
        assert_eq!(binding.engine().killswitch(), KillswitchState::Armed);
        allow(&mut binding, 1)?;
        assert_eq!(walk_store(&world), Ok(4));
    }
    Ok(())
}

/// Boundary: the level of a halt is what the head record states, and the
/// highest level takes two checkers whatever the action was. A head halted
/// at the lowest level, with the level byte set to the highest and hashed
/// again, is no longer released by one person or with one checker.
#[test]
fn the_level_of_the_head_record_decides_the_approval() -> Fallible<()> {
    let world = halted_world()?;
    let halted = last_stored(&world)?;
    let head = rehashed(&halted, LEVEL_AT, RiskLevel::HIGHEST.tag())?;
    for persons in [&["olga"][..], &["olga", "petra"]] {
        let refused = continued(&world, &head, &release(persons)?);
        assert_eq!(refused.err(), Some(InitError::Approval), "{persons:?}");
    }
    let passed = continued(&world, &head, &release(&["olga", "petra", "quinn"])?);
    assert!(passed.is_ok());
    for none in [0, RiskLevel::HIGHEST.tag().saturating_add(1)] {
        let head = rehashed(&halted, LEVEL_AT, none)?;
        let refused = continued(&world, &head, KEEP);
        assert_eq!(refused.err(), Some(InitError::Head), "level {none}");
    }
    Ok(())
}

/// Planted: the level of a halt travels with every record written under it.
/// A chain halted at a level that takes one checker is continued halted,
/// refuses a routine action there, and is continued again from the record of
/// that refusal: the release still takes the checker.
#[test]
fn the_level_of_a_halt_is_carried_over_every_continuation() -> Fallible<()> {
    let world = halted_at(TIER_A)?;
    let level = stored_level(&world)?;
    assert_ne!(level, RiskLevel::LOWEST.tag());
    let mut kept = resumed(&world, &last_stored(&world)?, KEEP)?;
    assert_eq!(kept.decide(ROUTINE.as_bytes()).class(), Class::Block);
    assert_eq!(world.stored.borrow().len(), 3);
    assert_eq!(stored_level(&world)?, level);
    let refused = released(&world, &["olga"])?;
    assert_eq!(refused.err(), Some(InitError::Approval));
    assert!(released(&world, &["olga", "petra"])?.is_ok());
    Ok(())
}

/// Negative: a release asked for a chain that is not halted is refused, and
/// nothing is written.
#[test]
fn a_release_of_a_chain_that_is_not_halted_is_refused() -> Fallible<()> {
    let world = world();
    allow(&mut binding(&world)?, 2)?;
    for persons in [&["olga"][..], &["olga", "petra", "quinn"]] {
        let refused = released(&world, persons)?;
        assert_eq!(refused.err(), Some(InitError::NotHalted), "{persons:?}");
    }
    assert_eq!(world.stored.borrow().len(), 2);
    Ok(())
}

/// Planted: a release the engine approved and could not record. Each effect
/// fails in turn; no binding is set up, the store is as it was, and the same
/// release from the same head passes once the host delivers.
#[test]
fn a_release_that_cannot_be_recorded_sets_up_no_binding() -> Fallible<()> {
    let world = halted_world()?;
    let faults: [Fault; 3] = [
        ("clock", |w| w.time.set(-1), |w| w.time.set(START)),
        (
            "signer",
            |w| w.sign_answer.set(Some(0)),
            |w| w.sign_answer.set(None),
        ),
        (
            "sink",
            |w| w.sink_answer.set(1),
            |w| w.sink_answer.set(SINK_STORED),
        ),
    ];
    for (name, plant, mend) in faults {
        plant(&world);
        let refused = released(&world, &["olga"])?;
        mend(&world);
        assert_eq!(refused.err(), Some(InitError::ReleaseFailed), "{name}");
        assert_still_halted(&world, 2)?;
    }
    assert!(released(&world, &["olga"])?.is_ok());
    assert_eq!(walk_store(&world), Ok(3));
    Ok(())
}

/// Negative: release bytes that are no release set up no binding, whatever
/// the chain.
#[test]
fn release_bytes_that_are_no_release_are_refused() -> Fallible<()> {
    let world = halted_world()?;
    let long = "p".repeat(MAX_IDENTITY_LEN.saturating_add(1));
    let cases: [(&str, Vec<u8>); 10] = [
        ("no person", vec![0]),
        ("a count of zero before one person", vec![0, 1, b'a']),
        (
            "a count of four before three persons",
            vec![4, 1, b'a', 1, b'b', 1, b'c'],
        ),
        ("four persons", release(&["a", "b", "c", "d"])?),
        (
            "a count beyond the persons",
            vec![2, 4, b'o', b'l', b'g', b'a'],
        ),
        (
            "bytes behind the last person",
            [release(&["olga"])?, vec![0]].concat(),
        ),
        ("an empty identity", vec![1, 0]),
        ("an identity past its bound", release(&[long.as_str()])?),
        ("an identity that is no text", vec![1, 2, 0xff, 0xfe]),
        (
            "an identity outside the character set",
            release(&["bad name!"])?,
        ),
    ];
    for (name, bytes) in cases {
        let refused = continued(&world, &last_stored(&world)?, &bytes);
        assert_eq!(refused.err(), Some(InitError::Release), "{name}");
    }
    assert_still_halted(&world, 2)
}

/// Boundary: release bytes split into one to three persons, each identity up
/// to its bound, and into nothing else.
#[test]
fn release_bytes_split_into_their_persons() -> Fallible<()> {
    let widest = "p".repeat(MAX_IDENTITY_LEN);
    let one = release(&["olga"])?;
    let parts = ReleaseParts::split(&one).ok_or("one person was not read")?;
    assert_eq!(parts.releaser(), b"olga");
    assert_eq!(parts.checkers(), [None, None]);
    let two = release(&["olga", "petra"])?;
    let parts = ReleaseParts::split(&two).ok_or("two persons were not read")?;
    assert_eq!(parts.checkers(), [Some(&b"petra"[..]), None]);
    let three = release(&[widest.as_str(), widest.as_str(), widest.as_str()])?;
    assert_eq!(three.len(), MAX_RELEASE_BYTES);
    let parts = ReleaseParts::split(&three).ok_or("three persons were not read")?;
    assert_eq!(parts.releaser(), widest.as_bytes());
    assert_eq!(parts.checkers(), [Some(widest.as_bytes()); 2]);
    let too_wide = "p".repeat(MAX_IDENTITY_LEN.saturating_add(1));
    for bytes in [
        Vec::new(),
        vec![0],
        vec![0, 1, b'a'],
        vec![4, 1, b'a', 1, b'b', 1, b'c'],
        vec![1],
        vec![1, 0],
        vec![1, 5, b'o'],
        release(&[too_wide.as_str()])?,
        release(&["a", "b", "c", "d"])?,
        [one.as_slice(), &[0]].concat(),
    ] {
        assert_eq!(ReleaseParts::split(&bytes), None, "{bytes:?}");
    }
    Ok(())
}

/// Planted: a chain halted as compromised. It continues halted, and the
/// release is refused whoever approves it.
#[test]
fn a_chain_halted_as_compromised_is_not_released() -> Fallible<()> {
    let world = halted_world()?;
    let tag = HaltReason::LedgerCompromised.tag();
    let head = rehashed(&last_stored(&world)?, REASON_AT, tag)?;
    for persons in [&["olga"][..], &["olga", "petra", "quinn"]] {
        let refused = continued(&world, &head, &release(persons)?);
        assert_eq!(refused.err(), Some(InitError::Compromised), "{persons:?}");
    }
    let mut kept = resumed(&world, &head, KEEP)?;
    assert_eq!(
        parts(kept.decide(ROUTINE.as_bytes())),
        block(BlockReason::KillswitchEngaged(
            HaltReason::LedgerCompromised
        ))
    );
    Ok(())
}

/// Boundary: a halt whose record never reached the store. The sink failed, so
/// the store ends on a record written with the latch armed, and a
/// continuation from it starts armed: the chain cannot carry what it was
/// never given. Once the sink stores again, the next record the halted engine
/// writes carries the halt, and a continuation from that record is halted.
#[test]
fn a_halt_that_reached_no_record_is_not_carried_over() -> Fallible<()> {
    let world = world();
    let mut first = binding(&world)?;
    allow(&mut first, 1)?;
    world.sink_answer.set(1);
    let code = first.decide(ROUTINE.as_bytes());
    assert_eq!(parts(code), block(BlockReason::AuditUnavailable));
    assert_ne!(first.engine().killswitch(), KillswitchState::Armed);
    world.sink_answer.set(SINK_STORED);
    let second = resumed(&world, &last_stored(&world)?, KEEP)?;
    assert_eq!(second.engine().killswitch(), KillswitchState::Armed);
    assert_eq!(first.decide(ROUTINE.as_bytes()).class(), Class::Block);
    assert_eq!(world.stored.borrow().len(), 2);
    let third = resumed(&world, &last_stored(&world)?, KEEP)?;
    assert_ne!(third.engine().killswitch(), KillswitchState::Armed);
    Ok(())
}

/// Negative: a continuation is refused over the same settings a first set-up
/// is refused over, before the head is read.
#[test]
fn a_continuation_refuses_a_bad_key_identifier_and_a_zero_deadline() -> Fallible<()> {
    let world = world();
    allow(&mut binding(&world)?, 1)?;
    let head = stored(&world, 0)?;
    let handle = || Handle(Rc::clone(&world));
    let from = Continuation::new(&head, KEEP);
    assert_eq!((from.head(), from.release()), (head.as_slice(), KEEP));
    let refused = Binding::continue_from(b"", DEADLINE_MS, from, handle(), handle(), handle());
    assert_eq!(refused.err(), Some(InitError::KeyId));
    let key_id = KEY_ID.as_bytes();
    let refused = Binding::continue_from(key_id, 0, from, handle(), handle(), handle());
    assert_eq!(refused.err(), Some(InitError::Deadline));
    Ok(())
}

// --- The decision of a held action ---------------------------------------------

/// The intent id the held action of these tests is proposed under.
const HELD: &str = "intent-held-1";

/// The signer and the sink, each failing in turn.
const RECORD_FAULTS: [Fault; 2] = [
    (
        "signer",
        |w| w.sign_answer.set(Some(0)),
        |w| w.sign_answer.set(None),
    ),
    (
        "sink",
        |w| w.sink_answer.set(1),
        |w| w.sink_answer.set(SINK_STORED),
    ),
];

/// The bytes of an adjudication, as a host writes them.
fn adjudication(vote: u8, request: &str, checkers: &[&str]) -> Fallible<Vec<u8>> {
    let width = |text: &str| u8::try_from(text.len()).map_err(|error| error.to_string());
    let mut bytes = vec![vote, width(request)?];
    bytes.extend_from_slice(request.as_bytes());
    bytes.push(u8::try_from(checkers.len()).map_err(|error| error.to_string())?);
    for checker in checkers {
        bytes.push(width(checker)?);
        bytes.extend_from_slice(checker.as_bytes());
    }
    Ok(bytes)
}

/// An approval of the held action by `checkers`.
fn approval(checkers: &[&str]) -> Fallible<Vec<u8>> {
    adjudication(VOTE_APPROVE, HELD, checkers)
}

/// The code of an adjudication the engine did not take.
fn untaken(why: Unadjudicated, halt: Option<HaltReason>) -> (Class, u8, u8) {
    (
        Class::NotAdjudicated,
        why as u8,
        halt.map_or(0, HaltReason::tag),
    )
}

/// A binding that holds one action: the routine proposal under [`HELD`],
/// spelled with `change`.
fn holding(world: &Rc<World>, change: (&str, &str)) -> Fallible<TestBinding> {
    let mut binding = binding(world)?;
    let proposal = routine_with(change.0, change.1)?.replacen("intent-0001", HELD, 1);
    let code = binding.decide(proposal.as_bytes());
    if parts(code) == (Class::RequireApproval, 0, 0) && !binding.engine().registry().is_empty() {
        Ok(binding)
    } else {
        Err(format!("the fixture holds no action: {code:?}"))
    }
}

/// The byte at `at` of the pre-image of the last stored record.
fn stored_byte(world: &World, at: usize) -> Fallible<u8> {
    let head = last_stored(world)?;
    parse(&head)?
        .preimage
        .get(at)
        .copied()
        .ok_or_else(|| format!("the record has no byte {at}"))
}

/// Positive: one checker approves a held action. The approval is a record of
/// the chain under the intent id of the proposal, the action may proceed, and
/// the action is decided once.
#[test]
fn an_approval_is_a_record_and_lets_the_held_action_proceed() -> Fallible<()> {
    let world = world();
    let mut binding = holding(&world, TIER_A)?;
    let code = binding.adjudicate(&approval(&["carol"])?);
    assert_eq!(parts(code), (Class::Allow, 0, 0));
    assert!(code.permits_execution());
    assert_eq!(
        stored_byte(&world, STATUS_AT)?,
        RecordStatus::Approved.tag()
    );
    let record = last_stored(&world)?;
    assert!(
        parse(&record)?
            .preimage
            .windows(HELD.len())
            .any(|window| window == HELD.as_bytes()),
        "the record of the vote names the intent id"
    );
    let again = binding.adjudicate(&approval(&["carol"])?);
    assert_eq!(parts(again), untaken(Unadjudicated::AlreadyDecided, None));
    assert!(!again.permits_execution());
    assert_eq!(walk_store(&world), Ok(2));
    Ok(())
}

/// Positive: a rejection is a decision and a record, and permits nothing; an
/// approval that follows it is not taken.
#[test]
fn a_rejection_is_a_record_and_permits_nothing() -> Fallible<()> {
    let world = world();
    let mut binding = holding(&world, TIER_A)?;
    let code = binding.adjudicate(&adjudication(VOTE_REJECT, HELD, &["carol"])?);
    assert_eq!(parts(code), (Class::Rejected, 0, 0));
    assert!(!code.permits_execution());
    assert_eq!(code.to_u32(), 5);
    assert_eq!(
        stored_byte(&world, STATUS_AT)?,
        RecordStatus::Rejected.tag()
    );
    let after = binding.adjudicate(&approval(&["carol"])?);
    assert_eq!(parts(after), untaken(Unadjudicated::AlreadyDecided, None));
    assert!(!after.permits_execution());
    assert_eq!(walk_store(&world), Ok(2));
    Ok(())
}

/// A set of checkers, as a test names it.
type Panel = &'static [&'static str];

/// Planted, both ways: the checkers are held to the approval rule of the
/// action. A panel that is too small, names one person twice or names the
/// maker of the proposal is not taken and records nothing; the action stays
/// held, and the panel its level demands is taken.
#[test]
fn the_checkers_are_held_to_the_approval_rule_of_the_action() -> Fallible<()> {
    let one: [Panel; 3] = [
        &["maker-alice"],
        &["carol", "carol"],
        &["carol", "maker-alice"],
    ];
    let two: [Panel; 4] = [
        &["carol"],
        &["maker-alice"],
        &["carol", "carol"],
        &["maker-alice", "carol"],
    ];
    let cases: [((&str, &str), Panel, &[Panel]); 2] = [
        (TIER_A, &["carol"], &one),
        (ANNEX_III, &["carol", "dave"], &two),
    ];
    for (change, full, short) in cases {
        let world = world();
        let mut binding = holding(&world, change)?;
        for panel in short {
            let code = binding.adjudicate(&approval(panel)?);
            assert_eq!(
                parts(code),
                untaken(Unadjudicated::Approval, None),
                "{panel:?}"
            );
            assert!(!code.permits_execution(), "{panel:?}");
        }
        assert_eq!(world.stored.borrow().len(), 1);
        let code = binding.adjudicate(&approval(full)?);
        assert_eq!(parts(code), (Class::Allow, 0, 0), "{full:?}");
    }
    Ok(())
}

/// Planted: an adjudication for an action that is not held. Nothing was
/// proposed, the action was allowed and never held, or another action is the
/// held one: the engine takes no vote, records nothing and permits nothing.
#[test]
fn an_adjudication_for_an_action_that_is_not_held_is_not_taken() -> Fallible<()> {
    let not_held = untaken(Unadjudicated::UnknownRequest, None);
    let world = world();
    let mut binding = binding(&world)?;
    for vote in [VOTE_APPROVE, VOTE_REJECT] {
        let code = binding.adjudicate(&adjudication(vote, HELD, &["carol"])?);
        assert_eq!(parts(code), not_held, "nothing was proposed, vote {vote}");
        assert!(!code.permits_execution());
    }
    assert_eq!(world.offered.get(), 0);
    allow(&mut binding, 1)?;
    let code = binding.adjudicate(&adjudication(VOTE_APPROVE, "intent-0001", &["carol"])?);
    assert_eq!(parts(code), not_held, "an allowed action is not held");
    let mut held = holding(&world, TIER_A)?;
    let code = held.adjudicate(&adjudication(VOTE_APPROVE, "intent-held-2", &["carol"])?);
    assert_eq!(parts(code), not_held, "another action is the held one");
    assert!(!code.permits_execution());
    assert_eq!(world.stored.borrow().len(), 2);
    Ok(())
}

/// Planted: a held action is not carried over a continuation. The engine that
/// continues the chain holds nothing, and the action stays unreleased.
#[test]
fn a_held_action_stays_unreleased_after_a_continuation() -> Fallible<()> {
    let world = world();
    drop(holding(&world, TIER_A)?);
    let mut binding = resumed(&world, &last_stored(&world)?, KEEP)?;
    assert!(binding.engine().registry().is_empty());
    let code = binding.adjudicate(&approval(&["carol"])?);
    assert_eq!(parts(code), untaken(Unadjudicated::UnknownRequest, None));
    assert!(!code.permits_execution());
    assert_eq!(world.stored.borrow().len(), 1);
    Ok(())
}

/// One vote under a host that cannot record it: no vote is taken, the hold
/// is released without a decision, the engine halts, and a host that
/// delivers again finds it halted.
fn unrecorded_vote(fault: Fault, vote: u8) -> Fallible<()> {
    let (name, plant, mend) = fault;
    let halted = Some(HaltReason::AuditUnavailable);
    let world = world();
    let mut binding = holding(&world, TIER_A)?;
    plant(&world);
    let code = binding.adjudicate(&adjudication(vote, HELD, &["carol"])?);
    assert_eq!(
        parts(code),
        untaken(Unadjudicated::Unrecorded, halted),
        "{name}, vote {vote}"
    );
    assert!(!code.permits_execution(), "{name}");
    assert_eq!(world.stored.borrow().len(), 1, "{name}");
    assert!(binding.engine().registry().is_empty(), "{name}");
    mend(&world);
    let after = binding.adjudicate(&adjudication(vote, HELD, &["carol"])?);
    assert_eq!(
        parts(after),
        untaken(Unadjudicated::Halted, halted),
        "{name}"
    );
    assert_eq!(
        parts(binding.decide(ROUTINE.as_bytes())),
        block(BlockReason::KillswitchEngaged(HaltReason::AuditUnavailable)),
        "{name}"
    );
    Ok(())
}

/// Planted: a host that cannot sign the record of a vote, or cannot store it.
/// An approval that is not in the chain did not happen.
#[test]
fn a_vote_that_cannot_be_signed_or_stored_is_no_vote_and_halts() -> Fallible<()> {
    for fault in RECORD_FAULTS {
        for vote in [VOTE_APPROVE, VOTE_REJECT] {
            unrecorded_vote(fault, vote)?;
        }
    }
    Ok(())
}

/// Planted, both ways: a clock that is unreadable when the decision arrives.
/// No vote is taken and the engine halts at the level of the held action; an
/// adjudication that names no held action halts at the highest level.
#[test]
fn an_adjudication_under_an_unreadable_clock_halts_at_the_level_in_hand() -> Fallible<()> {
    let halted = Some(HaltReason::ClockUnavailable);
    let fault_world = halted_at(TIER_A)?;
    let held_level = stored_level(&fault_world)?;
    assert_ne!(held_level, RiskLevel::HIGHEST.tag());
    let cases = [
        (HELD, held_level),
        ("intent-held-2", RiskLevel::HIGHEST.tag()),
    ];
    for (request, level) in cases {
        let world = world();
        let mut binding = holding(&world, TIER_A)?;
        let bytes = adjudication(VOTE_APPROVE, request, &["carol"])?;
        world.time.set(-1);
        let code = binding.adjudicate(&bytes);
        world.time.set(START);
        assert_eq!(
            parts(code),
            untaken(Unadjudicated::ClockUnavailable, halted),
            "{request}"
        );
        assert!(!code.permits_execution(), "{request}");
        assert_eq!(
            stored_byte(&world, STATUS_AT)?,
            RecordStatus::HaltEngaged.tag()
        );
        assert_eq!(stored_level(&world)?, level, "{request}");
        let after = binding.adjudicate(&bytes);
        assert_eq!(
            parts(after),
            untaken(Unadjudicated::Halted, halted),
            "{request}"
        );
    }
    Ok(())
}

/// Boundary: a held action is decided inside its approval window. One second
/// before the window closes the approval is taken; at the second it closes
/// it is not, and nothing is recorded.
#[test]
fn a_held_action_is_decided_only_inside_its_approval_window() -> Fallible<()> {
    let window = i64::from(DEFAULT_APPROVAL_TTL_SECS);
    let due = START.saturating_add(window);
    let open = world();
    let mut binding = holding(&open, TIER_A)?;
    open.time.set(due.saturating_sub(1));
    let code = binding.adjudicate(&approval(&["carol"])?);
    assert_eq!(parts(code), (Class::Allow, 0, 0));
    let late = world();
    let mut binding = holding(&late, TIER_A)?;
    late.time.set(due);
    let code = binding.adjudicate(&approval(&["carol"])?);
    assert_eq!(parts(code), untaken(Unadjudicated::Expired, None));
    assert!(!code.permits_execution());
    assert_eq!(late.stored.borrow().len(), 1);
    Ok(())
}

/// Negative: a halted engine takes no decision of a held action, approval or
/// rejection.
#[test]
fn a_halted_engine_takes_no_adjudication() -> Fallible<()> {
    let world = world();
    let mut binding = holding(&world, TIER_A)?;
    assert_eq!(binding.halt(1), HaltStatus::Recorded);
    for vote in [VOTE_APPROVE, VOTE_REJECT] {
        let code = binding.adjudicate(&adjudication(vote, HELD, &["carol"])?);
        assert_eq!(
            parts(code),
            untaken(Unadjudicated::Halted, Some(HaltReason::OperatorStop)),
            "vote {vote}"
        );
        assert!(!code.permits_execution());
    }
    assert_eq!(world.stored.borrow().len(), 2);
    Ok(())
}

/// Negative: bytes that are no adjudication never reach the engine, record
/// nothing and leave the action held.
#[test]
fn adjudication_bytes_that_are_no_adjudication_are_refused() -> Fallible<()> {
    let world = world();
    let mut binding = holding(&world, TIER_A)?;
    let long = "p".repeat(MAX_IDENTITY_LEN.saturating_add(1));
    let good = approval(&["carol"])?;
    let cases: [(&str, Vec<u8>); 14] = [
        ("no bytes", Vec::new()),
        ("a vote byte of zero", adjudication(0, HELD, &["carol"])?),
        ("a vote byte of three", adjudication(3, HELD, &["carol"])?),
        ("no checker", adjudication(VOTE_APPROVE, HELD, &[])?),
        (
            "three checkers",
            adjudication(VOTE_APPROVE, HELD, &["a", "b", "c"])?,
        ),
        ("a count beyond the checkers", vec![1, 1, b'i', 2, 1, b'a']),
        (
            "a count of zero before two checkers",
            vec![1, 1, b'i', 0, 1, b'a', 1, b'b'],
        ),
        (
            "a count of three before two checkers",
            vec![1, 1, b'i', 3, 1, b'a', 1, b'b'],
        ),
        ("bytes behind the last checker", [&good[..], &[0]].concat()),
        ("an empty intent id", vec![1, 0, 1, 1, b'a']),
        (
            "an intent id past its bound",
            adjudication(VOTE_APPROVE, &long, &["carol"])?,
        ),
        (
            "an intent id outside the character set",
            adjudication(VOTE_APPROVE, "bad id!", &["carol"])?,
        ),
        (
            "a checker outside the character set",
            adjudication(VOTE_APPROVE, HELD, &["carol", "bad name!"])?,
        ),
        (
            "a checker that is no text",
            vec![1, 1, b'i', 1, 2, 0xff, 0xfe],
        ),
    ];
    for (name, bytes) in cases {
        let code = binding.adjudicate(&bytes);
        assert_eq!(code, OutcomeCode::refused(Refusal::Adjudication), "{name}");
        assert!(!code.permits_execution(), "{name}");
    }
    assert_eq!(OutcomeCode::refused(Refusal::Adjudication).to_u32(), 0x0804);
    assert_eq!(world.stored.borrow().len(), 1);
    assert_eq!(parts(binding.adjudicate(&good)), (Class::Allow, 0, 0));
    Ok(())
}

/// Boundary: adjudication bytes split into the vote, the intent id and one or
/// two checkers, each identity up to its bound, and into nothing else.
#[test]
fn adjudication_bytes_split_into_their_parts() -> Fallible<()> {
    let widest = "p".repeat(MAX_IDENTITY_LEN);
    let one = approval(&["carol"])?;
    let parts = AdjudicationParts::split(&one).ok_or("one checker was not read")?;
    assert_eq!(parts.vote(), Vote::Approve);
    assert_eq!(parts.request(), HELD.as_bytes());
    assert_eq!((parts.first(), parts.second()), (&b"carol"[..], None));
    let panel = [widest.as_str(), widest.as_str()];
    let two = adjudication(VOTE_REJECT, &widest, &panel)?;
    assert_eq!(two.len(), MAX_ADJUDICATION_BYTES);
    let parts = AdjudicationParts::split(&two).ok_or("two checkers were not read")?;
    assert_eq!(parts.vote(), Vote::Reject);
    assert_eq!(parts.request(), widest.as_bytes());
    assert_eq!(parts.first(), widest.as_bytes());
    assert_eq!(parts.second(), Some(widest.as_bytes()));
    Ok(())
}

/// Boundary: adjudication bytes that end early, name more than they carry or
/// hold an identity past its bound split into nothing.
#[test]
fn adjudication_bytes_cut_short_split_into_nothing() -> Fallible<()> {
    let too_wide = "p".repeat(MAX_IDENTITY_LEN.saturating_add(1));
    for bytes in [
        vec![VOTE_APPROVE],
        vec![VOTE_APPROVE, 1, b'i'],
        vec![VOTE_APPROVE, 1, b'i', 1],
        vec![VOTE_APPROVE, 1, b'i', 1, 5, b'c'],
        vec![VOTE_APPROVE, 1, b'i', 2, 1, b'c'],
        vec![VOTE_APPROVE, 1, b'i', 1, 0],
        adjudication(VOTE_APPROVE, HELD, &[too_wide.as_str()])?,
        adjudication(VOTE_APPROVE, &too_wide, &["carol"])?,
    ] {
        assert_eq!(AdjudicationParts::split(&bytes), None, "{bytes:?}");
    }
    Ok(())
}

// --- The operator halt -------------------------------------------------------

/// Positive: an operator halt is a record of the chain at the level the host
/// names, for every level, and the engine blocks from then on.
#[test]
fn an_operator_halt_is_a_record_at_the_level_it_names() -> Fallible<()> {
    let stopped = block(BlockReason::KillswitchEngaged(HaltReason::OperatorStop));
    for tag in RiskLevel::LOWEST.tag()..=RiskLevel::HIGHEST.tag() {
        let world = world();
        let mut binding = binding(&world)?;
        allow(&mut binding, 1)?;
        assert_eq!(binding.halt(u32::from(tag)), HaltStatus::Recorded);
        assert_eq!(
            stored_byte(&world, STATUS_AT)?,
            RecordStatus::HaltEngaged.tag()
        );
        assert_eq!(stored_byte(&world, LATCH_AT)?, 1);
        assert_eq!(
            stored_byte(&world, REASON_AT)?,
            HaltReason::OperatorStop.tag()
        );
        assert_eq!(stored_level(&world)?, tag);
        let code = binding.decide(ROUTINE.as_bytes());
        assert_eq!(parts(code), stopped, "level {tag}");
        assert!(!code.permits_execution());
        assert_eq!(walk_store(&world), Ok(3));
    }
    Ok(())
}

/// Planted: a level value that is the tag of no level. The halt is not
/// refused for it and stands at the highest level, also where the low byte
/// of the value is the tag of a lower one.
#[test]
fn an_operator_halt_at_no_level_stands_at_the_highest() -> Fallible<()> {
    assert_eq!((RiskLevel::LOWEST.tag(), RiskLevel::HIGHEST.tag()), (1, 6));
    for level in [0, 7, 255, 256, 257, 0x0100_0003, u32::MAX] {
        let world = world();
        let mut binding = binding(&world)?;
        assert_eq!(binding.halt(level), HaltStatus::Recorded, "level {level}");
        assert_eq!(
            stored_level(&world)?,
            RiskLevel::HIGHEST.tag(),
            "level {level}"
        );
        assert_eq!(walk_store(&world), Ok(1));
    }
    Ok(())
}

/// A binding halted by the operator under a host that cannot record the
/// halt: the engine is halted all the same and blocks while the fault lasts.
fn halted_unrecorded(fault: Fault) -> Fallible<(Rc<World>, TestBinding)> {
    let (name, plant, mend) = fault;
    let world = world();
    let mut binding = binding(&world)?;
    allow(&mut binding, 1)?;
    plant(&world);
    assert_eq!(binding.halt(2), HaltStatus::Unrecorded, "{name}");
    assert_ne!(binding.engine().killswitch(), KillswitchState::Armed);
    let code = binding.decide(ROUTINE.as_bytes());
    assert_eq!(
        parts(code),
        block(BlockReason::KillswitchEngaged(HaltReason::OperatorStop)),
        "{name}"
    );
    assert!(!code.permits_execution(), "{name}");
    assert_eq!(world.stored.borrow().len(), 1, "{name}");
    mend(&world);
    Ok((world, binding))
}

/// Planted: a host that cannot sign the record of a halt, or cannot store
/// it. The engine is halted all the same and blocks while the fault lasts;
/// the stored chain shows the halt once the host delivers again.
#[test]
fn a_halt_that_cannot_be_recorded_is_still_a_halt() -> Fallible<()> {
    let stopped = block(BlockReason::KillswitchEngaged(HaltReason::OperatorStop));
    for fault in RECORD_FAULTS {
        let (world, mut binding) = halted_unrecorded(fault)?;
        assert_eq!(binding.halt(2), HaltStatus::Recorded, "{}", fault.0);
        assert_eq!(stored_byte(&world, LATCH_AT)?, 1, "{}", fault.0);
        assert_eq!(stored_level(&world)?, 2, "{}", fault.0);
        assert_eq!(parts(binding.decide(ROUTINE.as_bytes())), stopped);
    }
    Ok(())
}

/// Boundary: a halt is never made weaker. A second halt at a stricter level
/// raises the level and is a record; one at a lower level, or at no level
/// where the highest stands, changes nothing and writes nothing.
#[test]
fn a_second_halt_never_lowers_the_level() -> Fallible<()> {
    let world = world();
    let mut binding = binding(&world)?;
    let steps = [
        (1, 1, 1),
        (3, 3, 2),
        (1, 3, 2),
        (6, 6, 3),
        (3, 6, 3),
        (0, 6, 3),
    ];
    for (asked, stands, records) in steps {
        assert_eq!(binding.halt(asked), HaltStatus::Recorded);
        assert_eq!(stored_level(&world)?, stands, "asked {asked}");
        assert_eq!(world.stored.borrow().len(), records, "asked {asked}");
    }
    assert_eq!(walk_store(&world), Ok(3));
    Ok(())
}

/// Planted, both ways: an operator halt is released as every halt is, at a
/// continuation and with the approval of the level it stands at.
#[test]
fn an_operator_halt_is_released_with_the_approval_of_its_level() -> Fallible<()> {
    let world = world();
    let mut halted = binding(&world)?;
    assert_eq!(halted.halt(3), HaltStatus::Recorded);
    drop(halted);
    let refused = released(&world, &["olga"])?;
    assert_eq!(refused.err(), Some(InitError::Approval));
    assert_still_halted(&world, 1)?;
    let mut binding =
        released(&world, &["olga", "petra"])?.map_err(|error| format!("{error:?}"))?;
    assert_eq!(binding.engine().killswitch(), KillswitchState::Armed);
    allow(&mut binding, 1)?;
    assert_eq!(walk_store(&world), Ok(3));
    Ok(())
}

/// Boundary: an adjudication and a halt that find the engine's window full
/// drop it as a decision does, and their records go on the one chain.
#[test]
fn an_adjudication_and_a_halt_run_past_a_full_window() -> Fallible<()> {
    let world = world();
    let mut binding = holding(&world, TIER_A)?;
    let rest = MAX_LEDGER_RECORDS.saturating_sub(1);
    allow(&mut binding, rest)?;
    assert_eq!(binding.engine().audit_room(), 0);
    let code = binding.adjudicate(&approval(&["carol"])?);
    assert_eq!(parts(code), (Class::Allow, 0, 0));
    assert_eq!(binding.engine().ledger().len(), 1);
    allow(&mut binding, rest)?;
    assert_eq!(binding.engine().audit_room(), 0);
    assert_eq!(binding.halt(1), HaltStatus::Recorded);
    assert_eq!(binding.engine().ledger().len(), 1);
    let stored = MAX_LEDGER_RECORDS.saturating_mul(2).saturating_add(1);
    let stored = u64::try_from(stored).map_err(|error| error.to_string())?;
    assert_eq!(walk_store(&world), Ok(stored));
    Ok(())
}

/// Negative: the numbers of an adjudication and of a halt are fixed.
#[test]
fn the_numbers_of_an_adjudication_and_of_a_halt_are_fixed() {
    assert_eq!((Class::Rejected as u8, Class::NotAdjudicated as u8), (5, 6));
    assert_eq!(Refusal::Adjudication as u8, 8);
    assert_eq!((VOTE_APPROVE, VOTE_REJECT), (1, 2));
    assert_eq!(MAX_ADJUDICATION_CHECKERS, 2);
    assert_eq!(MAX_ADJUDICATION_BYTES, 197);
    let details = [
        Unadjudicated::Halted,
        Unadjudicated::UnknownRequest,
        Unadjudicated::AlreadyDecided,
        Unadjudicated::Expired,
        Unadjudicated::Approval,
        Unadjudicated::ClockUnavailable,
        Unadjudicated::Unrecorded,
        Unadjudicated::Engine,
    ];
    assert_eq!(details.map(|detail| detail as u8), [1, 2, 3, 4, 5, 6, 7, 8]);
    let statuses = [
        HaltStatus::Recorded,
        HaltStatus::NotInitialised,
        HaltStatus::Busy,
        HaltStatus::Unrecorded,
    ];
    assert_eq!(statuses.map(|status| status as u32), [0, 1, 2, 3]);
}
