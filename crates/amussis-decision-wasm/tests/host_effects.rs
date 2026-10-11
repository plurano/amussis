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
    AUDIT_DOMAIN, BlockReason, DIGEST_LEN, HaltReason, LedgerHasher, MAX_IDENTITY_LEN,
    MAX_LEDGER_RECORDS, MAX_PROPOSAL_BYTES, MAX_SIGNATURE_BYTES, Sha256Hasher,
};
use amussis_decision_wasm::{
    ABI_VERSION, Binding, Class, FRAME_VERSION, HOST_MODULE, HOST_UNAVAILABLE, HostClock,
    HostSigner, HostSink, InitError, MAX_FRAME_BYTES, OutcomeCode, Refusal, SINK_STORED,
};

type Fallible<T> = Result<T, String>;

const KEY_ID: &str = "host-key-01";
const DEADLINE_MS: u32 = 250;
const START: i64 = 1_000;

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
    assert_eq!(ABI_VERSION, 1);
    assert_eq!(HOST_MODULE, "amussis_host_v1");
    assert_eq!(SINK_STORED, 0);
    assert_eq!(HOST_UNAVAILABLE, -1);
    assert_eq!(FRAME_VERSION, 1);
    assert_eq!(MAX_FRAME_BYTES, 1126);
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
        assert_eq!(world.offered.get(), 1, "answer {answer}");
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

// --- Boundary: the chain bound ----------------------------------------------

/// Boundary: the engine's chain holds `MAX_LEDGER_RECORDS` records. The
/// binding decides exactly that many, then blocks; it does not start a second
/// chain, so the host's copy stays one chain.
#[test]
fn the_chain_bound_blocks_and_no_second_chain_starts() -> Fallible<()> {
    let world = world();
    let mut binding = binding(&world)?;
    for _ in 0..MAX_LEDGER_RECORDS {
        assert_eq!(binding.decide(ROUTINE.as_bytes()).class(), Class::Allow);
    }
    let code = binding.decide(ROUTINE.as_bytes());
    assert_eq!(parts(code), block(BlockReason::AuditUnavailable));
    let after = binding.decide(ROUTINE.as_bytes());
    assert_eq!(
        parts(after),
        block(BlockReason::KillswitchEngaged(HaltReason::AuditUnavailable))
    );
    assert_eq!(world.stored.borrow().len(), MAX_LEDGER_RECORDS);
    assert_eq!(binding.engine().ledger().len(), MAX_LEDGER_RECORDS);
    Ok(())
}
