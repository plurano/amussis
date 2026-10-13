// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The public pieces the binding is built from, each on its own: the three
//! host adapters, the record frame and the outcome code.
//!
//! `host_effects.rs` reaches these pieces only through a [`Binding`]. Here
//! each one is held to its contract directly, at both ends of every bound,
//! so a change to one of them fails a test that names it.

use std::cell::RefCell;

use amussis_decision::{
    BlockReason, Clock, ClockError, DIGEST_LEN, Digest32, HaltReason, InterceptorOutcome,
    IoDeadline, LedgerSink, MAX_SIGNATURE_BYTES, RecordSigner, SignError, SignerKeyId, SinkError,
    UnixSeconds, WarningCode,
};
use amussis_decision_wasm::{
    Binding, Class, ClockAdapter, Frame, FrameParts, HostClock, HostSigner, HostSink, OutcomeCode,
    Refusal, SINK_STORED, SignerAdapter, SinkAdapter,
};

type Fallible<T> = Result<T, String>;

const KEY_ID: &str = "host-key-01";
const DEADLINE_MS: u32 = 250;

const ROUTINE: &str = concat!(
    r#"{"schema":"amussis.decision.proposal.v1","id":"intent-0001","agent":"agent-01","#,
    r#""maker":"maker-alice","action":"file-modification","target":"/srv/data/report.txt","#,
    r#""declared-tier":"tier-c-routine-bounded","oversight":"standard"}"#
);

/// A host clock that reads one fixed value.
#[derive(Debug, Clone, Copy)]
struct Reads(i64);

impl HostClock for Reads {
    fn now(&self) -> i64 {
        self.0
    }
}

/// A host signer that writes `fill` into every byte it was handed and answers
/// `answer`, whatever length that claims.
#[derive(Debug, Clone, Copy)]
struct Answers {
    answer: i32,
    fill: u8,
}

impl HostSigner for Answers {
    fn sign(&self, _digest: &[u8; DIGEST_LEN], out: &mut [u8; MAX_SIGNATURE_BYTES]) -> i32 {
        out.fill(self.fill);
        self.answer
    }
}

/// A host sink that answers `answer` and keeps what it was offered.
#[derive(Debug, Default)]
struct Keeps {
    answer: i32,
    offered: RefCell<Vec<(Vec<u8>, u32)>>,
}

impl HostSink for Keeps {
    fn append(&mut self, frame: &[u8], deadline_ms: u32) -> i32 {
        self.offered
            .borrow_mut()
            .push((frame.to_vec(), deadline_ms));
        self.answer
    }
}

/// A host that answers in earnest: the clock reads a fixed time, the signer
/// signs with the digest read backwards, and the sink stores every frame.
#[derive(Debug, Clone, Copy)]
struct Earnest;

impl HostClock for Earnest {
    fn now(&self) -> i64 {
        1_000
    }
}

impl HostSigner for Earnest {
    fn sign(&self, digest: &[u8; DIGEST_LEN], out: &mut [u8; MAX_SIGNATURE_BYTES]) -> i32 {
        for (slot, byte) in out.iter_mut().zip(digest.iter().rev()) {
            *slot = *byte;
        }
        i32::try_from(DIGEST_LEN).unwrap_or(0)
    }
}

impl HostSink for Earnest {
    fn append(&mut self, _frame: &[u8], _deadline_ms: u32) -> i32 {
        SINK_STORED
    }
}

fn key_id() -> Fallible<SignerKeyId> {
    SignerKeyId::parse(KEY_ID).map_err(|error| format!("the key id was refused: {error:?}"))
}

fn deadline() -> Fallible<IoDeadline> {
    IoDeadline::try_from_millis(DEADLINE_MS).ok_or_else(|| "a zero deadline".to_owned())
}

/// One record the engine sealed, taken from a binding over an earnest host.
fn sealed_record() -> Fallible<amussis_decision::AuditRecord> {
    let mut binding = Binding::new(KEY_ID.as_bytes(), DEADLINE_MS, Earnest, Earnest, Earnest)
        .map_err(|error| format!("the binding was refused: {error:?}"))?;
    let code = binding.decide(ROUTINE.as_bytes());
    if code.class() != Class::Allow {
        return Err(format!("the routine proposal gave {code:?}"));
    }
    binding
        .engine()
        .ledger()
        .records()
        .first()
        .copied()
        .ok_or_else(|| "the engine sealed no record".to_owned())
}

#[test]
fn the_clock_adapter_reads_every_time_from_the_epoch_on() {
    for seconds in [0, 1, 1_000, i64::MAX] {
        let read = ClockAdapter::new(Reads(seconds))
            .now()
            .map(UnixSeconds::get);
        assert_eq!(read, Ok(seconds.unsigned_abs()), "host time {seconds}");
    }
}

#[test]
fn the_clock_adapter_refuses_every_time_before_the_epoch() {
    for seconds in [-1, -1_000, i64::MIN] {
        let read = ClockAdapter::new(Reads(seconds)).now();
        assert_eq!(read, Err(ClockError::BeforeEpoch), "host time {seconds}");
    }
}

#[test]
fn the_signer_adapter_signs_under_its_key_at_the_length_the_host_gave() -> Fallible<()> {
    let digest = Digest32::from_bytes([7; DIGEST_LEN]);
    let max = i32::try_from(MAX_SIGNATURE_BYTES).map_err(|error| error.to_string())?;
    for answer in [1, 64, max] {
        let signer = SignerAdapter::new(key_id()?, Answers { answer, fill: 0xA5 });
        assert_eq!(signer.key_id(), &key_id()?);
        let signature = signer
            .sign(&digest)
            .map_err(|error| format!("answer {answer} was refused: {error:?}"))?;
        assert_eq!(
            signature.len(),
            answer.unsigned_abs() as usize,
            "answer {answer}"
        );
        assert!(
            signature.as_bytes().iter().all(|byte| *byte == 0xA5),
            "answer {answer}"
        );
        assert_eq!(signature.key_id(), &key_id()?);
    }
    Ok(())
}

#[test]
fn the_signer_adapter_reads_no_length_and_a_negative_length_as_unavailable() -> Fallible<()> {
    let digest = Digest32::from_bytes([7; DIGEST_LEN]);
    for answer in [0, -1, i32::MIN] {
        let signer = SignerAdapter::new(key_id()?, Answers { answer, fill: 0xA5 });
        assert_eq!(
            signer.sign(&digest),
            Err(SignError::Unavailable),
            "answer {answer}"
        );
    }
    Ok(())
}

#[test]
fn the_signer_adapter_refuses_a_length_past_its_buffer() -> Fallible<()> {
    let digest = Digest32::from_bytes([7; DIGEST_LEN]);
    let max = i32::try_from(MAX_SIGNATURE_BYTES).map_err(|error| error.to_string())?;
    for answer in [max + 1, i32::MAX] {
        let signer = SignerAdapter::new(key_id()?, Answers { answer, fill: 0xA5 });
        let refused = SignError::TooLong {
            max: MAX_SIGNATURE_BYTES,
            actual: answer.unsigned_abs() as usize,
        };
        assert_eq!(signer.sign(&digest), Err(refused), "answer {answer}");
    }
    Ok(())
}

#[test]
fn the_sink_adapter_hands_over_the_frame_and_the_deadline() -> Fallible<()> {
    let record = sealed_record()?;
    let mut sink = SinkAdapter::new(Keeps::default());
    assert_eq!(sink.append_record(&record, deadline()?), Ok(()));
    assert_eq!(sink.sync(deadline()?), Ok(()));
    let frame = Frame::encode(&record).ok_or("the sealed record did not frame")?;
    let offered = sink.host().offered.borrow();
    assert_eq!(
        offered.as_slice(),
        [(frame.as_slice().to_vec(), DEADLINE_MS)]
    );
    Ok(())
}

#[test]
fn the_sink_adapter_reads_every_other_answer_as_not_stored() -> Fallible<()> {
    let record = sealed_record()?;
    for answer in [1, -1, i32::MIN, i32::MAX] {
        let mut sink = SinkAdapter::new(Keeps {
            answer,
            ..Keeps::default()
        });
        let stored = sink.append_record(&record, deadline()?);
        assert_eq!(stored, Err(SinkError::Unavailable), "answer {answer}");
        assert_eq!(sink.host().offered.borrow().len(), 1, "answer {answer}");
    }
    Ok(())
}

#[test]
fn a_frame_splits_back_into_the_parts_of_its_record() -> Fallible<()> {
    let record = sealed_record()?;
    let frame = Frame::encode(&record).ok_or("the sealed record did not frame")?;
    let parts = FrameParts::split(frame.as_slice()).ok_or("the frame did not split")?;
    let preimage = record
        .body()
        .canonical_preimage()
        .map_err(|error| format!("no pre-image: {error:?}"))?;
    assert_eq!(parts.preimage(), preimage.as_slice());
    assert_eq!(parts.digest(), record.digest().to_bytes());
    assert_eq!(parts.key_id(), KEY_ID.as_bytes());
    assert_eq!(parts.signature(), record.signature().as_bytes());
    Ok(())
}

#[test]
fn an_outcome_code_carries_the_class_detail_and_halt_of_its_outcome() {
    let cases = [
        (InterceptorOutcome::Allow, (Class::Allow, 0, 0), true),
        (
            InterceptorOutcome::Warn {
                code: WarningCode::MonitoredTierB,
            },
            (Class::Warn, 1, 0),
            true,
        ),
        (
            InterceptorOutcome::Block {
                reason: BlockReason::AuditUnavailable,
            },
            (Class::Block, 2, 0),
            false,
        ),
        (
            InterceptorOutcome::Block {
                reason: BlockReason::RequestAlreadyPending,
            },
            (Class::Block, 8, 0),
            false,
        ),
        (
            InterceptorOutcome::Block {
                reason: BlockReason::KillswitchEngaged(HaltReason::OperatorStop),
            },
            (Class::Block, 1, 1),
            false,
        ),
        (
            InterceptorOutcome::Block {
                reason: BlockReason::KillswitchEngaged(HaltReason::ClockUnavailable),
            },
            (Class::Block, 1, 4),
            false,
        ),
    ];
    for (outcome, (class, detail, halt), permits) in cases {
        let code = OutcomeCode::from_outcome(&outcome);
        assert_eq!(
            (code.class(), code.detail(), code.halt()),
            (class, detail, halt),
            "{outcome:?}"
        );
        assert_eq!(code.permits_execution(), permits, "{outcome:?}");
        let packed = u32::from_le_bytes([class as u8, detail, halt, 0]);
        assert_eq!(code.to_u32(), packed, "{outcome:?}");
    }
}

#[test]
fn a_refused_code_permits_nothing_and_names_why() {
    let code = OutcomeCode::refused(Refusal::TooLong);
    assert_eq!(
        (code.class(), code.detail(), code.halt()),
        (Class::Refused, Refusal::TooLong as u8, 0)
    );
    assert!(!code.permits_execution());
}
