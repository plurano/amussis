// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! HISS-03 and the memory arithmetic behind the default bounds.
//!
//! The crate documentation claims that the decision path performs no heap
//! allocation after construction, and names the products that the default
//! bounds retain without writing a byte figure for either. Both claims are
//! executable here: if the engine reallocates any of its three retention
//! buffers, or if a bound is raised past [`MAX_RETAINED_AUDIT_BYTES`], a test in
//! this file fails. The widths are computed from `size_of` on the building
//! target, so this file, not the prose, is the authority for the numbers.
//!
//! The encoding rules are held to the same standard at the end of this file,
//! on the fixture schema of `common`, and the property they are held to is
//! narrower than the one first written down. A decoded payload owns no heap, and an escape-free payload is
//! decoded without a copy; a payload that spells the same value with a JSON
//! escape is not, because `serde_json` unescapes into a heap scratch buffer.
//! That last case is the falsifier for "decoding allocates nothing", and it is
//! asserted rather than avoided.

mod common;

use amussis_decision::{
    ActionType, ApprovalTicket, AuditRecord, BlockReason, ContractError, Correlation,
    InterceptorOutcome, MAX_CONTRACT_PAYLOAD_BYTES, MAX_LEDGER_RECORDS, MAX_PENDING_REQUESTS,
    MAX_RETAINED_AUDIT_BYTES, MAX_SIGNATURE_BYTES, MAX_TARGET_LEN, OversightClass, RequestState,
    RiskTier, TargetResource,
};

use common::{
    CORRELATION, ENVELOPE, FIXTURE_AUDIT_BOUND, Fallible, decoded, encoded, engine, envelope,
    filler, intent,
};

// --- Positive -------------------------------------------------------------

/// Fills `engine`'s registry to `holds` with distinct held requests.
fn fill_registry(engine: &mut common::TestEngine, holds: usize) -> Fallible<()> {
    for step in 0..holds {
        let proposal = intent(
            &format!("intent-hold-{step}"),
            "maker-alice",
            ActionType::PermissionEscalation,
            RiskTier::TierAConsequential,
            OversightClass::Standard,
        )?;
        assert!(engine.decide(&proposal).ticket().is_some());
    }
    Ok(())
}

/// Drives `engine` for `steps` further decisions, alternating an action that is
/// released with one that is refused, so both audit arms are exercised.
fn drive_mixed(engine: &mut common::TestEngine, steps: usize) -> Fallible<()> {
    let mut refuse_next = false;
    for step in 0..steps {
        let (action, tier) = if refuse_next {
            (
                ActionType::PermissionEscalation,
                RiskTier::TierAConsequential,
            )
        } else {
            (ActionType::FileModification, RiskTier::TierCRoutineBounded)
        };
        refuse_next = !refuse_next;
        let proposal = intent(
            &format!("intent-fill-{step}"),
            "maker-alice",
            action,
            tier,
            OversightClass::Standard,
        )?;
        let _outcome = engine.decide(&proposal);
    }
    Ok(())
}

/// Positive: driving the engine to both bounds changes no reserved capacity.
///
/// This is the falsifier for the no-allocation claim. `Vec::push` only
/// reallocates when `len == capacity`; every buffer here is reserved to its
/// bound at construction and refuses a push at that bound, so a changed
/// `reserved()` is proof that a reallocation happened on the decision path.
#[test]
fn the_decision_path_never_reallocates() -> Fallible<()> {
    let holds = 4usize;
    let mut engine = engine(600, holds)?;

    let registry_reserved = engine.registry().reserved();
    let ledger_reserved = engine.ledger().reserved();
    let sink_reserved = engine.ledger().sink().reserved();
    assert!(registry_reserved >= holds);
    assert!(ledger_reserved >= FIXTURE_AUDIT_BOUND);
    assert!(sink_reserved >= FIXTURE_AUDIT_BOUND);

    fill_registry(&mut engine, holds)?;
    drive_mixed(&mut engine, FIXTURE_AUDIT_BOUND.saturating_sub(holds))?;

    assert_eq!(
        engine.ledger().len(),
        FIXTURE_AUDIT_BOUND,
        "the ledger reached its bound exactly"
    );
    assert_eq!(
        engine.registry().reserved(),
        registry_reserved,
        "the registry reallocated on the decision path"
    );
    assert_eq!(
        engine.ledger().reserved(),
        ledger_reserved,
        "the ledger reallocated on the decision path"
    );
    assert_eq!(
        engine.ledger().sink().reserved(),
        sink_reserved,
        "the sink reallocated on the decision path"
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: one action past the ledger bound is refused, and the refusal still
/// does not reallocate.
#[test]
fn one_action_past_the_audit_bound_is_refused_without_growing() -> Fallible<()> {
    let mut engine = engine(600, 2)?;
    let ledger_reserved = engine.ledger().reserved();
    let sink_reserved = engine.ledger().sink().reserved();

    for step in 0..=FIXTURE_AUDIT_BOUND {
        let proposal = intent(
            &format!("intent-over-{step}"),
            "maker-alice",
            ActionType::FileModification,
            RiskTier::TierCRoutineBounded,
            OversightClass::Standard,
        )?;
        let outcome = engine.decide(&proposal);
        if step < FIXTURE_AUDIT_BOUND {
            assert_eq!(
                outcome,
                InterceptorOutcome::Allow,
                "step {step} is inside the bound"
            );
        } else {
            assert_eq!(
                outcome.block_reason(),
                Some(BlockReason::AuditUnavailable),
                "one past the audit bound is refused, never allowed unaudited"
            );
        }
    }
    assert_eq!(engine.ledger().len(), FIXTURE_AUDIT_BOUND);
    assert_eq!(engine.ledger().reserved(), ledger_reserved);
    assert_eq!(engine.ledger().sink().reserved(), sink_reserved);
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the retained and pending budgets, computed from `size_of`.
///
/// The crate documentation deliberately states no byte figure. This test is the
/// authority instead: it computes the record and entry widths on the target that
/// is building the crate, so raising a bound, widening the signature, growing a
/// record or changing the target's padding fails the gate rather than leaving a
/// hand-written number in the documentation quietly wrong.
#[test]
fn the_retained_and_pending_budgets_are_computed_from_size_of() {
    let record = core::mem::size_of::<AuditRecord>();
    let retained = record.saturating_mul(MAX_LEDGER_RECORDS).saturating_mul(2);
    assert!(
        record >= MAX_SIGNATURE_BYTES,
        "the record is dominated by its {MAX_SIGNATURE_BYTES}-byte inline \
         signature, but measures only {record} bytes"
    );
    assert!(
        retained <= MAX_RETAINED_AUDIT_BYTES,
        "the default bounds retain {retained} bytes ({record} per record, \
         {MAX_LEDGER_RECORDS} records, held twice), past the \
         {MAX_RETAINED_AUDIT_BYTES}-byte budget"
    );
    assert!(
        retained > 2 << 20,
        "the budget is not so slack that it would catch nothing"
    );

    let entry = core::mem::size_of::<(ApprovalTicket, RequestState)>();
    let pending = entry.saturating_mul(MAX_PENDING_REQUESTS);
    assert!(
        pending <= 1 << 20,
        "the pending registry reserves {pending} bytes ({entry} per entry, \
         {MAX_PENDING_REQUESTS} entries), which is no longer a rounding error \
         beside the audit budget"
    );

    assert_eq!(MAX_LEDGER_RECORDS, 4096);
    assert_eq!(MAX_PENDING_REQUESTS, 256);
}

// --- What decoding one payload costs --------------------------------------

/// Whether `serde_json` handed a string field a slice borrowed straight out of
/// the payload, or a copy it had to build in a heap scratch buffer first.
///
/// This is the allocation signal a test in this crate can actually observe.
/// The workspace sets `unsafe_code = "forbid"` for every target of the package,
/// so a counting `#[global_allocator]` cannot be written here: implementing
/// `GlobalAlloc` needs `unsafe impl`, which is a hard error rather than a
/// warning. The distinction below is not a proxy for the allocation, it is the
/// allocation. `serde_json` can hand a visitor a borrowed slice only while the
/// field is literally present in the input; the moment the field carries an
/// escape it must unescape into a `Vec<u8>` scratch buffer and pass a reference
/// into that buffer instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// The field was a slice of the input: no scratch, and no heap.
    Borrowed,
    /// The field carried a JSON escape, so the decoder unescaped it into a heap
    /// scratch buffer before the visitor ever saw it.
    Copied,
}

/// The visitor that records which of the two `serde_json` used.
struct ProvenanceVisitor;

impl<'de> serde::de::Visitor<'de> for ProvenanceVisitor {
    type Value = Provenance;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("any JSON string")
    }

    fn visit_borrowed_str<E: serde::de::Error>(self, _value: &'de str) -> Result<Provenance, E> {
        Ok(Provenance::Borrowed)
    }

    fn visit_str<E: serde::de::Error>(self, _value: &str) -> Result<Provenance, E> {
        Ok(Provenance::Copied)
    }
}

impl<'de> serde::Deserialize<'de> for Provenance {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(ProvenanceVisitor)
    }
}

/// Reads one field of a payload for its provenance and nothing else.
///
/// Every other field is unknown to this view and is skipped, so the witness
/// works against any schema that carries the key without naming it.
#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct CorrelationWitness {
    /// How the correlation identifier reached the visitor.
    correlation_id: Provenance,
}

/// Returns how `serde_json` delivered the correlation identifier of `text`.
///
/// # Errors
///
/// Propagates a parse failure.
fn provenance(text: &str) -> Fallible<Provenance> {
    Ok(serde_json::from_str::<CorrelationWitness>(text)?.correlation_id)
}

/// Returns `text` with the correlation identifier spelled through a `\u0069`
/// escape: the same string, one JSON escape sequence, nothing else changed.
fn escaped(text: &str) -> String {
    let plain = format!("\"{CORRELATION}\"");
    let escape = format!("\"\\u0069{}\"", CORRELATION.trim_start_matches('i'));
    text.replace(&plain, &escape)
}

/// Accepts only a `Copy` value, and returns its width.
///
/// The bound is the assertion: a `String`, a `Vec`, a `Box` or any other
/// heap-owning field anywhere inside the type makes it non-`Copy`, and this
/// stops compiling. It is a stronger statement than any run-time count, and it
/// is the half of the allocation claim that survived falsification.
fn inline_only<T: Copy>(_value: &T) -> usize {
    core::mem::size_of::<T>()
}

// --- Positive -------------------------------------------------------------

/// Positive: a decoded payload owns no heap, and a whole decoded payload fits
/// inside the same scalar bound as its wire form.
#[test]
fn a_decoded_payload_owns_no_heap() -> Fallible<()> {
    let width = inline_only(&decoded(&encoded(&envelope()?)?)?);
    assert!(width > 0);
    assert!(
        width <= MAX_CONTRACT_PAYLOAD_BYTES,
        "a decoded payload of {width} bytes is wider than the \
         {MAX_CONTRACT_PAYLOAD_BYTES}-byte bound on its wire form"
    );
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: one JSON escape makes the decoder copy a field into a heap scratch
/// buffer, so "decoding allocates nothing" is false as stated.
///
/// This is the falsifier. Both spellings are accepted and both decode to the
/// same value, so the escape is not a hostile payload that could simply be
/// refused: it is an ordinary, admissible spelling that costs heap. What is
/// true, and what the module documentation claims, is the narrower property
/// the other two tests here assert.
#[test]
fn one_json_escape_makes_the_decoder_copy_a_field_into_scratch() -> Fallible<()> {
    let plain = encoded(&envelope()?)?;
    let with_escape = escaped(&plain);
    assert_ne!(plain, with_escape, "the fixture carries the identifier");
    assert_eq!(provenance(&plain)?, Provenance::Borrowed);
    assert_eq!(
        provenance(&with_escape)?,
        Provenance::Copied,
        "an escaped field cannot be borrowed, so the decoder allocated"
    );
    assert_eq!(
        decoded(&with_escape)?,
        decoded(&plain)?,
        "the escaped spelling is admissible and decodes to the same value"
    );
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: whatever scratch a decode takes is bounded by
/// [`MAX_CONTRACT_PAYLOAD_BYTES`], because a longer payload never reaches the
/// parser at all.
///
/// The widest escape a field admits is a target resource of
/// [`MAX_TARGET_LEN`] bytes with every byte escaped, which doubles the field on
/// the wire. It still fits the payload bound, and the buffer it is unescaped
/// into is narrower than the payload that carried it. One byte past the bound
/// is refused before parsing, so no scratch is reserved for it.
#[test]
fn no_decoder_scratch_can_exceed_the_payload_bound() -> Fallible<()> {
    let mut widest = envelope()?;
    widest.target = TargetResource::parse(&"/".repeat(MAX_TARGET_LEN))?;
    let plain = encoded(&widest)?;
    let with_escapes = plain.replace('/', "\\/");
    assert!(
        with_escapes.len() > plain.len(),
        "the escape widened the field"
    );
    assert!(
        with_escapes.len() <= MAX_CONTRACT_PAYLOAD_BYTES,
        "the widest escaped payload is {} bytes, past the bound",
        with_escapes.len()
    );
    let value = decoded(&with_escapes)?;
    assert_eq!(value, widest);
    assert!(
        value.target.len() <= with_escapes.len(),
        "the buffer the field is unescaped into is narrower than the payload \
         that carried it, so the payload bound bounds it too"
    );
    assert!(value.target.len() <= MAX_CONTRACT_PAYLOAD_BYTES);

    let over_bound = filler(MAX_CONTRACT_PAYLOAD_BYTES.saturating_add(1));
    assert_eq!(
        decoded(&over_bound),
        Err(ContractError::PayloadTooLong {
            correlation: Correlation::new(ENVELOPE, None),
            max: MAX_CONTRACT_PAYLOAD_BYTES
        }),
        "one byte past the bound is refused before it is parsed"
    );
    Ok(())
}
