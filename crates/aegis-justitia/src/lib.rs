// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Aegis OS P06 `aegis-justitia`: the decision engine.
//!
//! The crate carries the risk-tier, maker-checker, Annex III, timeout and
//! killswitch logic as library code. Every rule is reachable through the public
//! API so the integration tests exercise the shipped logic, not a test-only
//! copy.
//!
//! Design invariants enforced here (see `AGENTS.md`):
//!
//! * no recursion: [`ledger::verify_chain_bounded`] walks a chain iteratively;
//! * every loop carries a scalar upper bound, declared as a constant below;
//! * no `unwrap`, `expect`, `panic!`, slice indexing or wrapping arithmetic;
//! * no dynamic execution and no `unsafe` (forbidden at the crate root).
//!
//! # HISS-03: what the decision path allocates
//!
//! [`JustitiaEngine::decide`] and [`JustitiaEngine::adjudicate`] perform **no
//! heap allocation after construction**. That is a structural property, not a
//! convention:
//!
//! * every value on the path ([`ActionIntent`], [`InterceptorOutcome`],
//!   [`AuditRecord`], [`identity::Identity`], [`Signature`]) is `Copy` and holds
//!   its bytes inline in a fixed-size array; the crate contains no `String`,
//!   `Box` or `Vec` field outside the three retention buffers named below;
//! * those three buffers -- the pending-request registry, the ledger's record
//!   list and the sink's record list -- are each `Vec::with_capacity(bound)` at
//!   construction and each refuses a push at `len >= bound`, so `Vec::push`
//!   never reaches its reallocation path;
//! * reclamation uses `Vec::retain`, which compacts in place and never
//!   allocates.
//!
//! `tests/allocation_bounds.rs` proves it rather than asserting it: it records
//! `reserved()` on all three buffers, drives the engine to each bound, and fails
//! if any reserved capacity changed.
//!
//! # Memory arithmetic behind the default bounds
//!
//! An [`AuditRecord`] is dominated by its [`MAX_SIGNATURE_BYTES`]-byte inline
//! signature. Milestone M02 retains every record **twice** -- once in
//! [`AuditLedger`] for the chain re-walk and once in the [`InMemorySink`] that
//! stands in for the durable sink M14 pins -- so the default retention is
//!
//! ```text
//! 2 x MAX_LEDGER_RECORDS x size_of::<AuditRecord>()
//! ```
//!
//! and the pending registry adds
//!
//! ```text
//! MAX_PENDING_REQUESTS x size_of::<(ApprovalTicket, RequestState)>()
//! ```
//!
//! No byte figure is written here, because a hand-written one drifts the moment
//! a field moves or the target changes its padding. `tests/allocation_bounds.rs`
//! computes both from `size_of` on the target that is actually building the
//! crate and fails if the retained total passes the
//! [`MAX_RETAINED_AUDIT_BYTES`] budget; the figures in that failure message are
//! the authority, not this paragraph. The point the bounds exist to make is the
//! order of magnitude: a hardened unit reserves single-digit mebibytes for P06,
//! not the gibibytes a `1 << 20` record bound would have demanded.
//!
//! # Total inventory of `unwrap_or` in the library
//!
//! HISS-07 bans `unwrap` and `expect`; `unwrap_or` is permitted because it names
//! the fallback, but every use still has to be justified rather than counted
//! loosely. There are **six**, and `tests/manifest_hygiene.rs` fails if that
//! ever stops being the exact set:
//!
//! | site | fallback | why it is unreachable or correct |
//! | :-- | :-- | :-- |
//! | `identity::Identity::as_bytes` | `&[]` | `len <= MAX_IDENTITY_LEN` by construction, so the slice always exists |
//! | `identity::TargetResource::as_bytes` | `&[]` | `len <= MAX_TARGET_LEN` by construction |
//! | `ledger::hash::CanonicalBuffer::as_slice` | `&[]` | `len <= MAX_PREIMAGE_BYTES`, enforced on every write |
//! | `ledger::signer::Signature::as_bytes` | `&[]` | `len <= MAX_SIGNATURE_BYTES`, enforced in `Signature::new` |
//! | `engine::EngineConfig::default` | one-second window | `DEFAULT_APPROVAL_TTL_SECS` is a non-zero constant |
//! | `ledger::default_service_time` | one-millisecond deadline | `DEFAULT_SINK_SERVICE_MILLIS` is a non-zero constant |
//!
//! The first four are the same shape: a bounded inline buffer returning a slice
//! of its own validated prefix. The last two convert a non-zero constant into a
//! non-zero-typed value, where the only alternative would be `expect`.
//!
//! # What milestone M14 added, and what it deliberately did not
//!
//! [`contracts`] holds the three versioned consumer schemas P06 speaks over --
//! the action proposal from P09 Minerva, the decision request to P05 Forum and
//! the signed audit record to P16 Athena -- together with the reviewed
//! hardened-unit contract. Every schema is a typed Rust struct with an explicit
//! contract version, a stable field encoding and a decoder that lands every
//! field in a fixed inline buffer. See [`contracts`] for what that does and
//! does not say about heap: an escape-free payload is decoded without one, an
//! admissible JSON escape costs the decoder a bounded scratch copy, and the
//! decoded value owns nothing either way.
//!
//! **No transport is implemented anywhere in this crate.** There is no D-Bus
//! connection, no socket, no eBPF program and no TPM2 signing: a signature
//! field is a field encoding, not a signer. eBPF compilation and verifier load
//! are M19 and M10, TPM2 sealing is M20, the Forum consumer is M16, and a
//! file-backed ledger sink is still absent.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod contracts;
pub mod effects;
pub mod engine;
pub mod error;
pub mod identity;
pub mod intent;
pub mod killswitch;
pub mod ledger;
pub mod outcome;
pub mod oversight;
pub mod registry;
pub mod risk;
pub mod time;

/// Contract version tag mixed into every audit pre-image.
pub const CONTRACT_VERSION: &str = "aegis.justitia.v1";

/// Default scalar upper bound on the number of records in one audit chain.
///
/// Chosen so that two retained copies of a full chain stay inside the
/// [`MAX_RETAINED_AUDIT_BYTES`] budget; `tests/allocation_bounds.rs` computes
/// the product from `size_of` and fails if it ever stops holding. The in-memory
/// chain is a staging window, not the archive; the durable sink that drains it
/// is M14 work.
pub const MAX_LEDGER_RECORDS: usize = 4096;

/// Scalar budget, in bytes, for every audit record the default bounds retain.
///
/// Both retained copies of the chain must fit inside this budget. A change to
/// [`MAX_LEDGER_RECORDS`], to [`MAX_SIGNATURE_BYTES`] or to the record shape
/// that breaches it fails `tests/allocation_bounds.rs`.
pub const MAX_RETAINED_AUDIT_BYTES: usize = 8 << 20;

/// Scalar upper bound on the canonical pre-image of a single audit record.
pub const MAX_PREIMAGE_BYTES: usize = 512;

/// Default scalar upper bound on concurrently pending approval requests.
///
/// This is a concurrency bound, not a lifetime cap: decided and expired tickets
/// are reclaimed by [`PendingRegistry::reclaim`] before the bound is tested, so
/// the engine cannot wedge at it.
pub const MAX_PENDING_REQUESTS: usize = 256;

/// Scalar upper bound, in bytes, on any identity string.
pub const MAX_IDENTITY_LEN: usize = 64;

/// Scalar upper bound, in bytes, on a target-resource string.
pub const MAX_TARGET_LEN: usize = 256;

/// Scalar upper bound, in bytes, on a detached record signature.
pub const MAX_SIGNATURE_BYTES: usize = 512;

/// Width of every digest this crate produces, in bytes.
pub const DIGEST_LEN: usize = 32;

/// Default approval window, in seconds, for a request that needs a checker.
pub const DEFAULT_APPROVAL_TTL_SECS: u32 = 300;

/// Shortest deadline, in milliseconds, under which [`InMemorySink`] will accept
/// a record. A caller offering less is refused with [`SinkError::WouldBlock`]
/// rather than allowed to block past its own deadline.
pub const DEFAULT_SINK_SERVICE_MILLIS: u32 = 1;

pub use crate::contracts::audit::{AuditRecordVersion, PLD_EFFECTIVE_AT, SignedAuditRecord};
pub use crate::contracts::decision_request::{
    DecisionRequest, DecisionRequestVersion, MAX_DECISION_WINDOW_SECS, MIN_DECISION_WINDOW_SECS,
};
pub use crate::contracts::encoding::{
    DIGEST_HEX_CHARS, MAX_SIGNATURE_HEX_CHARS, OversightSignature, SignatureAlgorithm,
    SignatureBytes,
};
pub use crate::contracts::graph::{
    D03_ACTION_GATE, D03_ACTION_GATE_DIRECTION, D03_ACTION_GATE_TRANSPORT, D04_SANDBOX_GATE,
    DecisionRecord, DecisionState, EdgeId, GateDirection, MAX_ADMISSION_HOPS, SandboxAdmissionPath,
    contract_edges,
};
pub use crate::contracts::proposal::{ActionProposal, ActionProposalVersion};
pub use crate::contracts::unit::{
    CONTRACT_MARKER, INSTALL_DIRECTORIES, MAX_UNIT_BYTES, MAX_UNIT_LINES, REQUIRED_DIRECTIVES,
    UnitContractError, is_installed_path, review,
};
pub use crate::contracts::{
    ContractError, Correlation, MAX_CONTRACT_PAYLOAD_BYTES, PayloadBuffer, SchemaId,
};
pub use crate::engine::{EngineConfig, JustitiaEngine};
pub use crate::error::JustitiaError;
pub use crate::identity::{
    AgentId, CheckerId, EventId, Identity, IdentityError, IntentId, MakerId, RequestId,
    SignerKeyId, TargetResource,
};
pub use crate::intent::{ActionIntent, IntentError, IntentSpec};
pub use crate::killswitch::{HaltReason, Killswitch, KillswitchState};
pub use crate::ledger::hash::{
    CanonicalBuffer, Digest32, HashAlgorithm, HashError, LedgerHasher, PreimageError,
};
pub use crate::ledger::sha256::Sha256Hasher;
pub use crate::ledger::signer::{RecordSigner, SignError, Signature, SignerBinding};
pub use crate::ledger::{
    AUDIT_DOMAIN, AuditLedger, AuditRecord, InMemorySink, IoDeadline, LedgerError, LedgerSink,
    RecordBody, RecordDraft, RecordStatus, Sequence, Sha256Ledger, SinkError, UnavailableSink,
    verify_chain, verify_chain_bounded,
};
pub use crate::outcome::{BlockReason, InterceptorOutcome, WarningCode};
pub use crate::oversight::{
    Adjudication, ApprovalTicket, CheckerSet, OversightError, VerifiedCheckerSet, Vote,
};
pub use crate::registry::{PendingRegistry, RegistryError, RequestState};
pub use crate::risk::{ActionType, OversightClass, RequiredApproval, RiskTier};
pub use crate::time::{
    Clock, ClockError, Deadline, DeadlineError, DeadlineStatus, FixedClock, MonotonicGuard, Ttl,
    UnixSeconds,
};
