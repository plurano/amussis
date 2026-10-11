// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The decision engine as a WebAssembly module.
//!
//! Built for `wasm32-unknown-unknown`, this crate is one module that a host
//! program instantiates in its own process; `bindings/go` is the host for Go
//! programs. The module cannot reach a clock, a key or a disk by itself. The
//! host hands in all three as functions, and the module refuses to
//! instantiate when one of them is missing.
//!
//! # Imports, module `amussis_host_v1`
//!
//! | Function | Signature | Answer |
//! | :--- | :--- | :--- |
//! | `clock_now` | `() -> i64` | Whole seconds since the Unix epoch. Negative: the clock is unreadable. |
//! | `signer_sign` | `(digest: i32, out: i32, out_capacity: i32) -> i32` | Reads 32 bytes at `digest`, writes the signature at `out`, returns its length. Zero, negative or above `out_capacity`: not signed. |
//! | `sink_append` | `(frame: i32, frame_len: i32, deadline_ms: i32) -> i32` | Stores the framed record ([`wire`]) durably within the deadline and returns `0`. Every other value: not stored. |
//!
//! A failed effect is never replaced by a default. An unreadable clock, a
//! record that cannot be signed and a record that cannot be stored each block
//! the action and engage the engine's halt latch, as the engine does for its
//! own effects; [`host`] is the code that reads the answers.
//!
//! # Exports
//!
//! | Export | Signature | Meaning |
//! | :--- | :--- | :--- |
//! | `memory` | memory | The module's linear memory. |
//! | `amussis_abi_version` | `() -> i32` | [`ABI_VERSION`]. |
//! | `amussis_input` | `() -> i32` | Address of the input buffer. |
//! | `amussis_input_capacity` | `() -> i32` | Its size in bytes, the proposal bound. |
//! | `amussis_init` | `(key_id_len: i32, io_deadline_ms: i32) -> i32` | Sets up the engine; the signer key identifier is in the input buffer. `0`, or an [`InitError`] number. |
//! | `amussis_continue` | `(key_id_len: i32, head_len: i32, release_len: i32, io_deadline_ms: i32) -> i32` | Sets up the engine as the continuation of a stored chain; the input buffer holds the signer key identifier, the frame ([`wire`]) of the chain's last stored record and the release of its halt ([`ReleaseParts`]; `release_len` zero keeps the halt). `0`, or an [`InitError`] number. |
//! | `amussis_decide` | `(len: i32) -> i32` | Decides the proposal text in the input buffer; returns the outcome code. |
//! | `amussis_adjudicate` | `(len: i32) -> i32` | Brings the checkers' decision of a held action to the engine; the input buffer holds the adjudication ([`AdjudicationParts`]). Returns the outcome code. |
//! | `amussis_halt` | `(level: i32, by_len: i32) -> i32` | Halts the engine as the stop of the person whose identity is in the input buffer, at the risk level `level` is the tag of (`1` to `6`); every other value halts at the highest level. `0`, or a [`HaltStatus`] number. |
//!
//! # Outcome code
//!
//! Three bytes, lowest first: the [`Class`], a detail byte and a halt byte.
//! Only the classes `0` (allow) and `1` (warn) permit the action; a host
//! treats every class it does not know as a refusal.
//!
//! | Class | Detail byte | Halt byte |
//! | :--- | :--- | :--- |
//! | `0` allow | `0` | `0` |
//! | `1` warn | warning tag (`1` monitored tier B) | `0` |
//! | `2` require approval | `0` | `0` |
//! | `3` block | block-reason tag of the engine | halt-reason tag when the halt latch caused the block |
//! | `4` refused by the binding | [`Refusal`] number | `0` |
//! | `5` rejected by the checkers | `0` | `0` |
//! | `6` not adjudicated | [`Unadjudicated`] number | halt-reason tag when the engine is halted after the call |
//!
//! `amussis_decide` answers with the classes `0` to `4`. `amussis_adjudicate`
//! answers with `0` (approved, and the held action may proceed), `4`, `5` and
//! `6`. An approval and a rejection are each a record of the chain; the
//! classes `4` and `6` record no vote.
//!
//! # Held actions
//!
//! An action the engine holds (class `2`) is named by the `id` of the
//! proposal it was decided for; that intent id is all an adjudication needs
//! to name it, and no handle crosses the interface. The hold stands until the
//! checkers decide, its approval window closes or the engine halts.
//!
//! Who may approve is the host's decision. The host names one or two
//! checkers; the engine holds them to the approval rule of the action (one
//! checker, or two distinct ones for an Annex III action, none of them the
//! maker of the proposal) and records the vote. The record names the maker
//! and the checkers the host named, byte for byte.
//!
//! An adjudication never passes for want of a working effect. A vote that
//! cannot be signed or stored is no vote: the hold is released without a
//! decision and the engine halts. An unreadable clock halts the engine as
//! well. A halted engine takes no adjudication.
//!
//! # The audit chain
//!
//! The chain lives in the host's sink. The engine keeps a window of at most
//! `MAX_LEDGER_RECORDS` records in memory; when the window is full the
//! binding has the engine walk it once more and drop it, and the next record
//! links onto the last one as before. A window that no longer verifies is not
//! dropped: the engine halts as compromised.
//!
//! A module instance holds one engine for its lifetime. A host that starts
//! again does not start a second chain: it calls `amussis_continue` with the
//! frame of the last record its store holds. The module checks that the
//! record hashes to its digest and reads the sequence number, the time and
//! the halt-latch state out of the hashed bytes; nothing is taken from loose
//! numbers. A continuation from any record but the last leaves two records
//! with one sequence number in the store, which a walk over the store
//! refuses.
//!
//! # Halt and release
//!
//! A halt is a record of the chain, and it stands at a risk level: the level
//! of the action the engine had in hand when an effect failed, or the highest
//! level when it had none. A chain that ends halted continues halted; a
//! restart is no release.
//!
//! The host halts the engine with `amussis_halt`, the stop of a person at
//! the risk level it names. The record of the halt names that person where
//! the call engaged the halt or made it stricter; a call that changes
//! nothing about the halt writes no record. The halt holds whatever the call
//! answers: a halt whose record cannot be signed or stored is still a halt
//! of this engine, and the answer says that the stored chain does not show
//! it. A halt is never refused for its arguments either: bytes that are no
//! identity halt the engine with a record that names nobody, and the answer
//! says that too. A module instance has no call that lifts a halt.
//!
//! The one release of a halt is part of a continuation. The host names the
//! person who releases and the checkers who approve ([`ReleaseParts`]), and
//! the engine holds the release to the approval rule it holds actions of the
//! halted level to, the releasing person in the place of the maker: a level
//! whose actions need no checker is released by that person alone, a level
//! whose actions need one or two checkers only with that many, none of them
//! the releasing person. The release is a record, the first one the new
//! engine writes. A chain halted as compromised is not released, and a
//! release asked for a chain that is not halted is refused.
//!
//! The release record states that the halt was released and when, the level
//! it stood at, the releasing person and the checkers who approved.
//!
//! # Identities
//!
//! The maker in a proposal, the checkers of an adjudication, the persons of
//! a release and the person who halts are identities of at most 64 bytes.
//! The module writes them
//! into the records it hands to the signer and the sink as it received
//! them, and compares them as bytes; it does not hash them. A host passes a
//! keyed hash of its own identifier, never a name: what it passes in is
//! what the store keeps. The record of a halt the engine engaged itself, on
//! a fault, names nobody.
//!
//! # Limits
//!
//! - Holds are not carried over a continuation: an action held by the engine
//!   that wrote the head record stays unreleased, and an adjudication for it
//!   finds no held action.
//! - The head handed to `amussis_continue` is checked for integrity, not for
//!   origin: this library verifies no signature. That the frame is the last
//!   record of the host's own store is the host's statement.
//! - A halt is carried over a continuation only as far as the store shows
//!   it. A halt whose record never reached the store (the sink or the signer
//!   failed and did not recover before the host stopped) is not in the head
//!   record, so a continuation from that head starts armed. The host saw the
//!   block that halt answered with, and is the one who can keep it.
//!
//! # Unsafe code
//!
//! The workspace forbids unsafe code and this crate denies it. One file,
//! `src/abi.rs`, allows it for the linkage attributes an export and an import
//! need; it holds no `unsafe` block.

pub mod binding;
pub mod host;
pub mod wire;

#[cfg(target_family = "wasm")]
mod abi;

pub use crate::binding::{
    Binding, Class, Continuation, Engine, HaltStatus, InitError, OutcomeCode, Refusal,
    Unadjudicated,
};
pub use crate::host::{
    ClockAdapter, HostClock, HostSigner, HostSink, SINK_STORED, SignerAdapter, SinkAdapter,
};
pub use crate::wire::{
    AdjudicationParts, FRAME_VERSION, Frame, FrameParts, MAX_ADJUDICATION_BYTES,
    MAX_ADJUDICATION_CHECKERS, MAX_FRAME_BYTES, MAX_RELEASE_BYTES, MAX_RELEASE_PERSONS,
    ReleaseParts, VOTE_APPROVE, VOTE_REJECT,
};

/// Version of the import and export interface described above.
pub const ABI_VERSION: u32 = 6;

/// Name of the import module the host functions live in.
pub const HOST_MODULE: &str = "amussis_host_v1";

/// The answer the binding itself gives in a host function's place when it
/// cannot make the call; every adapter reads it as a failure.
pub const HOST_UNAVAILABLE: i32 = -1;
