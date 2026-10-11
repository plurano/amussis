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
//! | `amussis_continue` | `(key_id_len: i32, head_len: i32, io_deadline_ms: i32, latch: i32) -> i32` | Sets up the engine as the continuation of a stored chain; the input buffer holds the signer key identifier followed by the frame ([`wire`]) of the chain's last stored record. `latch` is a [`Latch`] number. `0`, or an [`InitError`] number. |
//! | `amussis_decide` | `(len: i32) -> i32` | Decides the proposal text in the input buffer; returns the outcome code. |
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
//! A chain that ends halted continues halted ([`Latch::Keep`]).
//! [`Latch::Release`] is the one release of a halt this interface has; it is
//! refused for a chain halted as compromised.
//!
//! # Limits
//!
//! - A held action (class `2`) cannot be adjudicated through this interface
//!   yet; the hold lapses with its approval window. Holds are not carried
//!   over a continuation.
//! - The head handed to `amussis_continue` is checked for integrity, not for
//!   origin: this library verifies no signature. That the frame is the last
//!   record of the host's own store is the host's statement.
//! - A halt is carried over a continuation only as far as the store shows
//!   it. A halt whose record never reached the store (the sink or the signer
//!   failed) is not in the head record, so a continuation from that head
//!   starts armed.
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
    Binding, Class, Continuation, Engine, InitError, Latch, OutcomeCode, Refusal,
};
pub use crate::host::{
    ClockAdapter, HostClock, HostSigner, HostSink, SINK_STORED, SignerAdapter, SinkAdapter,
};
pub use crate::wire::{FRAME_VERSION, Frame, FrameParts, MAX_FRAME_BYTES};

/// Version of the import and export interface described above.
pub const ABI_VERSION: u32 = 2;

/// Name of the import module the host functions live in.
pub const HOST_MODULE: &str = "amussis_host_v1";

/// The answer the binding itself gives in a host function's place when it
/// cannot make the call; every adapter reads it as a failure.
pub const HOST_UNAVAILABLE: i32 = -1;
