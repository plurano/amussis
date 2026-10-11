// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The WebAssembly imports and exports. The only file of the workspace that
//! allows unsafe code; `exceptions.toml` names it, the reason and the date the
//! allowance ends, and `tools/exceptions_check.py` holds it to that entry.
//!
//! What needs the allowance is linkage alone: an export needs
//! `#[unsafe(no_mangle)]` and an import needs an `unsafe extern` block. There
//! is no `unsafe` block and no raw pointer dereference here. Bytes cross in
//! four static buffers of atomic cells: the host writes and reads them at the
//! addresses this module hands out, and this module reads and writes them
//! through the cells.
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use amussis_decision::{DIGEST_LEN, MAX_PROPOSAL_BYTES, MAX_SIGNATURE_BYTES};

use crate::binding::{Binding, Continuation, InitError, Latch, OutcomeCode, Refusal};
use crate::host::{HostClock, HostSigner, HostSink};
use crate::wire::MAX_FRAME_BYTES;
use crate::{ABI_VERSION, HOST_UNAVAILABLE};

static INPUT: [AtomicU8; MAX_PROPOSAL_BYTES] = [const { AtomicU8::new(0) }; MAX_PROPOSAL_BYTES];
static DIGEST: [AtomicU8; DIGEST_LEN] = [const { AtomicU8::new(0) }; DIGEST_LEN];
static SIGNATURE: [AtomicU8; MAX_SIGNATURE_BYTES] =
    [const { AtomicU8::new(0) }; MAX_SIGNATURE_BYTES];
static FRAME: [AtomicU8; MAX_FRAME_BYTES] = [const { AtomicU8::new(0) }; MAX_FRAME_BYTES];

static BINDING: Mutex<Option<Binding<Imports, Imports, Imports>>> = Mutex::new(None);

// SAFETY: the three functions take and return plain integers. The addresses
// they receive are of the static buffers above, whose cells are atomic, so a
// host that writes them does not break a rule of this program; a host that
// writes elsewhere in the module's memory could do so with or without these
// declarations.
#[link(wasm_import_module = "amussis_host_v1")]
unsafe extern "C" {
    safe fn clock_now() -> i64;
    safe fn signer_sign(digest: u32, out: u32, out_capacity: u32) -> i32;
    safe fn sink_append(frame: u32, frame_len: u32, deadline_ms: u32) -> i32;
}

/// The address of a static buffer in the module's memory.
///
/// The address is exposed, not merely read: the host forms its own accesses
/// from it. An address that does not fit (it always does on a 32-bit target)
/// becomes the highest one, which no host access of any length can satisfy.
fn address(cells: &'static [AtomicU8]) -> u32 {
    u32::try_from(cells.as_ptr().expose_provenance()).unwrap_or(u32::MAX)
}

/// The length of a buffer as the host sees it.
fn capacity(cells: &[AtomicU8]) -> u32 {
    u32::try_from(cells.len()).unwrap_or(0)
}

/// Copies the first `out.len()` cells into `out`.
fn load(cells: &[AtomicU8], out: &mut [u8]) {
    for (byte, cell) in out.iter_mut().zip(cells) {
        *byte = cell.load(Ordering::Relaxed);
    }
}

/// Copies `bytes` into the first cells.
fn store(cells: &[AtomicU8], bytes: &[u8]) {
    for (cell, byte) in cells.iter().zip(bytes) {
        cell.store(*byte, Ordering::Relaxed);
    }
}

/// The host functions, read as the three host effects.
#[derive(Debug)]
struct Imports;

impl HostClock for Imports {
    fn now(&self) -> i64 {
        clock_now()
    }
}

impl HostSigner for Imports {
    fn sign(&self, digest: &[u8; DIGEST_LEN], out: &mut [u8; MAX_SIGNATURE_BYTES]) -> i32 {
        store(&DIGEST, digest);
        let answer = signer_sign(address(&DIGEST), address(&SIGNATURE), capacity(&SIGNATURE));
        load(&SIGNATURE, out);
        answer
    }
}

impl HostSink for Imports {
    fn append(&mut self, frame: &[u8], deadline_ms: u32) -> i32 {
        let Ok(len) = u32::try_from(frame.len()) else {
            return HOST_UNAVAILABLE;
        };
        if frame.len() > FRAME.len() {
            return HOST_UNAVAILABLE;
        }
        store(&FRAME, frame);
        sink_append(address(&FRAME), len, deadline_ms)
    }
}

/// The version of this interface; a host refuses a module that answers another.
// SAFETY: the name is prefixed with the library's name and is the only
// definition of it in the module.
#[unsafe(no_mangle)]
pub extern "C" fn amussis_abi_version() -> u32 {
    ABI_VERSION
}

/// The address the host writes the key identifier, the head frame of a chain
/// and the proposal text to.
// SAFETY: as for `amussis_abi_version`.
#[unsafe(no_mangle)]
pub extern "C" fn amussis_input() -> u32 {
    address(&INPUT)
}

/// The number of bytes the host may write at [`amussis_input`].
// SAFETY: as for `amussis_abi_version`.
#[unsafe(no_mangle)]
pub extern "C" fn amussis_input_capacity() -> u32 {
    capacity(&INPUT)
}

/// Sets up the engine. The signer key identifier is the first `key_id_len`
/// bytes of the input buffer. Returns zero, or an [`InitError`] number.
// SAFETY: as for `amussis_abi_version`.
#[unsafe(no_mangle)]
pub extern "C" fn amussis_init(key_id_len: u32, io_deadline_ms: u32) -> u32 {
    match init(key_id_len, io_deadline_ms) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn init(key_id_len: u32, io_deadline_ms: u32) -> Result<(), InitError> {
    let mut guard = BINDING.try_lock().map_err(|_| InitError::Busy)?;
    if guard.is_some() {
        return Err(InitError::AlreadyInitialised);
    }
    let mut text = [0u8; MAX_PROPOSAL_BYTES];
    let key_id = input(key_id_len, &mut text).ok_or(InitError::KeyId)?;
    *guard = Some(Binding::new(
        key_id,
        io_deadline_ms,
        Imports,
        Imports,
        Imports,
    )?);
    Ok(())
}

/// Sets up the engine as the continuation of a stored chain. The input buffer
/// holds the signer key identifier in its first `key_id_len` bytes and, behind
/// it, the `head_len` bytes of the frame of the chain's last stored record.
/// `latch` is a [`Latch`] number. Returns zero, or an [`InitError`] number.
// SAFETY: as for `amussis_abi_version`.
#[unsafe(no_mangle)]
pub extern "C" fn amussis_continue(
    key_id_len: u32,
    head_len: u32,
    io_deadline_ms: u32,
    latch: u32,
) -> u32 {
    match resume(key_id_len, head_len, io_deadline_ms, latch) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn resume(
    key_id_len: u32,
    head_len: u32,
    io_deadline_ms: u32,
    latch: u32,
) -> Result<(), InitError> {
    let mut guard = BINDING.try_lock().map_err(|_| InitError::Busy)?;
    if guard.is_some() {
        return Err(InitError::AlreadyInitialised);
    }
    let latch = Latch::from_flag(latch).ok_or(InitError::Latch)?;
    let mut text = [0u8; MAX_PROPOSAL_BYTES];
    let both = key_id_len
        .checked_add(head_len)
        .and_then(|len| input(len, &mut text))
        .ok_or(InitError::Head)?;
    let (key_id, head) = usize::try_from(key_id_len)
        .ok()
        .and_then(|at| both.split_at_checked(at))
        .ok_or(InitError::KeyId)?;
    *guard = Some(Binding::continue_from(
        key_id,
        io_deadline_ms,
        Continuation::new(head, latch),
        Imports,
        Imports,
        Imports,
    )?);
    Ok(())
}

/// Decides the proposal whose text is the first `len` bytes of the input
/// buffer. Returns the outcome code (see the crate documentation).
// SAFETY: as for `amussis_abi_version`.
#[unsafe(no_mangle)]
pub extern "C" fn amussis_decide(len: u32) -> u32 {
    decide(len).to_u32()
}

fn decide(len: u32) -> OutcomeCode {
    let Ok(mut guard) = BINDING.try_lock() else {
        return OutcomeCode::refused(Refusal::Busy);
    };
    let Some(binding) = guard.as_mut() else {
        return OutcomeCode::refused(Refusal::NotInitialised);
    };
    let mut text = [0u8; MAX_PROPOSAL_BYTES];
    match input(len, &mut text) {
        Some(bytes) => binding.decide(bytes),
        None => OutcomeCode::refused(Refusal::TooLong),
    }
}

/// Copies the first `len` bytes of the input buffer into `text`, or returns
/// `None` when `len` exceeds the buffer.
fn input(len: u32, text: &mut [u8; MAX_PROPOSAL_BYTES]) -> Option<&[u8]> {
    let bytes = text.get_mut(..usize::try_from(len).ok()?)?;
    load(&INPUT, bytes);
    Some(bytes)
}
