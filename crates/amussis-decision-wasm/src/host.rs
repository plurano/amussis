// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The three effects a host hands in, and their reading as engine effects.
//!
//! The traits carry the same integers the WebAssembly imports carry, so the
//! rule that turns a host answer into "sealed" or "refused" is ordinary code
//! in this module, tested on the build machine, and not a property of the
//! export file. Each adapter reads every answer it does not recognise as a
//! failure: there is no answer a host can give, or fail to give, that yields
//! a time, a signature or a stored record by default.

use amussis_decision::{
    AuditRecord, Clock, ClockError, DIGEST_LEN, Digest32, IoDeadline, LedgerSink,
    MAX_SIGNATURE_BYTES, RecordSigner, SignError, Signature, SignerKeyId, SinkError, UnixSeconds,
};

use crate::wire::Frame;

/// The one answer of [`HostSink::append`] that means the record is stored.
pub const SINK_STORED: i32 = 0;

/// The host's wall clock.
pub trait HostClock {
    /// Returns whole seconds since the Unix epoch.
    ///
    /// A host that cannot read its clock returns a negative number.
    fn now(&self) -> i64;
}

/// The host's record signer.
pub trait HostSigner {
    /// Signs `digest` into `out` and returns the signature's length in bytes.
    ///
    /// A host that cannot sign returns zero or a negative number.
    fn sign(&self, digest: &[u8; DIGEST_LEN], out: &mut [u8; MAX_SIGNATURE_BYTES]) -> i32;
}

/// The host's durable record store.
pub trait HostSink {
    /// Stores one framed record (see [`crate::wire`]) within `deadline_ms`.
    ///
    /// Returns [`SINK_STORED`] once the record is durable. Every other value
    /// means the record is not stored.
    fn append(&mut self, frame: &[u8], deadline_ms: u32) -> i32;
}

/// Reads a [`HostClock`] as the engine's clock.
#[derive(Debug, Clone)]
pub struct ClockAdapter<C> {
    host: C,
}

impl<C: HostClock> ClockAdapter<C> {
    /// Wraps a host clock.
    pub const fn new(host: C) -> Self {
        Self { host }
    }
}

impl<C: HostClock> Clock for ClockAdapter<C> {
    fn now(&self) -> Result<UnixSeconds, ClockError> {
        u64::try_from(self.host.now())
            .map(UnixSeconds::new)
            .map_err(|_| ClockError::BeforeEpoch)
    }
}

/// Reads a [`HostSigner`] as the engine's record signer.
#[derive(Debug, Clone)]
pub struct SignerAdapter<S> {
    key_id: SignerKeyId,
    host: S,
}

impl<S: HostSigner> SignerAdapter<S> {
    /// Wraps a host signer that signs under `key_id`.
    pub const fn new(key_id: SignerKeyId, host: S) -> Self {
        Self { key_id, host }
    }
}

impl<S: HostSigner> RecordSigner for SignerAdapter<S> {
    fn key_id(&self) -> &SignerKeyId {
        &self.key_id
    }

    fn sign(&self, digest: &Digest32) -> Result<Signature, SignError> {
        let mut out = [0u8; MAX_SIGNATURE_BYTES];
        let answer = self.host.sign(digest.as_bytes(), &mut out);
        let len = usize::try_from(answer).map_err(|_| SignError::Unavailable)?;
        if len == 0 {
            return Err(SignError::Unavailable);
        }
        let raw = out.get(..len).ok_or(SignError::TooLong {
            max: MAX_SIGNATURE_BYTES,
            actual: len,
        })?;
        Signature::new(self.key_id, raw)
    }
}

/// Reads a [`HostSink`] as the engine's ledger sink.
#[derive(Debug, Clone)]
pub struct SinkAdapter<K> {
    host: K,
}

impl<K: HostSink> SinkAdapter<K> {
    /// Wraps a host sink.
    pub const fn new(host: K) -> Self {
        Self { host }
    }

    /// Returns the wrapped host sink.
    pub const fn host(&self) -> &K {
        &self.host
    }
}

impl<K: HostSink> LedgerSink for SinkAdapter<K> {
    fn append_record(
        &mut self,
        record: &AuditRecord,
        deadline: IoDeadline,
    ) -> Result<(), SinkError> {
        let frame = Frame::encode(record).ok_or(SinkError::Unavailable)?;
        if self.host.append(frame.as_slice(), deadline.millis()) == SINK_STORED {
            Ok(())
        } else {
            Err(SinkError::Unavailable)
        }
    }

    /// Nothing to flush: [`HostSink::append`] answers [`SINK_STORED`] only
    /// once the record is durable, so the adapter never holds a record back.
    fn sync(&mut self, _deadline: IoDeadline) -> Result<(), SinkError> {
        Ok(())
    }
}
