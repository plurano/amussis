// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The record-signing boundary.
//!
//! Milestone M02 ships no production signer: TPM2 sealing is deferred to M20.
//! The deferral is a typed hole rather than a placeholder string. The default
//! binding is [`SignerBinding::Unbound`], which hard-errors, so "a missing
//! signer returns an error" is the deferral proof itself.

use crate::MAX_SIGNATURE_BYTES;
use crate::identity::SignerKeyId;
use crate::ledger::hash::Digest32;

/// Reasons a record cannot be sealed.
///
/// Every variant has a producer in this module, and only those two conditions
/// are representable in milestone M02: [`SignerBinding::Unbound`] produces
/// [`Self::Unavailable`] and [`Signature::new`] produces [`Self::TooLong`]. A
/// backend-specific refusal has no producer here because M02 ships no backend,
/// so it is not a variant; M20 adds one with the TPM2 path that raises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The signing backend is unusable. [`SignerBinding::Unbound`], the
    /// milestone M02 default, is the in-crate producer.
    #[error("the record signer is unavailable; TPM2 sealing is deferred to M20")]
    Unavailable,
    /// The signature the backend produced exceeded the scalar bound.
    #[error("signature of {actual} bytes exceeds the bound of {max}")]
    TooLong {
        /// The scalar bound in bytes.
        max: usize,
        /// The width observed.
        actual: usize,
    },
}

/// A detached signature over one record digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    key_id: SignerKeyId,
    bytes: [u8; MAX_SIGNATURE_BYTES],
    len: u16,
}

impl Signature {
    /// Builds a signature from backend output.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::TooLong`] when the output exceeds
    /// [`MAX_SIGNATURE_BYTES`]; the output is never truncated.
    pub fn new(key_id: SignerKeyId, raw: &[u8]) -> Result<Self, SignError> {
        if raw.len() > MAX_SIGNATURE_BYTES {
            return Err(SignError::TooLong {
                max: MAX_SIGNATURE_BYTES,
                actual: raw.len(),
            });
        }
        let len = u16::try_from(raw.len()).map_err(|_| SignError::TooLong {
            max: MAX_SIGNATURE_BYTES,
            actual: raw.len(),
        })?;
        let mut bytes = [0u8; MAX_SIGNATURE_BYTES];
        for (slot, byte) in bytes.iter_mut().zip(raw.iter().take(MAX_SIGNATURE_BYTES)) {
            *slot = *byte;
        }
        Ok(Self { key_id, bytes, len })
    }

    /// Returns the key that produced the signature.
    #[must_use]
    pub const fn key_id(&self) -> &SignerKeyId {
        &self.key_id
    }

    /// Returns the signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Returns the signature width in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` when the signature carries no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Produces a detached signature over a record digest.
pub trait RecordSigner {
    /// Returns the key this signer uses.
    fn key_id(&self) -> &SignerKeyId;

    /// Signs a record digest.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] when the backend is unavailable or refuses.
    fn sign(&self, digest: &Digest32) -> Result<Signature, SignError>;
}

/// Whether a signer is bound to the ledger.
///
/// `Unbound` is the milestone M02 default and always errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerBinding<S: RecordSigner> {
    /// A signer is bound.
    Bound(S),
    /// No signer is bound; sealing fails closed.
    Unbound,
}

impl<S: RecordSigner> SignerBinding<S> {
    /// Signs a record digest through the bound signer.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Unavailable`] when no signer is bound, and
    /// otherwise whatever the bound signer returns.
    pub fn sign(&self, digest: &Digest32) -> Result<Signature, SignError> {
        match self {
            Self::Bound(signer) => signer.sign(digest),
            Self::Unbound => Err(SignError::Unavailable),
        }
    }

    /// Returns the milestone M02 default binding: no signer at all.
    ///
    /// `Default` is deliberately not implemented: deriving it would demand
    /// `S: Default`, and a signer backend has no meaningful default.
    #[must_use]
    pub const fn unbound() -> Self {
        Self::Unbound
    }

    /// Returns `true` when a signer is bound.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        matches!(self, Self::Bound(_))
    }
}
