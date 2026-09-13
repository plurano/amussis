// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The D02 hashing boundary.
//!
//! The ledger never names a hash function directly: it goes through
//! [`LedgerHasher`]. [`HashAlgorithm`] has exactly one variant, `Sha256`. MD5 is
//! excluded structurally rather than by convention: there is no variant, no
//! dependency, no lock entry and no serialisation alias for it. Adding BLAKE3
//! is one variant plus one implementation, and needs a superseding decision.

use core::fmt;

use crate::{DIGEST_LEN, MAX_PREIMAGE_BYTES};

/// Reasons a digest cannot be produced or parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HashError {
    /// The hash function returned an output of the wrong width.
    #[error("hash output width {actual} does not match the {expected}-byte digest")]
    Width {
        /// The width the ledger requires.
        expected: usize,
        /// The width observed.
        actual: usize,
    },
    /// The hexadecimal text was not a valid lower-case digest.
    #[error("not a valid lower-case hexadecimal digest")]
    Encoding,
}

/// Reasons a canonical pre-image cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PreimageError {
    /// The encoded pre-image would exceed the fixed buffer.
    #[error("canonical pre-image exceeds the bound of {max} bytes")]
    Overflow {
        /// The scalar bound in bytes.
        max: usize,
    },
}

/// The hash algorithms the ledger admits. There is no `Md5` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "jsonl", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "jsonl", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// FIPS 180-4 SHA-256.
    #[cfg_attr(feature = "jsonl", serde(rename = "sha-256"))]
    Sha256,
}

impl HashAlgorithm {
    /// Returns the stable tag mixed into every canonical pre-image.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Sha256 => 1,
        }
    }

    /// Returns the algorithm name used in records and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A fixed-width ledger digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32([u8; DIGEST_LEN]);

impl Digest32 {
    /// The link value of the first record in a chain: all zero bytes.
    pub const GENESIS: Self = Self([0u8; DIGEST_LEN]);

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    /// Returns a copy of the digest bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; DIGEST_LEN] {
        self.0
    }

    /// Returns `true` for the genesis link.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        *self == Self::GENESIS
    }

    /// Renders the digest as lower-case hexadecimal into `buffer`.
    ///
    /// The buffer is caller-supplied so the seal path never allocates.
    ///
    /// # Errors
    ///
    /// Returns [`HashError::Encoding`] when the buffer is the wrong width.
    pub fn encode_hex<'b>(&self, buffer: &'b mut [u8; 64]) -> Result<&'b str, HashError> {
        base16ct::lower::encode_str(&self.0, buffer).map_err(|_| HashError::Encoding)
    }

    /// Parses a 64-character lower-case hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`HashError::Encoding`] for anything that is not exactly one
    /// lower-case digest, and [`HashError::Width`] on a width mismatch.
    pub fn parse_hex(text: &str) -> Result<Self, HashError> {
        let mut raw = [0u8; DIGEST_LEN];
        let decoded =
            base16ct::lower::decode(text.as_bytes(), &mut raw).map_err(|_| HashError::Encoding)?;
        if decoded.len() != DIGEST_LEN {
            return Err(HashError::Width {
                expected: DIGEST_LEN,
                actual: decoded.len(),
            });
        }
        Ok(Self(raw))
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [0u8; 64];
        let text = self.encode_hex(&mut buffer).map_err(|_| fmt::Error)?;
        f.write_str(text)
    }
}

/// The ledger's hashing boundary (decision D02).
pub trait LedgerHasher {
    /// The algorithm this implementation records in every audit record.
    const ALGORITHM: HashAlgorithm;

    /// Hashes a canonical pre-image.
    ///
    /// The method is fallible on purpose: a hash backend that returns an
    /// output of the wrong width must surface an error rather than reach an
    /// unreachable arm, a panicking copy or a genesis-colliding fallback.
    ///
    /// # Errors
    ///
    /// Returns [`HashError::Width`] when the backend output is not
    /// [`DIGEST_LEN`] bytes.
    fn digest(preimage: &[u8]) -> Result<Digest32, HashError>;
}

/// A fixed-size buffer holding one canonical, domain-separated pre-image.
///
/// The chain digest is taken over this encoding rather than over a
/// serialiser's output, so no serialisation library release can alter a
/// historical digest, and the record wire schema stays free for M14 to pin.
/// Every variable-length field is length-prefixed, so re-splitting a field
/// boundary changes the pre-image.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalBuffer {
    bytes: [u8; MAX_PREIMAGE_BYTES],
    len: usize,
}

impl Default for CanonicalBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalBuffer {
    /// Builds an empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0u8; MAX_PREIMAGE_BYTES],
            len: 0,
        }
    }

    /// Returns the bytes written so far.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }

    /// Returns the number of bytes written.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when nothing has been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends raw bytes without a length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`PreimageError::Overflow`] rather than truncating.
    pub fn write_raw(&mut self, source: &[u8]) -> Result<(), PreimageError> {
        let end = self
            .len
            .checked_add(source.len())
            .ok_or(PreimageError::Overflow {
                max: MAX_PREIMAGE_BYTES,
            })?;
        let slot = self
            .bytes
            .get_mut(self.len..end)
            .ok_or(PreimageError::Overflow {
                max: MAX_PREIMAGE_BYTES,
            })?;
        slot.copy_from_slice(source);
        self.len = end;
        Ok(())
    }

    /// Appends a domain-separation tag.
    ///
    /// # Errors
    ///
    /// Returns [`PreimageError::Overflow`] rather than truncating.
    pub fn write_tag(&mut self, tag: &[u8]) -> Result<(), PreimageError> {
        self.write_raw(tag)
    }

    /// Appends a single tag byte.
    ///
    /// # Errors
    ///
    /// Returns [`PreimageError::Overflow`] rather than truncating.
    pub fn write_u8(&mut self, value: u8) -> Result<(), PreimageError> {
        self.write_raw(&[value])
    }

    /// Appends a big-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`PreimageError::Overflow`] rather than truncating.
    pub fn write_u64(&mut self, value: u64) -> Result<(), PreimageError> {
        self.write_raw(&value.to_be_bytes())
    }

    /// Appends a digest as raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PreimageError::Overflow`] rather than truncating.
    pub fn write_digest(&mut self, digest: &Digest32) -> Result<(), PreimageError> {
        self.write_raw(digest.as_bytes())
    }

    /// Appends a variable-length field behind a big-endian `u32` length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`PreimageError::Overflow`] rather than truncating, including
    /// when the field length does not fit in a `u32`.
    pub fn write_framed(&mut self, field: &[u8]) -> Result<(), PreimageError> {
        let length = u32::try_from(field.len()).map_err(|_| PreimageError::Overflow {
            max: MAX_PREIMAGE_BYTES,
        })?;
        self.write_raw(&length.to_be_bytes())?;
        self.write_raw(field)
    }
}
