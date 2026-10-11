// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The field encoding every M14 consumer schema shares.
//!
//! One file holds every hand-written `Serialize`/`Deserialize` pair, so the
//! wire form of a bounded value can be reviewed in one place rather than
//! rediscovered per schema. Three properties are deliberate:
//!
//! * **Validation happens during decoding.** An identifier, a target resource,
//!   a digest and a signature are all parsed through the same constructors the
//!   library already uses, so an over-long or ill-formed field is refused by
//!   the decoder rather than accepted and checked later.
//! * **Every value lands in a fixed inline buffer.** Nothing in this file owns
//!   heap: each validated value is copied into an inline array, which is why
//!   all three schema types are `Copy`. What this does not claim is that
//!   decoding is allocation-free in every case. `serde_json` unescapes a JSON
//!   string into a heap scratch buffer before any visitor here sees it, so an
//!   escaped field costs a transient copy bounded by
//!   [`super::MAX_CONTRACT_PAYLOAD_BYTES`]; see the `contracts` module
//!   documentation and `tests/allocation_bounds.rs`.
//! * **The encoding is stable and explicit.** Bytes travel as lower-case
//!   hexadecimal, never as a byte array, and every enum names its variants
//!   explicitly, so a field reordering or a renamed variant is a visible
//!   change to this file.

use core::fmt;

use serde::de::{Error as DeError, Unexpected, Visitor};
use serde::ser::Error as SerError;
use serde::{Deserializer, Serializer};

use crate::MAX_SIGNATURE_BYTES;
use crate::identity::{Identity, SignerKeyId, TargetResource};
use crate::ledger::hash::Digest32;
use crate::ledger::signer::{SignError, Signature};

/// Width, in characters, of the longest admissible signature in hexadecimal.
pub const MAX_SIGNATURE_HEX_CHARS: usize = MAX_SIGNATURE_BYTES.saturating_mul(2);

/// Width, in characters, of a [`Digest32`] in hexadecimal.
pub const DIGEST_HEX_CHARS: usize = 64;

/// Renders `bytes` as lower-case hexadecimal into the front of `buffer`.
fn to_hex<'b>(bytes: &[u8], buffer: &'b mut [u8; MAX_SIGNATURE_HEX_CHARS]) -> Option<&'b str> {
    let width = bytes.len().checked_mul(2)?;
    let slot = buffer.get_mut(..width)?;
    base16ct::lower::encode_str(bytes, slot).ok()
}

/// Serialises a validated byte string as a UTF-8 string.
fn serialize_text<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    let text = core::str::from_utf8(bytes).map_err(S::Error::custom)?;
    serializer.serialize_str(text)
}

/// A visitor that parses one string field through a validating constructor.
struct Parsed<T> {
    label: &'static str,
    parse: fn(&str) -> Option<T>,
}

impl<T> Visitor<'_> for Parsed<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label)
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<T, E> {
        match (self.parse)(value) {
            Some(parsed) => Ok(parsed),
            None => Err(E::invalid_value(Unexpected::Str(value), &self)),
        }
    }
}

impl serde::Serialize for Identity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_text(self.as_bytes(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Identity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Parsed {
            label: "a bounded identifier",
            parse: |text| Self::parse(text).ok(),
        })
    }
}

impl serde::Serialize for TargetResource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_text(self.as_bytes(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for TargetResource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Parsed {
            label: "a bounded target resource",
            parse: |text| Self::parse(text).ok(),
        })
    }
}

impl serde::Serialize for Digest32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buffer = [0u8; DIGEST_HEX_CHARS];
        let text = self.encode_hex(&mut buffer).map_err(S::Error::custom)?;
        serializer.serialize_str(text)
    }
}

impl<'de> serde::Deserialize<'de> for Digest32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Parsed {
            label: "a 64-character lower-case hexadecimal digest",
            parse: |text| Self::parse_hex(text).ok(),
        })
    }
}

/// A detached signature's bytes, carried as lower-case hexadecimal.
///
/// The type exists so the wire form of a seal is bounded and reviewable
/// without widening [`Signature`], which also carries the key that produced
/// it. Converting in either direction is explicit:
/// [`Self::from_signature`] and [`Self::into_signature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes {
    bytes: [u8; MAX_SIGNATURE_BYTES],
    len: usize,
}

impl SignatureBytes {
    /// The empty signature: the wire form of a proposal nobody sealed.
    pub const EMPTY: Self = Self {
        bytes: [0u8; MAX_SIGNATURE_BYTES],
        len: 0,
    };

    /// Projects a sealed signature onto its wire bytes.
    #[must_use]
    pub fn from_signature(signature: &Signature) -> Self {
        let mut bytes = [0u8; MAX_SIGNATURE_BYTES];
        for (slot, byte) in bytes.iter_mut().zip(signature.as_bytes().iter()) {
            *slot = *byte;
        }
        Self {
            bytes,
            len: signature.len(),
        }
    }

    /// Rebuilds a sealed signature by naming the key that produced it.
    ///
    /// # Errors
    ///
    /// Propagates [`SignError::TooLong`] from [`Signature::new`], which cannot
    /// occur for a value this type could hold.
    pub fn into_signature(self, key_id: SignerKeyId) -> Result<Signature, SignError> {
        Signature::new(key_id, self.as_bytes())
    }

    /// Returns the signature bytes, without the trailing padding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self.bytes.get(..self.len) {
            Some(slice) => slice,
            None => &[],
        }
    }

    /// Returns the signature width in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no signature bytes are carried at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Parses lower-case hexadecimal into bounded signature bytes.
    fn parse_hex(text: &str) -> Option<Self> {
        let mut bytes = [0u8; MAX_SIGNATURE_BYTES];
        let decoded = base16ct::lower::decode(text.as_bytes(), &mut bytes).ok()?;
        let len = decoded.len();
        Some(Self { bytes, len })
    }
}

impl serde::Serialize for SignatureBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buffer = [0u8; MAX_SIGNATURE_HEX_CHARS];
        match to_hex(self.as_bytes(), &mut buffer) {
            Some(text) => serializer.serialize_str(text),
            None => Err(S::Error::custom("signature exceeds the hexadecimal bound")),
        }
    }
}

impl<'de> serde::Deserialize<'de> for SignatureBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Parsed {
            label: "lower-case hexadecimal signature bytes",
            parse: Self::parse_hex,
        })
    }
}

/// The signature scheme a seal declares.
///
/// One variant, naming the scheme the P06 report declares for audit records
/// (export-015 `fcbe2caed363`: a TPM2 RSA-PSS signature). Milestone M14
/// implements no signing at all: this is the field encoding a future signer
/// will fill, and nothing in this crate produces or verifies a signature. TPM2
/// sealing is milestone M20 work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSA-PSS over a TPM2-resident key.
    #[serde(rename = "tpm2-rsa-pss")]
    Tpm2RsaPss,
}

impl SignatureAlgorithm {
    /// Returns the stable tag the wire form carries.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Tpm2RsaPss => "tpm2-rsa-pss",
        }
    }
}

/// A detached seal as it travels on a contract payload.
///
/// The key that produced the signature travels with it, because a consumer
/// that cannot name the key cannot check the signature later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OversightSignature {
    /// The key that produced the signature.
    pub key_id: SignerKeyId,
    /// The scheme the signature was produced under.
    pub algorithm: SignatureAlgorithm,
    /// The signature bytes, lower-case hexadecimal on the wire.
    pub bytes: SignatureBytes,
}

impl OversightSignature {
    /// Builds a seal from a sealed signature produced by the ledger.
    #[must_use]
    pub fn from_signature(signature: &Signature, algorithm: SignatureAlgorithm) -> Self {
        Self {
            key_id: *signature.key_id(),
            algorithm,
            bytes: SignatureBytes::from_signature(signature),
        }
    }

    /// Returns `true` when the seal carries no signature bytes at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
