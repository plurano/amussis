// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The encoding rules a versioned JSON schema is built from.
//!
//! The library reads one schema of its own, [`crate::proposal`]. A system that
//! puts an envelope around a proposal, or that exports an audit record in a
//! form of its own, declares that schema in its own adapter crate. This module
//! is what such a schema is built from, so that every adapter refuses the same
//! inputs in the same way:
//!
//! | Rule | Item |
//! | :-- | :-- |
//! | One payload is at most [`MAX_CONTRACT_PAYLOAD_BYTES`] long | [`PayloadBuffer`], [`decode_text`], [`encode_into`] |
//! | Bytes travel as lower-case hexadecimal | [`fields`] |
//! | A seal travels as key, algorithm and bytes | [`fields::OversightSignature`] |
//! | A payload names its version in the key `schema` | [`SchemaTag`], [`ContractError::UnknownVersion`] |
//! | Every refusal names the payload it is about | [`Correlation`], [`ContractError`] |
//!
//! No schema is declared here, and no transport: there is no socket and no
//! signing in this module or in the crate. A signature field is a field
//! encoding; nothing here produces or verifies a signature.
//!
//! # Versioning
//!
//! A schema carries its version tag in the key `schema`, typed in the adapter
//! as an enum with one variant per admitted version. [`decode_text`] refuses a
//! payload that names another tag with [`ContractError::UnknownVersion`] rather
//! than parsing it leniently. Adding a version is adding a variant, which makes
//! every match on it a compile error until it is handled.
//!
//! # Correlated refusals
//!
//! Every refusal carries a [`Correlation`]: the schema the decoder was asked
//! for and, when it could still be read, the identifier the payload carried in
//! the key `correlation-id`. A refused payload can therefore be tied to the
//! conversation it belonged to without echoing the payload itself into a log.
//!
//! The two keys are read independently of each other and of the rest of the
//! payload, so a `schema` value that is out of the identifier charset, longer
//! than [`crate::MAX_IDENTITY_LEN`] or not a string at all cannot discard a
//! correlation identifier that is right there and readable. The only refusal
//! that is genuinely anonymous is one whose input carries nothing to read.
//!
//! # Bounds
//!
//! A payload longer than [`MAX_CONTRACT_PAYLOAD_BYTES`] is refused before it is
//! parsed at all. Every field type of [`fields`] and every identifier of the
//! library is a fixed inline buffer, so a schema built from them is `Copy` and
//! a decoded value owns no heap.
//!
//! Decoding is not unconditionally allocation-free, and this module does not
//! claim it is. Nothing here allocates for an escape-free payload: the encoder
//! writes into a caller-supplied [`PayloadBuffer`] and the decoder borrows each
//! field straight out of its input. A payload that spells the same value with a
//! JSON escape is different: `\/` is an admissible spelling of the `/` in a
//! target path, and `serde_json` unescapes any such string into a heap scratch
//! buffer before the field is validated. A refusal allocates too, for the
//! decoder's own error value. Both are transient, neither is retained, and both
//! are bounded by [`MAX_CONTRACT_PAYLOAD_BYTES`], because a payload longer than
//! that never reaches the parser. `tests/allocation_bounds.rs` is the
//! executable statement of all of this.

pub mod fields;

use core::fmt;

use crate::identity::Identity;

/// Scalar upper bound, in bytes, on one encoded payload.
///
/// The widest field this module encodes is a
/// [`crate::MAX_SIGNATURE_BYTES`]-byte signature, which is twice that in
/// hexadecimal. The bound leaves roughly the same again for every other field
/// and is the same for every schema, so one buffer serves all of them.
pub const MAX_CONTRACT_PAYLOAD_BYTES: usize = 4096;

/// The version tag of one schema: the text its payloads carry in the key
/// `schema`.
///
/// The library declares no tag here. An adapter declares one constant per
/// schema version it admits and hands it to [`decode_text`], which compares it
/// with the tag a refused payload named.
///
/// A payload's tag is read as an [`Identity`], so a tag that is not one (an
/// empty text, a text longer than [`crate::MAX_IDENTITY_LEN`] bytes, a byte
/// outside the identifier charset) is equal to no payload's tag: every
/// refusal of a payload that names a readable tag is then
/// [`ContractError::UnknownVersion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaTag(&'static str);

impl SchemaTag {
    /// Declares the tag `tag`.
    #[must_use]
    pub const fn new(tag: &'static str) -> Self {
        Self(tag)
    }

    /// Returns the tag as the payload spells it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for SchemaTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// What a refusal is about: the schema, and the payload when it could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Correlation {
    schema: SchemaTag,
    id: Option<Identity>,
}

impl Correlation {
    /// Builds a correlation from a schema and the identifier, if one was read.
    #[must_use]
    pub const fn new(schema: SchemaTag, id: Option<Identity>) -> Self {
        Self { schema, id }
    }

    /// Returns the schema the decoder was asked for.
    #[must_use]
    pub const fn schema(&self) -> SchemaTag {
        self.schema
    }

    /// Returns the correlation identifier, when the decoder could read one.
    #[must_use]
    pub const fn id(&self) -> Option<Identity> {
        self.id
    }
}

impl fmt::Display for Correlation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.id {
            Some(id) => write!(f, "{} [{}]", self.schema, id),
            None => write!(f, "{} [uncorrelated]", self.schema),
        }
    }
}

/// Reasons [`decode_text`] and [`encode_into`] refuse a payload.
///
/// Every variant carries its [`Correlation`], so no refusal is anonymous. The
/// rules of one schema (a missing seal, a window out of range) are that
/// schema's own refusals; its adapter declares them beside this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContractError {
    /// The payload names a schema version the decoder was not asked for.
    #[error("{correlation}: the payload names a schema version this build does not admit")]
    UnknownVersion {
        /// What the refusal is about.
        correlation: Correlation,
    },
    /// The payload is not a well-formed instance of its schema.
    #[error("{correlation}: the payload is not a well-formed instance of this schema")]
    Malformed {
        /// What the refusal is about.
        correlation: Correlation,
    },
    /// The payload does not fit the scalar byte bound.
    #[error("{correlation}: the payload does not fit the {max}-byte bound")]
    PayloadTooLong {
        /// What the refusal is about.
        correlation: Correlation,
        /// The scalar bound in bytes.
        max: usize,
    },
}

impl ContractError {
    /// Returns what the refusal is about.
    #[must_use]
    pub const fn correlation(&self) -> Correlation {
        match self {
            Self::UnknownVersion { correlation }
            | Self::Malformed { correlation }
            | Self::PayloadTooLong { correlation, .. } => *correlation,
        }
    }
}

/// A fixed buffer holding one encoded payload.
///
/// Encoding writes into a caller-supplied buffer rather than returning an
/// owned string, so a payload that encodes successfully costs no heap and the
/// [`MAX_CONTRACT_PAYLOAD_BYTES`] bound is enforced by the buffer itself
/// instead of by a length check after the fact.
#[derive(Debug, Clone, Copy)]
pub struct PayloadBuffer {
    bytes: [u8; MAX_CONTRACT_PAYLOAD_BYTES],
    len: usize,
}

impl Default for PayloadBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadBuffer {
    /// Builds an empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0u8; MAX_CONTRACT_PAYLOAD_BYTES],
            len: 0,
        }
    }

    /// Returns the bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self.bytes.get(..self.len) {
            Some(slice) => slice,
            None => &[],
        }
    }

    /// Returns the encoded payload as text, when it is valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }

    /// Returns the number of bytes written.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when nothing has been encoded into the buffer.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The lenient view of a payload's `schema` field, and of nothing else.
///
/// Every other field is an unknown field to this type, so it is skipped rather
/// than parsed. That is what keeps the peek per-field: reading the claimed
/// version cannot be spoiled by a field this view does not name.
#[derive(serde::Deserialize)]
struct PeekSchema {
    #[serde(default)]
    schema: Option<Identity>,
}

/// The lenient view of a payload's correlation identifier, and of nothing else.
///
/// Deliberately a second type rather than a second field on [`PeekSchema`]. A
/// `schema` value that is out of the identifier charset, longer than
/// [`crate::MAX_IDENTITY_LEN`] or not a string at all fails to parse, and a
/// single view carrying both fields would discard the correlation identifier
/// with it -- one byte in the version tag would make every refusal anonymous.
/// Here that byte is in a field this view never looks at.
#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PeekCorrelation {
    #[serde(default)]
    correlation_id: Option<Identity>,
}

/// Reads the correlation identifier a payload carried, if it carried one.
fn peek_correlation(text: &str) -> Option<Identity> {
    serde_json::from_str::<PeekCorrelation>(text)
        .ok()
        .and_then(|row| row.correlation_id)
}

/// Reads the schema version a payload claimed, if it claimed a readable one.
fn peek_schema(text: &str) -> Option<Identity> {
    serde_json::from_str::<PeekSchema>(text)
        .ok()
        .and_then(|row| row.schema)
}

/// Classifies a decode failure into a correlated refusal.
///
/// The two fields are read independently, so the only payload that refuses
/// anonymously is one whose correlation identifier genuinely cannot be read --
/// input that is not JSON, or that carries no readable identifier at all.
fn classify(schema: SchemaTag, text: &str) -> ContractError {
    let correlation = Correlation::new(schema, peek_correlation(text));
    match peek_schema(text) {
        Some(tag) if tag.as_bytes() != schema.as_str().as_bytes() => {
            ContractError::UnknownVersion { correlation }
        }
        _ => ContractError::Malformed { correlation },
    }
}

/// Decodes one payload of `schema`, refusing anything over the byte bound.
///
/// The value type decides what is well formed: a schema type that denies
/// unknown fields and types its `schema` key as an enum of admitted versions
/// refuses everything else here. A rule that spans fields is the schema's own
/// check on the decoded value.
///
/// # Errors
///
/// Returns [`ContractError::PayloadTooLong`] for a text longer than
/// [`MAX_CONTRACT_PAYLOAD_BYTES`], which is not parsed and so carries no
/// identifier, [`ContractError::UnknownVersion`] for a text that is refused
/// and names a readable tag other than `schema`, and
/// [`ContractError::Malformed`] for every other refused text.
pub fn decode_text<T>(schema: SchemaTag, text: &str) -> Result<T, ContractError>
where
    T: for<'de> serde::Deserialize<'de>,
{
    if text.len() > MAX_CONTRACT_PAYLOAD_BYTES {
        return Err(ContractError::PayloadTooLong {
            correlation: Correlation::new(schema, None),
            max: MAX_CONTRACT_PAYLOAD_BYTES,
        });
    }
    match serde_json::from_str::<T>(text) {
        Ok(value) => Ok(value),
        Err(_) => Err(classify(schema, text)),
    }
}

/// Encodes `value` into `buffer` and returns the rendered payload.
///
/// The buffer is emptied first, so it never holds a part of an earlier
/// payload; after a payload that did not fit it is empty.
///
/// # Errors
///
/// Returns [`ContractError::PayloadTooLong`] when the serialiser stops, which
/// for a value of bounded fields means the payload does not fit the buffer,
/// and [`ContractError::Malformed`] when the rendered bytes are not text. Both
/// carry `correlation` as given.
pub fn encode_into<'b, T>(
    value: &T,
    correlation: Correlation,
    buffer: &'b mut PayloadBuffer,
) -> Result<&'b str, ContractError>
where
    T: serde::Serialize,
{
    buffer.len = 0;
    let mut tail: &mut [u8] = &mut buffer.bytes;
    let written = serde_json::to_writer(&mut tail, value);
    let remaining = tail.len();
    if written.is_err() {
        return Err(ContractError::PayloadTooLong {
            correlation,
            max: MAX_CONTRACT_PAYLOAD_BYTES,
        });
    }
    buffer.len = MAX_CONTRACT_PAYLOAD_BYTES.saturating_sub(remaining);
    match buffer.as_str() {
        Some(text) => Ok(text),
        None => Err(ContractError::Malformed { correlation }),
    }
}
