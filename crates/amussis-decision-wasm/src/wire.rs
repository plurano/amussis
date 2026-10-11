// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! The bytes one sealed record crosses to the host sink in.
//!
//! ```text
//! u8        frame version, FRAME_VERSION
//! u16 LE    length of the canonical pre-image
//! bytes     canonical pre-image (starts with the audit domain tag)
//! 32 bytes  digest of the pre-image
//! u8        length of the signer key identifier
//! bytes     signer key identifier
//! u16 LE    length of the signature
//! bytes     signature over the digest
//! ```
//!
//! A reader needs nothing but the frame to check it: the digest is the hash
//! of the pre-image, the signature is over the digest, and the pre-image
//! carries the sequence number and the digest of the record before it.
//!
//! The same bytes come back once: a host that continues a chain hands in the
//! frame of the last record its store holds, and [`FrameParts::split`] reads
//! it.
//!
//! A host that releases the halt of the chain it continues names the persons
//! of the release in bytes of their own, which [`ReleaseParts::split`] reads:
//!
//! ```text
//! u8        number of persons, 1 to MAX_RELEASE_PERSONS
//! per person:
//!   u8      length of the identity, 1 to the identity bound
//!   bytes   identity
//! ```
//!
//! The first person releases the halt; the others are the checkers who
//! approve the release.

use amussis_decision::{
    AuditRecord, DIGEST_LEN, MAX_IDENTITY_LEN, MAX_PREIMAGE_BYTES, MAX_SIGNATURE_BYTES,
};

/// Version byte every frame starts with.
pub const FRAME_VERSION: u8 = 1;

/// Largest frame: every variable part at its bound.
pub const MAX_FRAME_BYTES: usize =
    1 + 2 + MAX_PREIMAGE_BYTES + DIGEST_LEN + 1 + MAX_IDENTITY_LEN + 2 + MAX_SIGNATURE_BYTES;

/// Most persons a release names: the releasing person and two checkers.
pub const MAX_RELEASE_PERSONS: usize = 3;

/// Largest release: the count byte and every identity at its bound.
pub const MAX_RELEASE_BYTES: usize = 1 + MAX_RELEASE_PERSONS * (1 + MAX_IDENTITY_LEN);

/// One framed record in a fixed buffer.
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    bytes: [u8; MAX_FRAME_BYTES],
    len: usize,
}

impl Frame {
    /// Frames `record`, or returns `None` when a part exceeds its bound.
    ///
    /// The bounds are those the engine already holds its records to, so a
    /// record the engine sealed always fits; the `None` arm exists so a
    /// record that does not is refused and never cut short.
    #[must_use]
    pub fn encode(record: &AuditRecord) -> Option<Self> {
        let preimage = record.body().canonical_preimage().ok()?;
        let digest = record.digest();
        let signature = record.signature();
        let key_id = signature.key_id().as_bytes();
        let mut frame = Self {
            bytes: [0u8; MAX_FRAME_BYTES],
            len: 0,
        };
        frame.push(&[FRAME_VERSION])?;
        frame.push(&u16::try_from(preimage.len()).ok()?.to_le_bytes())?;
        frame.push(preimage.as_slice())?;
        frame.push(digest.as_bytes())?;
        frame.push(&[u8::try_from(key_id.len()).ok()?])?;
        frame.push(key_id)?;
        frame.push(&u16::try_from(signature.len()).ok()?.to_le_bytes())?;
        frame.push(signature.as_bytes())?;
        Some(frame)
    }

    /// Returns the framed bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// Appends `part`, or returns `None` when it does not fit.
    fn push(&mut self, part: &[u8]) -> Option<()> {
        let end = self.len.checked_add(part.len())?;
        self.bytes.get_mut(self.len..end)?.copy_from_slice(part);
        self.len = end;
        Some(())
    }
}

/// The parts of one frame, borrowed from its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameParts<'a> {
    preimage: &'a [u8],
    digest: [u8; DIGEST_LEN],
    key_id: &'a [u8],
    signature: &'a [u8],
}

impl<'a> FrameParts<'a> {
    /// Splits `frame` into its parts, or returns `None` when the bytes are
    /// not one frame of [`FRAME_VERSION`]: another version byte, a length
    /// that runs past the end or past its bound, an empty key identifier or
    /// signature, or bytes after the signature.
    ///
    /// Only the layout is checked. Whether the digest is the hash of the
    /// pre-image is the reader's check
    /// (`amussis_decision::ChainAnchor::from_preimage` makes it), and the
    /// signature is not checked by this library at all.
    #[must_use]
    pub fn split(frame: &'a [u8]) -> Option<Self> {
        let mut rest = frame;
        if take(&mut rest, 1)? != [FRAME_VERSION] {
            return None;
        }
        let preimage_len = usize::from(u16::from_le_bytes(take(&mut rest, 2)?.try_into().ok()?));
        let preimage = take(&mut rest, preimage_len)?;
        let digest: [u8; DIGEST_LEN] = take(&mut rest, DIGEST_LEN)?.try_into().ok()?;
        let key_id_len = usize::from(*take(&mut rest, 1)?.first()?);
        let key_id = take(&mut rest, key_id_len)?;
        let signature_len = usize::from(u16::from_le_bytes(take(&mut rest, 2)?.try_into().ok()?));
        let signature = take(&mut rest, signature_len)?;
        let bounded = preimage.len() <= MAX_PREIMAGE_BYTES
            && (1..=MAX_IDENTITY_LEN).contains(&key_id.len())
            && (1..=MAX_SIGNATURE_BYTES).contains(&signature.len())
            && rest.is_empty();
        bounded.then_some(Self {
            preimage,
            digest,
            key_id,
            signature,
        })
    }

    /// Returns the canonical pre-image.
    #[must_use]
    pub const fn preimage(&self) -> &'a [u8] {
        self.preimage
    }

    /// Returns the digest the frame states for the pre-image.
    #[must_use]
    pub const fn digest(&self) -> [u8; DIGEST_LEN] {
        self.digest
    }

    /// Returns the signer key identifier.
    #[must_use]
    pub const fn key_id(&self) -> &'a [u8] {
        self.key_id
    }

    /// Returns the signature over the digest.
    #[must_use]
    pub const fn signature(&self) -> &'a [u8] {
        self.signature
    }
}

/// The persons of one release of a halt, borrowed from its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseParts<'a> {
    releaser: &'a [u8],
    checkers: [Option<&'a [u8]>; 2],
}

impl<'a> ReleaseParts<'a> {
    /// Splits `release` into its persons, or returns `None` when the bytes
    /// are not one release: no person or more than [`MAX_RELEASE_PERSONS`],
    /// an identity that is empty, runs past the end or past its bound, or
    /// bytes after the last person.
    ///
    /// Only the layout is checked. Whether the bytes of a person are an
    /// identity, and whether the checkers satisfy the approval rule, is the
    /// engine's check.
    #[must_use]
    pub fn split(release: &'a [u8]) -> Option<Self> {
        let mut rest = release;
        let persons = usize::from(*take(&mut rest, 1)?.first()?);
        if !(1..=MAX_RELEASE_PERSONS).contains(&persons) {
            return None;
        }
        let releaser = person(&mut rest)?;
        let mut checkers = [None; 2];
        for slot in checkers.iter_mut().take(persons.saturating_sub(1)) {
            *slot = Some(person(&mut rest)?);
        }
        rest.is_empty().then_some(Self { releaser, checkers })
    }

    /// Returns the identity of the person who releases the halt.
    #[must_use]
    pub const fn releaser(&self) -> &'a [u8] {
        self.releaser
    }

    /// Returns the identities of the checkers, the first slot filled first.
    #[must_use]
    pub const fn checkers(&self) -> [Option<&'a [u8]>; 2] {
        self.checkers
    }
}

/// Takes one length-prefixed identity off `rest`.
fn person<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::from(*take(rest, 1)?.first()?);
    let identity = take(rest, len)?;
    (1..=MAX_IDENTITY_LEN)
        .contains(&identity.len())
        .then_some(identity)
}

/// Takes the next `len` bytes of `rest`, or returns `None` when fewer are left.
fn take<'a>(rest: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (taken, tail) = rest.split_at_checked(len)?;
    *rest = tail;
    Some(taken)
}
