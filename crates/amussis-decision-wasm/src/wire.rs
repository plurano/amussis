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

use amussis_decision::{
    AuditRecord, DIGEST_LEN, MAX_IDENTITY_LEN, MAX_PREIMAGE_BYTES, MAX_SIGNATURE_BYTES,
};

/// Version byte every frame starts with.
pub const FRAME_VERSION: u8 = 1;

/// Largest frame: every variable part at its bound.
pub const MAX_FRAME_BYTES: usize =
    1 + 2 + MAX_PREIMAGE_BYTES + DIGEST_LEN + 1 + MAX_IDENTITY_LEN + 2 + MAX_SIGNATURE_BYTES;

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
