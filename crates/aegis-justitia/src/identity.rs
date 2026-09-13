// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Bounded, allocation-free identifiers.
//!
//! Every identifier is validated on construction and stored inline, so no
//! decision path allocates and no identifier can be silently truncated or
//! sanitised: a malformed input is refused.

use core::fmt;

use crate::{MAX_IDENTITY_LEN, MAX_TARGET_LEN};

/// Reasons an identifier string is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The string was empty.
    #[error("identifier is empty")]
    Empty,
    /// The string exceeded the scalar bound for its kind.
    #[error("identifier of {actual} bytes exceeds the bound of {max}")]
    TooLong {
        /// Inclusive upper bound in bytes.
        max: usize,
        /// Observed length in bytes.
        actual: usize,
    },
    /// The string contained a byte outside the permitted character set.
    #[error("identifier contains a byte outside the permitted character set")]
    Charset,
}

/// Returns `true` for the bytes permitted inside an identifier.
#[must_use]
const fn permitted(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'@' | b'/')
}

/// Validates `raw` against `max` and copies it into a fixed buffer of `N` bytes.
fn validate<const N: usize>(raw: &str, max: usize) -> Result<([u8; N], usize), IdentityError> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Err(IdentityError::Empty);
    }
    if bytes.len() > max || bytes.len() > N {
        return Err(IdentityError::TooLong {
            max,
            actual: bytes.len(),
        });
    }
    let mut buffer = [0u8; N];
    for (slot, byte) in buffer.iter_mut().zip(bytes.iter().take(N)) {
        if !permitted(*byte) {
            return Err(IdentityError::Charset);
        }
        *slot = *byte;
    }
    Ok((buffer, bytes.len()))
}

/// A validated principal or object name of at most [`MAX_IDENTITY_LEN`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identity {
    bytes: [u8; MAX_IDENTITY_LEN],
    len: u8,
}

impl Identity {
    /// Parses `raw` into an identity.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when `raw` is empty, longer than
    /// [`MAX_IDENTITY_LEN`] bytes, or contains a byte outside the permitted
    /// character set. The input is never truncated or sanitised.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        let (bytes, len) = validate::<MAX_IDENTITY_LEN>(raw, MAX_IDENTITY_LEN)?;
        let len = u8::try_from(len).map_err(|_| IdentityError::TooLong {
            max: MAX_IDENTITY_LEN,
            actual: len,
        })?;
        Ok(Self { bytes, len })
    }

    /// Returns the validated bytes, without the trailing padding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `false`; an identity is never empty by construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = core::str::from_utf8(self.as_bytes()).map_err(|_| fmt::Error)?;
        f.write_str(text)
    }
}

/// Declares a role-tagged wrapper so two roles can never be confused.
macro_rules! role_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(Identity);

        impl $name {
            /// Parses a role-tagged identifier.
            ///
            /// # Errors
            ///
            /// Propagates [`IdentityError`] from [`Identity::parse`].
            pub fn parse(raw: &str) -> Result<Self, IdentityError> {
                Identity::parse(raw).map(Self)
            }

            /// Wraps an already validated identity.
            #[must_use]
            pub const fn from_identity(identity: Identity) -> Self {
                Self(identity)
            }

            /// Returns the untagged identity.
            #[must_use]
            pub const fn identity(&self) -> &Identity {
                &self.0
            }

            /// Returns the validated bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

role_id!(MakerId, "The principal that proposes an action.");
role_id!(CheckerId, "The principal that reviews a proposed action.");
role_id!(
    AgentId,
    "The agent process on whose behalf an action is proposed."
);
role_id!(IntentId, "Stable identifier of one proposed action.");
role_id!(RequestId, "Stable identifier of one approval request.");
role_id!(
    SignerKeyId,
    "Identifier of the key that sealed an audit record."
);

impl MakerId {
    /// Returns `true` when the maker and the checker are the same principal.
    #[must_use]
    pub fn is_same_principal(&self, checker: &CheckerId) -> bool {
        self.0 == checker.0
    }
}

/// A validated target resource of at most [`MAX_TARGET_LEN`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetResource {
    bytes: [u8; MAX_TARGET_LEN],
    len: u16,
}

impl TargetResource {
    /// Parses `raw` into a target resource.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when `raw` is empty, longer than
    /// [`MAX_TARGET_LEN`] bytes, or outside the permitted character set.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        let (bytes, len) = validate::<MAX_TARGET_LEN>(raw, MAX_TARGET_LEN)?;
        let len = u16::try_from(len).map_err(|_| IdentityError::TooLong {
            max: MAX_TARGET_LEN,
            actual: len,
        })?;
        Ok(Self { bytes, len })
    }

    /// Returns the validated bytes, without the trailing padding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `false`; a target resource is never empty by construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Display for TargetResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = core::str::from_utf8(self.as_bytes()).map_err(|_| fmt::Error)?;
        f.write_str(text)
    }
}
