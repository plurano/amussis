// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The hardened `justitia-interceptor` unit, reviewed as a contract.
//!
//! The unit text lives at `crates/aegis-justitia/contracts/`
//! `justitia-interceptor.service`. It is **a contract file, not an installed
//! unit**: nothing in this repository copies it into a systemd unit directory,
//! enables it or starts it, and the `ExecStart` binary it names is not built by
//! this milestone (the crate ships a library and declares no `[[bin]]`).
//!
//! What is executable about it is the review. [`review`] is ordinary library
//! code that reads unit text and refuses it when a hardening directive is
//! missing, so "the unit declares `IPAddressDeny=any`" is a check that fails
//! when someone deletes the line, rather than a sentence in a document.
//! `IPAddressDeny=any` is the directive the source ties to the Zero-SaaS
//! requirement (export-015 `fcbe2caed363`).
//!
//! The unit text must also carry [`CONTRACT_MARKER`] in its header, so a copy
//! that has had the "this is not an installed unit" warning stripped out of it
//! fails review as well.

/// Scalar upper bound, in bytes, on a unit file this module will review.
pub const MAX_UNIT_BYTES: usize = 8192;

/// Scalar upper bound on the lines this module will read from a unit file.
pub const MAX_UNIT_LINES: usize = 256;

/// The marker the unit header must carry to say what the file is.
pub const CONTRACT_MARKER: &str = "CONTRACT-ONLY";

/// The directives the hardened unit must declare, each on a line of its own.
pub const REQUIRED_DIRECTIVES: [&str; 5] = [
    "IPAddressDeny=any",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "Type=notify",
    "Restart=always",
];

/// The systemd directories an installed unit would live in.
///
/// The contract file is refused a home in any of them; [`is_installed_path`]
/// is how a check states that rather than assuming it.
pub const INSTALL_DIRECTORIES: [&str; 4] = [
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/lib/systemd/system/",
    "/run/systemd/system/",
];

/// Reasons a unit text fails the contract review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UnitContractError {
    /// A required hardening directive is absent.
    #[error("the unit does not declare {directive}")]
    MissingDirective {
        /// The directive that was not found.
        directive: &'static str,
    },
    /// The header does not say that the file is a contract, not a unit.
    #[error("the unit header does not carry the {CONTRACT_MARKER} marker")]
    MissingContractMarker,
    /// The text is longer than this module will read.
    #[error("the unit text of {actual} bytes exceeds the bound of {max}")]
    TooLong {
        /// The scalar bound in bytes.
        max: usize,
        /// The width observed.
        actual: usize,
    },
}

/// Records which required directives one line declares.
fn mark(present: &mut [bool; REQUIRED_DIRECTIVES.len()], line: &str) {
    for (slot, directive) in present.iter_mut().zip(REQUIRED_DIRECTIVES.iter()) {
        if line == *directive {
            *slot = true;
        }
    }
}

/// Returns the first required directive that no line declared.
fn first_missing(present: [bool; REQUIRED_DIRECTIVES.len()]) -> Option<&'static str> {
    for (slot, directive) in present.iter().zip(REQUIRED_DIRECTIVES.iter()) {
        if !*slot {
            return Some(directive);
        }
    }
    None
}

/// Reviews unit text against the hardened-unit contract.
///
/// Comment lines are read for [`CONTRACT_MARKER`] and ignored for directives,
/// so a directive that survives only inside a comment does not count as
/// declared.
///
/// # Errors
///
/// Returns [`UnitContractError::TooLong`] past [`MAX_UNIT_BYTES`],
/// [`UnitContractError::MissingContractMarker`] when the header marker is
/// absent, and [`UnitContractError::MissingDirective`] naming the first
/// required directive the text does not declare.
pub fn review(text: &str) -> Result<(), UnitContractError> {
    if text.len() > MAX_UNIT_BYTES {
        return Err(UnitContractError::TooLong {
            max: MAX_UNIT_BYTES,
            actual: text.len(),
        });
    }
    let mut marked = false;
    let mut present = [false; REQUIRED_DIRECTIVES.len()];
    for line in text.lines().take(MAX_UNIT_LINES) {
        let trimmed = line.trim();
        marked = marked || trimmed.contains(CONTRACT_MARKER);
        if !trimmed.starts_with('#') {
            mark(&mut present, trimmed);
        }
    }
    if !marked {
        return Err(UnitContractError::MissingContractMarker);
    }
    match first_missing(present) {
        Some(directive) => Err(UnitContractError::MissingDirective { directive }),
        None => Ok(()),
    }
}

/// Returns `true` when `path` is inside a directory systemd loads units from.
///
/// The contract file must never be at such a path: it is reviewed, not
/// installed, and this is the check that says so.
#[must_use]
pub fn is_installed_path(path: &str) -> bool {
    INSTALL_DIRECTORIES
        .iter()
        .any(|directory| path.starts_with(directory))
}
