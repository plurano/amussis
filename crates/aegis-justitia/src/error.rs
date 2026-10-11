// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The aggregate crate error.
//!
//! This is public API, not an afterthought. Without the `#[from]` conversions a
//! caller that touches two boundaries cannot use `?` and falls back to
//! `unwrap`, which HISS-07 forbids. Every variant carries its originating
//! error, so an error is wrapped with context rather than flattened to a string.

use crate::identity::IdentityError;
use crate::intent::IntentError;
use crate::ledger::hash::{HashError, PreimageError};
use crate::ledger::signer::SignError;
use crate::ledger::{LedgerError, SinkError};
use crate::oversight::OversightError;
use crate::registry::RegistryError;
use crate::time::{ClockError, DeadlineError};

/// Any error this crate can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JustitiaError {
    /// An identifier was refused.
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    /// A proposed action was refused before classification.
    #[error("intent: {0}")]
    Intent(#[from] IntentError),
    /// An oversight step was refused.
    #[error("oversight: {0}")]
    Oversight(#[from] OversightError),
    /// The pending-request registry refused an operation.
    #[error("registry: {0}")]
    Registry(#[from] RegistryError),
    /// An approval window could not be opened.
    #[error("deadline: {0}")]
    Deadline(#[from] DeadlineError),
    /// The wall clock was unusable.
    #[error("clock: {0}")]
    Clock(#[from] ClockError),
    /// The ledger refused a record or a chain.
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    /// A digest could not be produced or parsed.
    #[error("hash: {0}")]
    Hash(#[from] HashError),
    /// A canonical pre-image could not be built.
    #[error("preimage: {0}")]
    Preimage(#[from] PreimageError),
    /// A record could not be sealed.
    #[error("seal: {0}")]
    Sign(#[from] SignError),
    /// A sink refused a record.
    #[error("sink: {0}")]
    Sink(#[from] SinkError),
}
