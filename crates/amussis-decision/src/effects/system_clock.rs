// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The host wall clock. This is the only module that names `SystemTime`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::time::{Clock, ClockError, UnixSeconds};

/// Reads the host wall clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

impl SystemClock {
    /// Builds a host clock reader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Result<UnixSeconds, ClockError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::BeforeEpoch)?;
        Ok(UnixSeconds::new(elapsed.as_secs()))
    }
}
