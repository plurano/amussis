// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Wall-clock abstraction and approval deadlines.
//!
//! A [`Deadline`] can only be produced by [`Deadline::open`], which uses checked
//! arithmetic, so a zero-width or wrapped window is unrepresentable. The closed
//! test is `now >= due`: equality is closed, which is the fail-closed reading of
//! the milestone boundary case.
//!
//! The [`Clock`] boundary is load-bearing, not decorative. Every time the
//! engine needs the wall clock it calls [`Clock::now`] and pushes the reading
//! through a [`MonotonicGuard`]; a source that errors, and a source that steps
//! backwards, both surface as [`ClockError`] and the engine fails closed on
//! them. There is no path on which a caller-supplied timestamp replaces the
//! clock.

use core::num::NonZeroU32;

/// Reasons a clock reading is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClockError {
    /// The clock reported a time before the Unix epoch.
    #[error("clock reported a time before the Unix epoch")]
    BeforeEpoch,
    /// The clock moved backwards relative to an earlier observation.
    #[error("clock moved backwards: last {last}, observed {observed}")]
    NonMonotonic {
        /// The most recent previously observed time.
        last: u64,
        /// The time just observed.
        observed: u64,
    },
}

/// Reasons an approval window cannot be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeadlineError {
    /// Adding the window to the opening time would overflow.
    #[error("approval window overflows the representable time range")]
    Overflow,
}

/// A whole number of seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixSeconds(u64);

impl UnixSeconds {
    /// The epoch itself.
    pub const EPOCH: Self = Self(0);

    /// Wraps a second count.
    #[must_use]
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the wrapped second count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds a window, returning `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, ttl: Ttl) -> Option<Self> {
        match self.0.checked_add(ttl.seconds() as u64) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl core::fmt::Display for UnixSeconds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A strictly positive approval window, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl(NonZeroU32);

impl Ttl {
    /// Wraps a strictly positive second count.
    #[must_use]
    pub const fn new(seconds: NonZeroU32) -> Self {
        Self(seconds)
    }

    /// Wraps `seconds`, returning `None` when it is zero.
    #[must_use]
    pub const fn from_secs(seconds: u32) -> Option<Self> {
        match NonZeroU32::new(seconds) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the window width in seconds.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.0.get()
    }
}

/// Whether an approval window is still open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineStatus {
    /// The window is still open; `now` is strictly before the due time.
    Open,
    /// The window is closed; `now` is at or after the due time.
    Closed,
}

/// A half-open approval window `[opened_at, due_at)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    opened_at: UnixSeconds,
    due_at: UnixSeconds,
}

impl Deadline {
    /// Opens a window of `ttl` seconds at `opened_at`.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineError::Overflow`] when the sum would leave the
    /// representable range. The addition is checked and never wraps.
    pub fn open(opened_at: UnixSeconds, ttl: Ttl) -> Result<Self, DeadlineError> {
        let due_at = opened_at.checked_add(ttl).ok_or(DeadlineError::Overflow)?;
        Ok(Self { opened_at, due_at })
    }

    /// Returns the time the window was opened.
    #[must_use]
    pub const fn opened_at(&self) -> UnixSeconds {
        self.opened_at
    }

    /// Returns the time the window closes.
    #[must_use]
    pub const fn due_at(&self) -> UnixSeconds {
        self.due_at
    }

    /// Classifies `now` against the window; `now >= due_at` is closed.
    #[must_use]
    pub fn status(&self, now: UnixSeconds) -> DeadlineStatus {
        if now >= self.due_at {
            DeadlineStatus::Closed
        } else {
            DeadlineStatus::Open
        }
    }
}

/// A source of wall-clock time.
pub trait Clock {
    /// Reads the current time.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError`] when the underlying source is unusable. A caller
    /// on the decision path must treat the error as fail-closed.
    fn now(&self) -> Result<UnixSeconds, ClockError>;
}

/// Rejects a clock reading that precedes the previous one.
///
/// This is the only producer of [`ClockError::NonMonotonic`]. A wall clock may
/// be stepped by an administrator or by NTP; a decision engine that accepted
/// the step would backdate an audit record, so the guard refuses it and the
/// caller fails closed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MonotonicGuard {
    last: Option<UnixSeconds>,
}

impl MonotonicGuard {
    /// Builds a guard that has observed nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// Returns the most recent accepted reading, if there is one.
    #[must_use]
    pub const fn last(&self) -> Option<UnixSeconds> {
        self.last
    }

    /// Accepts `observed` when it is at or after the previous reading.
    ///
    /// A reading equal to the previous one is accepted: a second-resolution
    /// clock read twice inside one second is not a fault.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::NonMonotonic`] when `observed` precedes the
    /// previous reading. The guard keeps the earlier reading, so a stepped
    /// clock cannot be laundered by retrying.
    pub fn observe(&mut self, observed: UnixSeconds) -> Result<UnixSeconds, ClockError> {
        if let Some(last) = self.last
            && observed < last
        {
            return Err(ClockError::NonMonotonic {
                last: last.get(),
                observed: observed.get(),
            });
        }
        self.last = Some(observed);
        Ok(observed)
    }
}

/// A clock pinned to one time. Library code, not test-only, so a deterministic
/// replay harness can drive an engine outside this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    at: UnixSeconds,
}

impl FixedClock {
    /// Builds a clock pinned to `at`.
    #[must_use]
    pub const fn new(at: UnixSeconds) -> Self {
        Self { at }
    }

    /// Moves the pinned time. A replay harness advances it between steps.
    ///
    /// Moving it backwards is permitted here and refused one layer up by
    /// [`MonotonicGuard`], so the fault is observable rather than unrepresentable.
    pub const fn set(&mut self, at: UnixSeconds) {
        self.at = at;
    }

    /// Returns the pinned time without the [`Clock`] error channel.
    #[must_use]
    pub const fn at(&self) -> UnixSeconds {
        self.at
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Result<UnixSeconds, ClockError> {
        Ok(self.at)
    }
}
