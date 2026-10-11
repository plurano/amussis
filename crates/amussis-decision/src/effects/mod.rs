// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The only part of the crate permitted to touch the host environment.
//!
//! Review invariant: a search for `SystemTime` or `std::fs` outside
//! `src/effects/` must return nothing. Everything else in the crate is a total
//! function over owned values.

pub mod system_clock;

pub use system_clock::SystemClock;
