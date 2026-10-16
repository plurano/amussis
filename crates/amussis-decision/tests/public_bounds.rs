// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! HISS-14: the public bounds are part of the append-only interface.
//!
//! The boundary tests elsewhere read each bound through its constant, so a
//! changed value moves them along with it. These literals pin the published
//! values; changing one is a breaking change and fails here first.

use amussis_decision::proposal::MAX_PROPOSAL_BYTES;
use amussis_decision::{
    DEFAULT_APPROVAL_TTL_SECS, DEFAULT_SINK_SERVICE_MILLIS, DIGEST_HEX_CHARS, DIGEST_LEN,
    MAX_CONTRACT_PAYLOAD_BYTES, MAX_IDENTITY_LEN, MAX_LEDGER_RECORDS, MAX_PENDING_REQUESTS,
    MAX_PREIMAGE_BYTES, MAX_RETAINED_AUDIT_BYTES, MAX_SIGNATURE_BYTES, MAX_SIGNATURE_HEX_CHARS,
    MAX_TARGET_LEN,
};

#[test]
fn size_bounds_keep_their_published_values() {
    assert_eq!(MAX_LEDGER_RECORDS, 4096);
    assert_eq!(MAX_RETAINED_AUDIT_BYTES, 8_388_608);
    assert_eq!(MAX_PREIMAGE_BYTES, 512);
    assert_eq!(MAX_PENDING_REQUESTS, 256);
    assert_eq!(MAX_IDENTITY_LEN, 64);
    assert_eq!(MAX_TARGET_LEN, 256);
    assert_eq!(MAX_SIGNATURE_BYTES, 512);
    assert_eq!(MAX_CONTRACT_PAYLOAD_BYTES, 4096);
    assert_eq!(MAX_PROPOSAL_BYTES, 4096);
}

#[test]
fn digest_and_hex_widths_keep_their_published_values() {
    assert_eq!(DIGEST_LEN, 32);
    assert_eq!(DIGEST_HEX_CHARS, 64);
    assert_eq!(MAX_SIGNATURE_HEX_CHARS, 1024);
}

#[test]
fn defaults_keep_their_published_values() {
    assert_eq!(DEFAULT_APPROVAL_TTL_SECS, 300);
    assert_eq!(DEFAULT_SINK_SERVICE_MILLIS, 1);
}
