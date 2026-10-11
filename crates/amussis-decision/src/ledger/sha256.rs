// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The single [`LedgerHasher`] implementation. This is the only module in the
//! crate that names a concrete hash function.

use sha2::Digest as _;

use crate::DIGEST_LEN;
use crate::ledger::hash::{Digest32, HashAlgorithm, HashError, LedgerHasher};

/// FIPS 180-4 SHA-256, the algorithm decision D02 records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sha256Hasher;

impl LedgerHasher for Sha256Hasher {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;

    fn digest(preimage: &[u8]) -> Result<Digest32, HashError> {
        let output = sha2::Sha256::digest(preimage);
        let bytes: &[u8] = output.as_ref();
        let sized = <[u8; DIGEST_LEN]>::try_from(bytes).map_err(|_| HashError::Width {
            expected: DIGEST_LEN,
            actual: bytes.len(),
        })?;
        Ok(Digest32::from_bytes(sized))
    }
}
