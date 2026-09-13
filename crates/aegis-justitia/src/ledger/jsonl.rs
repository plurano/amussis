// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Optional JSON Lines rendering, behind the `jsonl` feature.
//!
//! The renderer is off by default so the default build carries three direct
//! dependencies and the P06 to P16 record schema is not frozen before M14 pins
//! it. It is deliberately not on the hashing path: the chain digest is taken
//! over the crate's own canonical encoding, so a serialisation-library release
//! can never alter a historical ledger digest.

use crate::ledger::AuditRecord;
use crate::ledger::RecordStatus;
use crate::ledger::hash::{HashAlgorithm, HashError};

/// One rendered ledger line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LedgerLine {
    /// The record's chain position.
    pub sequence: u64,
    /// The algorithm the record names. A persisted `md5` tag fails to parse.
    pub algorithm: HashAlgorithm,
    /// The decision recorded.
    pub status: RecordStatus,
    /// Why the action was refused, when it was.
    pub block_reason: Option<String>,
    /// When the decision was taken.
    pub at: u64,
    /// The predecessor link, lower-case hexadecimal.
    pub previous: String,
    /// This record's digest, lower-case hexadecimal.
    pub digest: String,
    /// The intent the record describes.
    pub intent_id: String,
    /// The agent that proposed the action.
    pub agent: String,
    /// Whether the halt latch was engaged when the decision was taken.
    pub killswitch_engaged: bool,
}

/// Reasons a record cannot be rendered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    /// A digest could not be rendered as hexadecimal.
    #[error("digest: {0}")]
    Hash(#[from] HashError),
    /// An identifier was not valid UTF-8.
    #[error("identifier is not valid UTF-8")]
    Encoding,
    /// The line could not be serialised.
    #[error("serialisation failed")]
    Serialisation,
}

/// Projects a sealed record onto its rendered form.
///
/// # Errors
///
/// Returns [`RenderError`] when a digest or identifier cannot be rendered.
pub fn project(record: &AuditRecord) -> Result<LedgerLine, RenderError> {
    let body = record.body();
    let draft = body.draft();
    let mut previous_buffer = [0u8; 64];
    let mut digest_buffer = [0u8; 64];
    let previous = body.previous().encode_hex(&mut previous_buffer)?.to_owned();
    let digest = record.digest().encode_hex(&mut digest_buffer)?.to_owned();
    let intent_id = core::str::from_utf8(draft.intent_id.as_bytes())
        .map_err(|_| RenderError::Encoding)?
        .to_owned();
    let agent = core::str::from_utf8(draft.agent.as_bytes())
        .map_err(|_| RenderError::Encoding)?
        .to_owned();
    Ok(LedgerLine {
        sequence: body.sequence().get(),
        algorithm: body.algorithm(),
        status: draft.status,
        block_reason: draft.block_reason.map(|reason| reason.name().to_owned()),
        at: draft.at.get(),
        previous,
        digest,
        intent_id,
        agent,
        killswitch_engaged: draft.killswitch.is_engaged(),
    })
}

/// Renders one record as a single JSON line, without the trailing newline.
///
/// # Errors
///
/// Returns [`RenderError`] when the record cannot be projected or serialised.
pub fn render_line(record: &AuditRecord) -> Result<String, RenderError> {
    let line = project(record)?;
    serde_json::to_string(&line).map_err(|_| RenderError::Serialisation)
}

/// Parses one rendered ledger line.
///
/// # Errors
///
/// Returns [`RenderError::Serialisation`] for anything that is not exactly one
/// rendered line. A line naming an algorithm the crate does not admit, such as
/// `md5`, fails here.
pub fn parse_line(text: &str) -> Result<LedgerLine, RenderError> {
    serde_json::from_str(text).map_err(|_| RenderError::Serialisation)
}

/// Returns `true` when `line` names the algorithm the ledger uses.
#[must_use]
pub const fn uses_sha256(line: &LedgerLine) -> bool {
    matches!(line.algorithm, HashAlgorithm::Sha256)
}
