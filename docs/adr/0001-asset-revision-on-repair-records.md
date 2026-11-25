# ADR-0001: Asset revision on repair records

- **Status**: Proposed
- **Date**: 2026-11-23
- **Authors**: amussis maintainers

## Context

**Short version.** An approved repair must be tied to the commissioned state
of the plant item it covers. Today a ledger record names an intent, an agent
and an action type, but no asset. This ADR adds a typed asset number and
revision to repair proposals, approval tickets and ledger records. It does so
without invalidating any chain already sealed.

Three projects share the asset lifecycle. amussis (Latin *amussis*, the mason's
levelling board; pronounced ah-MOOS-sis) is this repository. Tornus (Latin for a
lathe; pronounced TOR-noos) owns asset design. Rhizomorph (Greek *rhiza* (root)
and *morphe* (form), a root-like fungal cord; pronounced RY-zo-morf) owns
commissioning and operation. amussis owns repair approval and audit. An audit
reader must be able to tie a decision to the plant item and its revision.

**Rhizomorph side.** `crates/kernel/src/lib.rs` in lusoris/rhizomorph (merged
in its pull request 38 on 2026-11-23, read at commit 555363e1b4a0) defines
`Revision(NonZeroU32)` (zero refused by
`Revision::new`), `AssetId(pub u32)`, `ModelId(pub u32)` and
`RevisionIdentity<S>`, with aliases `AssetRevision` and `ModelRevision`. The
kernel is `no_std` and numbers only; the host maps external names to numbers.

**amussis side** (workspace 0.2.0), the facts that constrain the design:

- `ActionType` in `crates/amussis-decision/src/risk.rs` is an exhaustive enum
  with five variants. `tag()` returns 1..=5 and `minimum_tier()` floors
  deletion, escalation and system config at Tier A.
- `Proposal` (`proposal.rs`) has all-public fields and `deny_unknown_fields`.
  `ProposalVersion` and `ProposalError` are `#[non_exhaustive]`.
  `ApprovalTicket` (`oversight.rs`) has private fields.
- `RecordSubject` and `RecordDraft` live in `ledger/mod.rs`.
  `RecordDraft::is_well_formed()` decides which field combinations a status
  allows. `RecordBody::canonical_preimage()` refuses a malformed draft with
  `PreimageError::Shape`, then writes the action tag before the names.
- `ChainAnchor::from_preimage` (`ledger/anchor.rs:175-187`) reads a stored
  pre-image back field by field, compares `CONTRACT_VERSION`, and refuses
  any bytes left after the second checker. `LedgerLine` (`ledger/jsonl.rs`)
  carries no contract version, so changing `CONTRACT_VERSION` would stop
  every existing chain from continuing.
- `cargo-semver-checks` in `.github/workflows/ci.yml` holds the public API to
  the v0.2.0 tag. HISS-14 makes the API append-only; a break needs a `!`
  subject and a `Migration:` footer.
- The workspace `Cargo.toml` shows `amussis-decision` depends on no Rhizomorph
  or Tornus crate.

## Decision

**D1. Own value type, no Rhizomorph dependency.** A new module
`crates/amussis-decision/src/revision.rs`, re-exported from the crate root,
defines `AssetRevision { asset: u32, revision: NonZeroU32 }`:

- `new(asset: u32, revision: u32) -> Result<AssetRevision, RevisionError>`
  refuses revision 0. `asset()` returns `u32`; `revision()` returns
  `NonZeroU32`.
- serde form is `{"asset": 7, "revision": 3}` with `deny_unknown_fields`.
  Revision 0 is refused on decode.
- It mirrors Rhizomorph's numbers. The host converts with
  `AssetId::as_u32()` and `Revision::get()`.

A dependency would couple the release of a published decision crate to
another repository's kernel for two integers.

**D2. New action `ActionType::AssetRepair`.** Serde name `asset-repair`,
tag 6, minimum tier A, because a repair touches physical plant.

**D3. Exactly `asset-repair` carries a revision, end to end.**

- `Proposal` gains `asset_revision: Option<AssetRevision>`, defaulted and
  skipped when none, so every existing V1 proposal text decodes and
  re-encodes byte-identically. Decode refuses `asset-repair` without it and
  any other action with it, through a new `ProposalError` variant (append-only
  because the enum is `#[non_exhaustive]`).
- `IntentSpec` (`intent.rs`) gains the same field, and `ActionIntent` keeps
  it, read by `ActionIntent::asset_revision()`. `ActionIntent::new` refuses
  a spec whose action and revision do not fit, through a new
  `IntentError::AssetRevisionMismatch` variant. `IntentError` becomes
  `#[non_exhaustive]`. `Proposal::intent()` carries the proposal's revision
  into the spec.
- `ApprovalTicket` gains a private field, set by
  `with_asset_revision(self, AssetRevision) -> Self` and read by
  `asset_revision() -> Option<AssetRevision>`. The engine (`engine.rs`) sets
  it from the intent when it opens the hold, and copies the revision of the
  intent or the ticket into every record subject it drafts.
- One fit rule, one function in `revision.rs`: an `AssetRepair` action has a
  revision and every other action has none. The proposal decode,
  `ActionIntent::new` and `RecordDraft::is_well_formed()` all call it.
- `RecordSubject` gains `asset_revision: Option<AssetRevision>`.
  `is_well_formed()` requires it exactly when `action_type` is `AssetRepair`.
  A repair record without it, or any other record with it, fails
  `canonical_preimage()` with `PreimageError::Shape`.
- Pre-image: for an `AssetRepair` record only, after the principals (the
  last field today), write the asset and the revision as two `u64` values.
  `CONTRACT_VERSION` does not change. The action tag is written earlier and
  decides the layout, so every record sealed today keeps its exact
  pre-image. `ChainAnchor::from_preimage` reads the two values when the
  action tag is 6 and still refuses any other trailing bytes.
- `LedgerLine` gains `asset_revision`, defaulted and skipped when none, so
  existing JSONL lines read and render unchanged.

**D4. Version 0.3.0.** A new public field on `RecordSubject`, `Proposal`
and `IntentSpec`, and a new variant on the exhaustive `ActionType` and
`IntentError`, break Rust callers (struct literals, exhaustive matches). They break no stored record or proposal text.
The change ships as 0.3.0 with a `!` subject and a `Migration:` footer. It
also marks `ActionType` and `RecordSubject` `#[non_exhaustive]` and adds
`RecordSubject::new`, so a later field or action there is append-only.

**D5. Model revisions are out of scope.** No amussis flow approves a Tornus
design release today. Revisit when a proposal approves a design-model change;
the Rhizomorph `ModelRevision` alias would then be mirrored the same way.

**D6. Sequencing and tests.** The Rhizomorph type landed first. amussis then
implements D1 to D4 with these tests, to be added under
`crates/amussis-decision`:

- Boundary: revision 1 and `u32::MAX` accepted, 0 refused (constructor and
  serde decode).
- Negative: a repair proposal without a revision is refused; a repair record
  without one is refused by `canonical_preimage()`; a non-repair record or
  proposal with one is refused.
- Compatibility: an existing non-repair record fixture keeps its pre-image
  digest, and `ChainAnchor` still continues a chain whose last record was
  sealed before this change.
- Anchor: a repair pre-image with the two values continues; one with them
  missing or with extra bytes is refused.

## Consequences

- **Positive**: An audit reader can tie a repair decision to one asset
  and one revision, and the revision is part of the sealed pre-image rather
  than free text.
- **Positive**: Existing chains, proposal texts and JSONL lines are
  untouched, because `CONTRACT_VERSION` and the non-repair layout do not
  change (`ledger/anchor.rs:185`).
- **Positive**: The approval ticket carries the revision, so the checker
  votes on a named asset state, and the sealed record states the same one.
- **Positive**: A shape rule in `is_well_formed()` makes a planted or
  stripped revision a `PreimageError::Shape` failure, not a silent mismatch.
- **Positive**: With `#[non_exhaustive]` on `ActionType` and `RecordSubject`,
  later additions pass `cargo-semver-checks` and HISS-14 as append-only.
- **Negative**: 0.3.0 is a breaking release for Rust callers. Every struct
  literal of `RecordSubject`, `Proposal` or `IntentSpec` and every
  exhaustive `match` on `ActionType` or `IntentError` must change (see the
  `Migration:` footer).
- **Negative**: The mirror of Rhizomorph's numbers is by convention; no
  compile-time check ties the two types together, so host mapping code carries
  the risk of drift.
- **Negative**: Pre-image layout now depends on the action tag. Any reader
  of stored pre-images outside this crate must read the two trailing `u64`
  values for tag 6, as `ChainAnchor::from_preimage` does.
- **Negative**: `Proposal` is not made `#[non_exhaustive]` here, so its next
  new field is again a breaking change.
- **Negative**: Tier A as a floor means every repair needs the strictest
  approval path, whatever the plant item's actual hazard.

## Alternatives considered

- **Depend on the Rhizomorph kernel crate.** Rejected: it couples amussis
  releases to another repository for two integers (D1).
- **Copy generic `RevisionIdentity<S>` with a model variant now.** Rejected:
  no flow uses model revisions (D5), so it would publish unused API that
  HISS-14 then forbids removing.
- **Put the revision in `TargetResource` text.** Rejected: it is unchecked,
  not part of the vote, and not typed.
- **Bump `CONTRACT_VERSION`.** Rejected: `ledger/anchor.rs:185` would refuse
  to continue every existing chain, since `LedgerLine` carries no version.
- **Write the revision between the names and the principals.** Rejected: the
  anchor reader would need a second conditional field in the middle of the
  layout; one trailing field keeps the existing prefix byte-identical.

## Open questions

- Must a repair approval also check that the revision is the asset's current
  one? That needs a host query; the decision crate holds no plant state.
- Is Tier A the right floor, or should the class come from the plant's own
  hazard rating?
