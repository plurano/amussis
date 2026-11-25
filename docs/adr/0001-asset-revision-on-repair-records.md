# ADR-0001: Asset revision on repair records

- **Status**: Proposed
- **Date**: 2026-11-23
- **Authors**: amussis maintainers

## Context

**Short version.** An approved repair must be tied to the commissioned state
of the plant item it covers. Action records name an intent, an agent and an
action type (`ledger/mod.rs:341-348`). Halt-latch records have no subject
(`ledger/mod.rs:446-451`). This ADR adds a typed asset number and revision
to repair proposals, tickets, votes and action records. Existing sealed
heads keep their binary layout (`ledger/mod.rs:635-652`).

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
- The binary pre-image embeds `CONTRACT_VERSION` (`ledger/mod.rs:641`).
  `read_anchor` checks it at line 185 and refuses trailing bytes at line 188
  (`ledger/anchor.rs:168-188`). A version bump would therefore refuse every
  old head. JSONL carries no version, so a reader cannot distinguish layouts
  from a line alone (`ledger/jsonl.rs:20-52`).
- `cargo-semver-checks` in `.github/workflows/ci.yml` holds the public API to
  the v0.2.0 tag. HISS-14 makes the API append-only; a break needs a `!`
  subject and a `Migration:` footer.
- The decision crate lists its dependencies in
  `crates/amussis-decision/Cargo.toml:23-32`. Neither Rhizomorph nor Tornus
  appears there.

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

- One function in D1's `revision.rs` checks that a revision is present
  exactly when the action is `AssetRepair`. Proposal decoding, intent
  construction, ticket revision assignment and record sealing use this rule.
- `Proposal` gains `asset_revision: Option<AssetRevision>`. The JSON key is
  `asset-revision`, following `proposal.rs:95`. A missing key or explicit
  `null` decodes to `None`. The writer omits the key for `None` and never
  writes `null`. Every existing V1 proposal text still decodes. Canonical
  texts re-encode to the same bytes. Escaped spellings may normalise
  (`tests/proposal_text.rs:77-83`, `tests/proposal_text.rs:115-119`).
  Decode refuses a failed fit through a new, append-only variant of the
  `#[non_exhaustive]` `ProposalError` (`proposal.rs:69-70,138-148`).
- `IntentSpec` gains the same field (`intent.rs:27`). `Proposal::spec()`
  copies it into the spec and `Proposal::from_spec()` copies it back
  (`proposal.rs:153-163,118-129`). `Proposal::intent()` calls
  `ActionIntent::new(self.spec())` (`proposal.rs:171-173`). The constructor
  (`intent.rs:63`) checks the fit and returns
  `IntentError::AssetRevisionMismatch` on failure. `IntentError` becomes
  `#[non_exhaustive]` (`intent.rs:11`).
  `ActionIntent::asset_revision()` exposes the validated value.
- `ApprovalTicket` stores its action and has a public constructor
  (`oversight.rs:177-196`). It gains a private revision field and an
  `asset_revision() -> Option<AssetRevision>` accessor. Its public
  `with_asset_revision(self, AssetRevision)` returns a `Result` and checks
  the supplied value against the stored action using the shared fit rule.
  Assigning a revision to a `FileDeletion` ticket fails. The engine copies
  the intent's revision onto the repair ticket before registry insertion
  (`engine.rs:682-693`) and copies the intent or ticket revision into each
  action record it drafts (`engine.rs:797-801,870-874`).
- The request ID comes from the caller's intent ID (`engine.rs:682`).
  A retry can reuse it after a decision or expiry (`registry.rs:13-29`).
  `Engine::adjudicate` looks up the held ticket by request ID alone
  (`engine.rs:733-738,755-760`). It must refuse a held `AssetRepair` with a
  new `OversightError::ReviewedRevisionRequired` variant. `OversightError`
  is exhaustive today (`oversight.rs:16-18`) and already travels through
  `DecisionError::Oversight` (`error.rs:23-32`). D4 makes `OversightError`
  `#[non_exhaustive]` so later variants are append-only.
- `Engine::adjudicate_repair(request, panel, vote, reviewed: AssetRevision)`
  requires a held repair and compares both reviewed numbers with the ticket.
  A mismatch leaves the hold pending and seals no vote. A match proceeds
  through the usual deadline, panel and recording checks
  (`engine.rs:755-760,788-801`). Add matching `AdjudicateRepair` in Go and
  `amussis_adjudicate_repair` in Wasm. Both carry the asset number and
  revision supplied by the checker alongside the existing vote fields
  (`bindings/go/decision/decision.go:187-199,581-590`,
  `crates/amussis-decision-wasm/src/abi.rs:222-229`).
- `RecordSubject` gains `asset_revision: Option<AssetRevision>`
  (`ledger/mod.rs:341-348`). `RecordDraft::is_well_formed()` checks the fit
  for every subject, so a missing repair revision or a revision on another
  action fails sealing with `PreimageError::Shape` (`ledger/mod.rs:541-557`,
  `ledger/mod.rs:635-638`).
- In `RecordBody::canonical_preimage`, the byte after the timestamp is the
  status, followed by the action byte and two refusal-reason bytes
  (`ledger/mod.rs:635-651,724-737`). `read_anchor` currently skips all
  four together after reading the timestamp (`ledger/anchor.rs:42-44,176`).
  It must retain the status and action bytes, step over the two reason bytes
  and read the latch, names and principals as today
  (`ledger/anchor.rs:168-188`).
- For action tag 6, append exactly two big-endian `u64` words after the
  principals, asset first and revision second. The reader consumes each word
  (`ledger/anchor.rs:153-156`) and checks its conversion to `u32`, refusing
  either value above `u32::MAX` and revision zero. Tag 6 requires a status
  that carries a subject (status tags 1 through 5, `ledger/mod.rs:305-314`).
  `HaltEngaged` and `HaltReleased` carry none (`ledger/mod.rs:541-557`).
  Every other action ends at the principals. Both layouts require end of
  input (`ledger/anchor.rs:188`) and use the existing `CONTRACT_VERSION`.
- `LedgerLine` gains an optional `asset_revision`, defaulted and omitted
  when absent. JSONL projects a sealed record for the operator. Parsing a
  line only rebuilds that projection (`ledger/jsonl.rs:6-10,73-79,154-155`).
  Sealing enforces the repair shape (`ledger/mod.rs:635-638`). Parsing a
  JSONL line cannot enforce it. A reader cannot tell
  a stripped revision from a non-repair line because the public fields carry
  no action discriminator (`ledger/jsonl.rs:20-52`).

**D4. Version 0.3.0.** The new public field breaks Rust struct literals for
`RecordSubject`, `Proposal`, `IntentSpec` and `LedgerLine`
(`ledger/mod.rs:341`, `proposal.rs:96`, `intent.rs:27`, `ledger/jsonl.rs:20`).
New variants break exhaustive matches on `ActionType`, `IntentError` and
`OversightError` (`risk.rs:43`, `intent.rs:11`, `oversight.rs:18`).
This release marks both error enums `#[non_exhaustive]`.
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
- Ticket and vote tests extend `tests/registry_lifecycle.rs:38-64`. Refuse a
  revision on a `FileDeletion` ticket and a revision-free vote on a held
  repair. Decide a hold for revision 3, then reuse its request ID for the
  same asset at revision 4. A delayed vote naming revision 3 must fail
  without deciding the new hold. A vote naming revision 4 can still succeed.
- Anchor tests extend `tests/chain_continuation.rs:511-513,528-532`. Accept a
  tag-6 head with both words. Give each malformed head its own digest. Test
  each refusal separately for a missing word, an extra byte, revision zero,
  asset above `u32::MAX`, revision above `u32::MAX`, status `HaltEngaged`,
  status `HaltReleased`, and a trailing byte on a legacy action.

## Consequences

- **Positive**: An audit reader can recover the asset number and revision
  from the same pre-image that determines the digest (`ledger/mod.rs:661-663`).
- **Positive**: Existing heads still continue (`ledger/anchor.rs:168-188`).
  Existing V1 texts still decode and their canonical forms keep their bytes
  (`tests/proposal_text.rs:77-83,115-119`). Omitting an absent revision
  preserves existing JSONL output (`ledger/jsonl.rs:142-145`).
- **Positive**: The checker supplies the reviewed asset and revision with
  the vote. Only a match with the held repair ticket can reach the sealed
  decision, even after request ID reuse (`engine.rs:755-760,792-801`,
  `registry.rs:13-29`).
- **Positive**: A shape rule in `is_well_formed()` makes a planted or
  stripped revision a `PreimageError::Shape` failure, not a silent mismatch.
- **Positive**: With `#[non_exhaustive]` on `ActionType` and `RecordSubject`,
  later additions pass `cargo-semver-checks` and HISS-14 as append-only.
- **Negative**: Rust callers must migrate struct literals for `RecordSubject`,
  `Proposal`, `IntentSpec` and the public JSONL projection `LedgerLine`
  (`ledger/jsonl.rs:20-52`). D4 also requires callers to update exhaustive
  matches on `ActionType`, `IntentError` and `OversightError` (see the
  `Migration:` footer).
- **Negative**: The mirror of Rhizomorph's numbers is by convention; no
  compile-time check ties the two types together, so host mapping code carries
  the risk of drift.
- **Negative**: Pre-image layout now depends on the action tag. Any reader
  of stored pre-images outside this crate must read the two trailing `u64`
  values for tag 6, as `ChainAnchor::from_preimage` does.
- **Negative**: `Proposal` is not made `#[non_exhaustive]` here, so its next
  new field is again a breaking change.
- **Negative**: The Tier A floor requires a checker even for a low-hazard
  repair. Standard Tier A requires one checker. Annex III requires two
  distinct checkers at every tier (`risk.rs:106-116`).

## Alternatives considered

- **Depend on the Rhizomorph kernel crate.** Rejected: it couples amussis
  releases to another repository for two integers (D1).
- **Copy generic `RevisionIdentity<S>` with a model variant now.** Rejected:
  no flow uses model revisions (D5), so it would publish unused API that
  HISS-14 then forbids removing.
- **Put the revision in `TargetResource` text.** The parser rejects empty,
  oversized or invalid text (`identity.rs:195-208`). Target text has no
  typed revision and the vote never carries it (`engine.rs:733-738`).
- **Derive the request ID from the intent ID and revision.** This would
  distinguish successive revisions of one intent (`engine.rs:682`), but the
  vote would still omit which asset and revision the checker reviewed
  (`engine.rs:733-738`).
- **Bump `CONTRACT_VERSION`.** The binary pre-image embeds the version
  (`ledger/mod.rs:641`) and `read_anchor` compares it (`ledger/anchor.rs:185`).
  A bump would therefore refuse every old head. JSONL has no version field
  to tell a reader which layout produced a line (`ledger/jsonl.rs:20-52`).
- **Write the revision between the names and the principals.** Rejected: the
  anchor reader would need a second conditional field in the middle of the
  layout; one trailing field keeps the existing prefix byte-identical.

## Open questions

- Must a repair approval also check that the revision is the asset's current
  one? That needs a host query; the decision crate holds no plant state.
- Is Tier A the right floor, or should the class come from the plant's own
  hazard rating?
