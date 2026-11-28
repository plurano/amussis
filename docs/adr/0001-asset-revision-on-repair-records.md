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

amussis (Latin for the mason's levelling board, pronounced ah-MOOS-sis)
houses the decision engine, its Wasm module and its Go binding
(`docs/index.md:8-18`). This ADR puts repair approval and audit there.
In the upstream projects' terms, Tornus (Latin for a lathe, pronounced
TOR-noos) owns asset design. Rhizomorph (Greek *rhiza*, root, and *morphe*,
form, pronounced RY-zo-morf) owns commissioning and operation. Its kernel
records the identities at that boundary.

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
  construction, ticket construction, registry insertion and record sealing
  use this rule (`proposal.rs:138-148`, `intent.rs:63`, `oversight.rs:189-204`,
  `registry.rs:147-159`, `ledger/mod.rs:635-638`).
- `Proposal` gains `asset_revision: Option<AssetRevision>`. Its private
  `ProposalWire` keeps the kebab-case keys and rejects unknown fields. A
  missing or null `asset-revision` means `None`. The writer omits `None`,
  preserving canonical V1 bytes and decode of escaped spellings
  (`proposal.rs:93-96`, `tests/proposal_text.rs:77-83,115-119`).
  Derive `Deserialize` with `#[serde(try_from = "ProposalWire")]`. The
  conversion checks the fit, so `serde_json::from_str::<Proposal>` refuses
  a revisionless repair. `Proposal::decode` parses the wire struct after its
  size check and calls the same conversion, preserving the typed fit error
  as a new `ProposalError` variant (`proposal.rs:69-70,138-148,194-206`).
- `IntentSpec` gains the same field (`intent.rs:27`). `Proposal::spec()`
  copies it into the spec and `Proposal::from_spec()` copies it back
  (`proposal.rs:153-163,118-129`). `Proposal::intent()` calls
  `ActionIntent::new(self.spec())` (`proposal.rs:171-173`). The constructor
  (`intent.rs:63`) checks the fit and returns
  `IntentError::AssetRevisionMismatch` on failure. `IntentError` becomes
  `#[non_exhaustive]` (`intent.rs:11`).
  `ActionIntent::asset_revision()` exposes the validated value.
- `ApprovalTicket::new` takes an additional `Option<AssetRevision>` and
  returns `Result<Self, OversightError>` (`oversight.rs:189-204`). It refuses
  a repair without a revision and a non-repair with one, both with
  `OversightError::AssetRevisionMismatch`. The revision stays private and
  `asset_revision()` reads it (`oversight.rs:177-184`). The engine passes the
  intent's revision into construction and copies the intent or ticket value
  into action records (`engine.rs:682-694,797-801,870-874`).
- `PendingRegistry::insert` independently checks the fit before insertion.
  Either mismatch returns `RegistryError::AssetRevisionMismatch`, even for a
  ticket built another way (`registry.rs:43-59,147-160`). On success, insert
  assigns every held ticket a `HoldId`, a `u64` serial from a per-registry
  counter. A checked increment that would overflow refuses the insert with
  `RegistryError::HoldIdExhausted`. The counter never wraps or resets on
  reclamation (`registry.rs:72-89,129-160`).
- Insert returns the assigned `HoldId` and stores it with the pending ticket.
  `DecisionEngine::decide` returns `InterceptorOutcome::RequireApproval`
  carrying that ID alongside the ticket and its request ID
  (`engine.rs:572,661-666,682-694`, `outcome.rs:127-128`,
  `oversight.rs:219-223`). Reopening an expired request for the same asset
  and revision gets a new `HoldId` (`registry.rs:13-29`).
- Rust exports `DecisionEngine` (`engine.rs:191`, `lib.rs:188`).
  `DecisionEngine::adjudicate` keeps the request-ID vote for non-repairs.
  On a held repair it returns `OversightError::ReviewedRevisionRequired`
  through `DecisionError::Oversight` (`engine.rs:733-738,755-760`,
  `error.rs:30-32`).
- `DecisionEngine::adjudicate_repair` takes the request ID, `HoldId`, panel,
  vote and reviewed `AssetRevision`. It looks up the live repair by request
  ID and checks the hold ID first. A late vote for the expired hold returns
  `OversightError::StaleVote`, even if both asset and revision still match.
  A wrong hold ID or either wrong reviewed number leaves the live hold
  pending and seals no vote. A match proceeds through the deadline, panel
  and recording checks (`engine.rs:755-760,788-801`).
- Go's `Engine.AdjudicateRepair` and Wasm's `amussis_adjudicate_repair`
  carry the hold ID and both reviewed numbers alongside the existing vote
  fields (`bindings/go/decision/decision.go:187-199,325,581-590`,
  `crates/amussis-decision-wasm/src/abi.rs:222-229`). The Wasm binding's
  `Engine` is an alias for the Rust receiver (`binding.rs:17-19`). Today its
  held outcome code discards the ticket (`binding.rs:167-172`). In v7 a
  held result also writes the request ID and full `HoldId` to the shared
  buffer. Go returns both in the held `Outcome` (`abi.rs:114-126,215-220`,
  `bindings/go/decision/outcome.go:102-110`).
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
  The framed intent and agent must both be nonempty UTF-8 and pass
  `IntentId::parse` and `AgentId::parse`, respectively
  (`ledger/mod.rs:341-348`, `identity.rs:72-77,132-134,165-169`). Today the
  reader skips both fields (`ledger/anchor.rs:178-183`). A subjectless record
  writes two empty fields (`ledger/mod.rs:676-690`).
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
New variants break exhaustive matches on `ActionType`, `IntentError`,
`OversightError` and `RegistryError` (`risk.rs:43`, `intent.rs:11`,
`oversight.rs:18`, `registry.rs:43`). Mark the intent and oversight errors
`#[non_exhaustive]`. Ticket construction gains a parameter, becomes fallible
and ceases to be a `const fn` (`oversight.rs:189-204`). Registry insertion
returns a hold ID and the held outcome gains that ID (`registry.rs:147-160`,
`outcome.rs:127-128`). Ship with a `!` subject and a `Migration:` footer.
Mark `ActionType` and `RecordSubject` `#[non_exhaustive]` and add
`RecordSubject::new` so later additions are append-only.

Ship the ninth Wasm function export with the Go loader. Raise the module's
`ABI_VERSION` and Go's `abiVersion` from 6 to 7
(`crates/amussis-decision-wasm/src/lib.rs:177`,
`bindings/go/decision/surface.go:15`). Add `amussis_adjudicate_repair`
with signature `(i32) -> i32` to `moduleExports` (`surface.go:38-49`).
Rebuild `bindings/go/decision/amussis_decision.wasm` for v7. The package
embeds those bytes, loads them, checks the exact export table and checks the
reported version (`decision.go:65-66,374,432-437,477-484`,
`surface.go:101-114`). A v7 loader refuses a v6 module and a v6 loader
refuses a v7 module.

**D5. Model revisions are out of scope.** The exhaustive action set has no
Tornus design-release action (`risk.rs:43-54`). Revisit the upstream
`ModelRevision` alias when a proposal approves a design-model change.

**D6. Sequencing and tests.** The Rhizomorph type landed first. amussis then
implements D1 to D4 with these tests:

- Boundary: revision 1 and `u32::MAX` accepted, 0 refused (D1 constructor
  and serde decode).
- Give both `Proposal::decode` and `serde_json::from_str::<Proposal>` a
  revisionless repair and a non-repair with a revision. Both refuse each
  input (`proposal.rs:93-96,138-148`). Sealing refuses both record shapes
  (`ledger/mod.rs:635-638`).
- Retain an existing non-repair fixture's pre-image digest and continue its
  chain with `ChainAnchor` (`tests/chain_continuation.rs:329-343`).
  Through the bundled v7 module, Go's `Continue` opens a chain head written
  before tag 6 and appends the next linked record
  (`bindings/go/decision/continue_test.go:184-198`).
- At `ApprovalTicket::new` and independently at `PendingRegistry::insert`,
  refuse a repair with no revision and `FileDeletion` with one. Supply the
  malformed tickets directly to the insertion tests. At serial exhaustion
  assert the named error and no insertion (`oversight.rs:189-204`,
  `registry.rs:147-160`).
- Extend `tests/registry_lifecycle.rs:38-64,70-88`. Refuse a plain vote on
  a repair. Decide a hold at revision 3, reopen its request at revision 4
  and refuse the delayed revision-3 vote. Separately, expire a hold and
  reopen the same request ID for the same asset and
  revision. Assert distinct hold IDs. Voting with the expired ID must
  return `StaleVote`, leave the new hold pending and append no record. With
  the live ID, refuse a wrong asset or revision independently, then accept
  the matching vote (`engine.rs:755-760,792-801`).
- Anchor tests extend `tests/chain_continuation.rs:511-513,528-532`. Accept a
  tag-6 head with both words. Give each malformed head its own digest. Test
  each refusal separately for a missing word, an extra byte, revision zero,
  asset above `u32::MAX`, revision above `u32::MAX`, status `HaltEngaged`,
  status `HaltReleased`, and a trailing byte on a legacy action. Refuse an
  `Approved` tag-6 head with valid words, its own digest and empty intent
  and agent. Also refuse each malformed identifier with the other valid
  (`ledger/anchor.rs:178-183`, `identity.rs:72-77`).

## Consequences

- **Positive**: An audit reader can recover the asset number and revision
  from the same pre-image that determines the digest (`ledger/mod.rs:661-663`).
- **Positive**: Existing heads still continue (`ledger/anchor.rs:168-188`).
  Existing V1 texts still decode and their canonical forms keep their bytes
  (`tests/proposal_text.rs:77-83,115-119`). Omitting an absent revision
  preserves existing JSONL output (`ledger/jsonl.rs:142-145`).
- **Positive**: Only a vote naming the live hold and its reviewed asset and
  revision can decide a repair after request ID reuse
  (`engine.rs:755-760,792-801`, `registry.rs:13-29`).
- **Negative**: Plain adjudication for non-repairs still votes by request ID.
  A delayed vote can decide a reopened request. Track that existing reuse
  window in a follow-up issue outside this ADR (`engine.rs:733-738,755-760`,
  `registry.rs:13-29`).
- **Positive**: A shape rule in `is_well_formed()` makes a planted or
  stripped revision a `PreimageError::Shape` failure, not a silent mismatch.
- **Positive**: With `#[non_exhaustive]` on `ActionType` and `RecordSubject`,
  later additions pass `cargo-semver-checks` and HISS-14 as append-only.
- **Negative**: Rust callers must migrate struct literals for `RecordSubject`,
  `Proposal`, `IntentSpec` and the public JSONL projection `LedgerLine`
  (`ledger/jsonl.rs:20-52`). D4 also requires callers to update exhaustive
  matches on the action and errors, held outcomes, constructor calls and
  registry insertions.
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
  one? The host would need to query it. The engine stores configuration,
  halt state, pending tickets, ledger and clock state. It holds no plant
  state (`engine.rs:191-208`), and the Wasm host effects are clock, signer
  and sink (`docs/index.md:30-31`).
- Is Tier A the right floor, or should the class come from the plant's own
  hazard rating?
