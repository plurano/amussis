<!--
SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
SPDX-License-Identifier: EUPL-1.2
-->

# Handover: the conversation schemas and the subsystem graph stay with the operating system

The decision engine was cut from the operating-system repository
(`cordanaLLM/Aegis-OS`, crate `aegis-justitia`). Its folder `src/contracts/`
held two things: rules for encoding any schema, and the three schemas that
operating system speaks, with its subsystem graph. The rules stay in the
library as the module `encoding`. The schemas and the graph are the operating
system's and were removed here before the first release.

The operating-system repository is not changed from here. This note is what its
maintainers need to run their schemas over the released library.

## What was removed

| File in the source crate | Lines | SHA-256 |
| :--- | ---: | :--- |
| `src/contracts/proposal.rs` | 138 | `f1d8e804f87864b743e35eada749ffd561300543922052f569fb3724a4bb96e4` |
| `src/contracts/decision_request.rs` | 199 | `39d8374f426956fdd7abe5a0abd1b2512b907420630dfd8674748e34e5d1d799` |
| `src/contracts/audit.rs` | 192 | `9584bf98138fbe330274db6031908e909745629f47a97076c5e2e4807290ff8e` |
| `src/contracts/graph.rs` | 312 | `bab42ad7ceaebd7ae95283e5c420962e2871e157121673fc48e9378dbbf401dd` |
| `tests/contract_action_proposal.rs` | 355 | `41186fc522d1c81c0688f1d85745f2a6e36f04d0fa6c9c64813dd7ed25cdf753` |
| `tests/contract_audit_record.rs` | 240 | `6d1ac6dad6dccdea7048794fad904510b09be90034238903992e0b51a3dd2098` |
| `tests/contract_decision_request.rs` | 204 | `ca1cad184ad501b0c0717f23ee723849ac92567bc43cff0143f25dbaf36f9fc9` |
| `tests/contract_graph_decisions.rs` | 275 | `21e3b5a7ef5ec1f53536f510fe3d6265dc53d02b207744d1ad042331ee8c82e9` |

The hashes are those of this repository's last commit that carries the files,
`7a13ad4e82dec69e51ac71eb0e7f70594a145810`, under `crates/amussis-decision/`. No copy is kept in
this tree: an uncompiled copy would not be built, linted or tested here.

## What stayed, under another name

| Before | Now | What it holds |
| :--- | :--- | :--- |
| `src/contracts/mod.rs` | `src/encoding/mod.rs` | payload buffer, byte bound, decoder, encoder, refusal type, without the three schemas' names |
| `src/contracts/encoding.rs` | `src/encoding/fields.rs` | hexadecimal byte fields and the signature form |
| `tests/contract_encoding.rs` | `tests/encoding_fields.rs` | the tests of those fields |

The library's own schema, the proposal of `src/proposal.rs`, is built on the
same module. `tests/encoding_payload.rs` tests the module through a schema
declared in the test itself.

## How the removed files differ from the operating system's copies

Compared on 2026-10-11 with `crates/aegis-justitia/` at operating-system commit
`4acc511d9675bb984c4f68aa9b32931e565db35d`. No file is byte-identical. The
differences are of three kinds, and only the third changes behaviour:

1. Every file: the address in the copyright line.
2. The four test files: the crate name in the `use` line.
3. `src/contracts/audit.rs` (5 lines added, 3 removed) and
   `tests/contract_audit_record.rs` (one test added): the audit-record schema
   refuses a record of the halt latch.

The third is needed with the released library and is step 6 below.

## What the operating system does when it switches to the released crate

The steps were carried out on a throwaway crate built from the removed files.
Its 43 tests, the same count as in this repository before the removal, pass
against the library, and a defect planted in step 4 fails four of them.

1. Keep the four schema files and their four tests in its own tree as the
   adapter. Keep its own shared module `contracts/mod.rs`; steps 3 to 5 change
   it.
2. In the four schema files, import the engine's types from the library: the
   `use` lines for `identity`, `ledger`, `outcome`, `risk` and `time` name
   `amussis_decision` instead of `crate`, and `OversightSignature` comes from
   `amussis_decision::encoding::fields`. Nothing else in these files changes.
3. In the shared module, keep `SchemaId` (with its tags and its edges),
   `Correlation` and `ContractError` as they are. The library knows none of the
   three schemas: its `SchemaTag` is declared by the caller, and its
   `ContractError` has the three refusals of the encoding alone
   (`UnknownVersion`, `Malformed`, `PayloadTooLong`). The eight refusals that
   belong to one schema (`Unsigned`, `WindowOutOfRange`,
   `GenesisLinkOutOfPlace`, `MissingGenesisLink`, `RefusalWithoutReason`,
   `ReasonWithoutRefusal`, `ApprovalMismatch`, `NoApprovalRequired`) exist only
   in the adapter's type from now on.
4. In the shared module, drop the payload buffer, the byte bound and the bodies
   of `decode_text` and `encode_into`, and take them from
   `amussis_decision::encoding`. The two functions become wrappers: they pass
   `SchemaTag::new(schema.tag())` and read a refusal of the library back as the
   adapter's own, with the identifier the library read. The library's refusal
   type may gain variants; a refusal the adapter does not know is answered as
   `Malformed`, never as success. The shared module shrinks from 423 to 310
   lines.
5. Drop `contracts/encoding.rs` and its test from the adapter; the library
   holds both. `serde_json` is then a dependency of the adapter's tests only.
6. Take the halt-latch refusal into `audit.rs` and its test into
   `contract_audit_record.rs` (difference 3 above). The library records a halt
   and its release in the audit chain; such a record decides no action, so a
   schema that names an action and an actor in every record cannot carry it.
   `RecordStatus::is_of_latch` tells the two kinds apart.
7. In the four test files, split the one `use` list: schema names come from the
   adapter, engine names from `amussis_decision`.

## What the library no longer exports

The modules `contracts`, `contracts::audit`, `contracts::decision_request`,
`contracts::graph` and `contracts::proposal`, and these names: `SchemaId`,
`ActionProposal`, `ActionProposalVersion`, `DecisionRequest`,
`DecisionRequestVersion`, `MAX_DECISION_WINDOW_SECS`,
`MIN_DECISION_WINDOW_SECS`, `SignedAuditRecord`, `AuditRecordVersion`,
`PLD_EFFECTIVE_AT`, `EdgeId`, `GateDirection`, `DecisionRecord`,
`DecisionState`, `SandboxAdmissionPath`, `MAX_ADMISSION_HOPS`,
`D03_ACTION_GATE`, `D03_ACTION_GATE_DIRECTION`, `D03_ACTION_GATE_TRANSPORT`,
`D04_SANDBOX_GATE` and `contract_edges`.

`Correlation` and `ContractError` are still exported and differ: `Correlation`
is built from a `SchemaTag`, and `ContractError` has three variants.
`decode_text` and `encode_into` are public now.

## Not verified

- The adapter was built against this repository's working tree, not against a
  published crate. Nothing is published yet.
- The documentation links inside the four schema files point at `crate::`
  paths that no longer exist in an adapter. The throwaway crate did not build
  its documentation.
