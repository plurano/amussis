# Amussis

<!-- praetor:readme-governance:start -->
[![HISS Adopted][praetor-hiss-badge]][praetor-hiss-agents]

Praetor manages this repository's declared governance policy. This managed
block records adoption state; it is not a verification certificate.

**Verification**: `make verify-all` runs the repository's configured
verification cascade.

**HISS Audit**: `praetorctl audit` enforces policy, generated-surface
integrity, and the debt ratchet.

**Context Sync**: `praetorctl compile-context --verify` verifies every
generated agent context against `AGENTS.md`.

**Debt Baseline**: `.standards-baseline.json` anchors the debt ratchet at
0 recorded infractions; audit forbids growth.

[praetor-hiss-badge]: https://img.shields.io/badge/Standards-HISS%20Adopted-blue
[praetor-hiss-agents]: https://github.com/plurano/amussis/blob/HEAD/AGENTS.md
<!-- praetor:readme-governance:end -->

Shared Rust crates of the Plurano framework family, kept in one workspace.

## Name

Latin *amussis*, the mason's levelling board; *ad amussim* means "exactly".
Pronounced ah-MOOS-sis.

A crate is named after what it does, with the family name in front:
`amussis-decision` is the decision engine. The deity names (Justitia, Minerva,
Vesta) stay the operating system's names for its components.

## Status

Private while the workspace is set up; nothing is released yet. The first crate
is a decision engine (risk levels, second-person approval, tamper-evident log,
kill switch) that moves here from the operating-system repository.

## Layout

| Path | Holds |
| :--- | :--- |
| `crates/` | One directory per library crate; each joins the workspace by a written-out line in `Cargo.toml`. |
| `crates/amussis-decision/` | The decision engine, imported with its history from the operating-system repository, where it is the crate `aegis-justitia`. |
| `crates/amussis-decision-wasm/` | The decision engine as a WebAssembly module: five exports, three host functions (clock, signer, sink). |
| `bindings/go/` | The Go module that embeds the WebAssembly module and runs it without cgo; package `decision`. |
| `exceptions.toml`, `tools/exceptions_check.py` | The workspace's exceptions to its own rules, each with one rule, one file, a reason and an end date, and the check that holds every entry to what it names. |
| `tools/wasm_module.py` | Builds the WebAssembly module and compares it byte for byte with the one `bindings/go` embeds. |
| `tools/settings_sync.py` | Holds the shared toolchain and lint settings to their recorded source. |
| `tools/apicompat/`, `.github/workflows/praetor-api.yml` | Written by the Praetor engine: on a pull request, compares the exported API of the Go module with the base commit. |
| `settings-source.json` | The record: source repository, commit, file hashes and manifest settings. |
| `LICENSES/`, `REUSE.toml` | Licence text and the annotations for files that cannot carry a header. |
| `.standards.yaml`, `.standards.lock`, `.standards-baseline.json` | The Praetor adoption: profile, pinned policy and the recorded debt the audit lets shrink, never grow. |

## Verification gate

```sh
make verify-all
```

One target, the same one CI runs. Its first half, `make verify`, needs no
engine: it checks the shared settings and the exception list, then formats,
builds, tests (default and all features), lints with warnings refused and
builds the documentation on the toolchain `rust-toolchain.toml` pins. It then
lints the export crate for `wasm32-unknown-unknown`, builds the WebAssembly
module and compares it with the committed one, formats, vets and tests the Go
binding, and checks the licence headers with `reuse lint`. Its second half is
the Praetor standards audit, which needs `praetorctl`; CI builds it from the
commit pinned in the workflow.

The gate needs the `wasm32-unknown-unknown` target of the pinned toolchain
(`rustup target add wasm32-unknown-unknown`) and Go at the version
`bindings/go/go.mod` names. It installs neither, and fails when one is missing.

`make fetch` is the only step that reaches a third-party host: `cargo fetch
--locked` reads the crates.io registry and `go mod download` the Go module
proxy. Everything after it runs with `--offline` or `GOPROXY=off`. Builds
follow `CARGO_BUILD_JOBS`; set it when other work shares the machine.

## Go binding

```go
import "github.com/plurano/amussis/bindings/go/decision"

engine, err := decision.New(ctx, decision.Config{
    KeyID:        "host-key-01",
    SinkDeadline: 250 * time.Millisecond,
    Mode:         decision.Compiled,
    Clock:        clock, Signer: signer, Sink: sink,
})
outcome, err := engine.Decide(ctx, proposalJSON)
if !outcome.Permits() { /* the action does not run */ }
```

The package embeds the WebAssembly module and runs it in the process with
[wazero](https://github.com/tetratelabs/wazero): no cgo, no shared library and
no Rust toolchain for the consumer. The module has no access to the operating
system. It asks the host for three effects and nothing else, and the loader
refuses a module that imports anything beyond them:

| Effect | The host supplies | When it cannot deliver |
| :--- | :--- | :--- |
| `Clock` | Seconds since the Unix epoch. | The decision is blocked and the engine halts. |
| `Signer` | A signature over the SHA-256 digest of each record. | Blocked and halted; nothing unsigned reaches the sink. |
| `Sink` | Durable storage of each signed record, within a deadline. | Blocked and halted; the engine keeps no record the sink does not hold. |

No effect has a default. `New` refuses a missing one, and a module that imports
a host function the host does not hold fails to load. `Mode` is named by the
caller as well: `Compiled` (amd64 and arm64) or `Interpreted` (every platform
Go runs on, about ninety times slower per decision on amd64); the package never
picks one or falls back to the other. A module that traps, or an answer the
loader cannot read, yields a blocked outcome and an error, and the engine
answers blocked from then on.

The audit chain lives in the `Sink` and has no bound of its own: the module
keeps a window of 4,096 records in memory and drops it when it is full
(`TestTheChainRunsPastTheWindowAsOneChain`). A program that starts again does
not start a second chain. It hands the last record its sink stored to
`decision.Continue`, and the next record links onto it:

```go
engine, err := decision.Continue(ctx, config, decision.Continuation{Head: lastStored})
```

The module recomputes the digest of that record and reads the chain position
and the halt state out of its content; a record that does not hash to its
digest is refused with `decision.ErrHead`. A chain that ends halted continues
halted, so a restart is no release.

A halt is a record of the chain and stands at a risk level: the level of the
action the engine had in hand when a fault halted it, and the highest level
where no action names one. `Continuation.Release` is the one release of a halt
the binding has. It names the person who releases and the checkers, and the
engine holds it to the approval rule it holds an action of that level to:

```go
from := decision.Continuation{
	Head:    lastStored,
	Release: &decision.Release{Releaser: "olga", Checkers: []string{"petra"}},
}
engine, err := decision.Continue(ctx, config, from)
```

| Level of the halt | Who releases it |
| :--- | :--- |
| Routine or material action, standard oversight | The releaser alone. |
| Consequential action, standard oversight | The releaser and one checker. |
| Any action under Annex III oversight, and a halt with no level of an action | The releaser and two distinct checkers. |

No checker is the releaser. The release is written into the chain as a record
of its own before the first decision, and a release that is refused writes
nothing and sets up no engine:

| Error | The release is refused because |
| :--- | :--- |
| `decision.ErrApproval` | a checker the level demands is missing, named twice, or is the releaser |
| `decision.ErrNotHalted` | the chain does not end halted |
| `decision.ErrCompromised` | the chain is halted as compromised; that halt is not released |
| `decision.ErrRelease` | a person is no identity of the engine, or more than two checkers are named |
| `decision.ErrReleaseFailed` | the clock, the signer or the sink did not deliver the release record |

The cases are replayed both ways in `bindings/go/decision/continue_test.go`
(`TestTheLowestLevelIsReleasedByOnePerson`,
`TestAReleaseWithoutTheNeededApprovalIsRefused`).

An action the engine holds (`RequireApproval`) is named by the `id` of its
proposal. The program brings the checkers' decision to the engine with
`Adjudicate`:

```go
outcome, err := engine.Adjudicate(ctx, decision.Adjudication{
	IntentID: "intent-0042",
	Vote:     decision.Approve,
	Checkers: []string{"carol"},
})
if outcome.Permits() { /* approved: the held action runs */ }
```

Who may approve is the program's decision. The engine holds the checkers it is
given to the approval rule of the action (one checker, or two distinct ones
under Annex III oversight, none of them the maker of the proposal) and writes
the vote into the chain. Only an approval permits:

| Outcome class | Meaning | Record of the vote |
| :--- | :--- | :--- |
| `Allowed` | The checkers approved; the held action may run. | the approval |
| `Rejected` | The checkers rejected the action. | the rejection |
| `NotAdjudicated` | The engine took no vote; `Detail` says why. | none |
| `Refused` | The adjudication cannot be read (`RefusedAdjudication`). | none |

| `Detail` of `NotAdjudicated` | The engine took no vote because |
| :--- | :--- |
| `UnadjudicatedUnknownRequest` | no action is held under the intent id |
| `UnadjudicatedAlreadyDecided` | the action was decided before |
| `UnadjudicatedExpired` | its approval window of 300 seconds has closed |
| `UnadjudicatedApproval` | the checkers do not satisfy the approval rule |
| `UnadjudicatedHalted` | the engine is halted |
| `UnadjudicatedClockUnavailable` | the clock could not be read; the engine halts |
| `UnadjudicatedUnrecorded` | the vote could not be signed or stored; the hold ends undecided and the engine halts |
| `UnadjudicatedEngine` | the engine refused for a reason this list does not name |

`Halt` is the operator stop. It names the risk level the halt stands at, which
is the level its release is held to:

```go
err := engine.Halt(ctx, decision.LevelConsequential)
```

The engine permits nothing after `Halt`, whatever it returns. `nil` says the
halt is a record of the chain; `decision.ErrHaltUnrecorded` says the engine is
halted and the record could not be signed or stored. A `Level` that is none of
the six, the zero value included, halts at the highest level, and a second
halt never lowers the level a halt stands at
(`TestAHaltAtNoLevelStandsAtTheHighest`, `TestASecondHaltNeverLowersTheLevel`).

The cases that must not permit are replayed in
`bindings/go/decision/adjudicate_test.go`: a vote for an action that is not
held (`TestAnAdjudicationForAnActionThatIsNotHeldIsNotTaken`), a vote that
cannot be signed or stored
(`TestAVoteThatCannotBeSignedOrStoredIsNoVoteAndHalts`) and a halt that cannot
be recorded (`TestAHaltThatCannotBeRecordedIsStillAHalt`). The byte layout of
an adjudication and the outcome code are in the documentation of
`crates/amussis-decision-wasm/src/lib.rs` and `src/wire.rs`.

Limits as of this state:

- Actions an earlier engine held are not carried over a continuation and stay
  unreleased: an adjudication for one finds no held action.
- A running engine has no call that lifts a halt. A halt set with `Halt` is
  released as every halt is, by a continuation of the stored chain with a
  `Release` (`TestAnOperatorHaltIsReleasedWithTheApprovalOfItsLevel`).
- The head record is checked for integrity, not for origin. The module verifies
  no signature, and it cannot know that the record is the last one stored. A
  continuation from another record leaves two records with one sequence number
  in the store, which a walk over the store shows
  (`TestAContinuationFromAnotherRecordThanTheHeadShowsInTheStore`); the module
  does not prevent it.
- No record names a person. The chain shows that a held action was approved
  or rejected and that a halt was released, and the halted records before the
  release show at which level it stood; it does not show which checkers voted,
  who released the halt or who approved the release. A host that has to show
  that keeps it itself.
- A halt whose record never reached the sink (a signer or a sink that failed) is
  not in the stored chain, so a continuation from the stored head starts without
  it. The halted engine writes the halt with the next record the sink stores.
- The binding has run on Linux amd64 only.

The committed module is the build of the source beside it: `tools/wasm_module.py
check` rebuilds it with the machine's paths rewritten and fails on one differing
byte. After a change to the engine or the export crate, run
`python3 tools/wasm_module.py update` and commit the module with the change.

## Exceptions

The workspace forbids `unsafe` code. The export file
`crates/amussis-decision-wasm/src/abi.rs` needs the allowance for linkage alone
(`unsafe extern` for the imports, `#[unsafe(no_mangle)]` for the exports) and
is named in `exceptions.toml` with one file, one rule, a reason and an end date
at most 90 days ahead. `tools/exceptions_check.py` fails on any other file that
lowers the lint, on an entry whose file lowers nothing, and on an entry past its
date: a lapsed exception excuses nothing.

The second entry names `.github/rulesets/main.json`. The Praetor engine writes
that file, and for the licence job, which calls the shared workflow of
`plurano/shared-ci` (`.github/workflows/licence-check.yml`), it requires the
check `Licence`. A run reports that job as `Licence / REUSE lint`, so the
required name is never reported (cordanaLLM/praetor#1212). The same check reads
every workflow's job names and the rule set: a required name that is the bare
name of a calling job needs the live entry, a required name no job carries is
refused with or without it, and the entry is refused once no such name is left.
No rule set is live on the forge while the repository is private; the entry's
reason states what has to hold before that changes.

## Shared settings

The toolchain pin, the formatter and lint configuration and the workspace lint
tables are not written here. They are taken from the operating-system
repository at the commit recorded in `settings-source.json`:

- `rust-toolchain.toml`, `clippy.toml` and `rustfmt.toml` are byte copies, held
  by their SHA-256 hashes.
- `resolver`, `edition`, `rust-version` and the lint tables of `Cargo.toml` are
  compared as parsed values.

They stay in step in two places. The gate runs `tools/settings_sync.py check`,
which needs no network and refuses any local edit of a shared setting. The
weekly *Settings drift* workflow checks out the source repository and runs
`check --source`, which refuses a record that no longer equals the source. A
change therefore starts in the source repository and arrives here with:

```sh
python3 tools/settings_sync.py update --source <checkout of the source repository>
```

`selftest` plants one defect per setting and requires each to be refused; the
gate runs it before the check.

## Dependencies

`Cargo.lock` is committed and every cargo step runs with `--locked`;
`bindings/go/go.sum` is committed and every Go step runs with `-mod=readonly`.
A release of an outside dependency is taken up three days after its publication
at the earliest; releases of this workspace's own crates are taken up at once.

## Licence

EUPL-1.2, see [LICENSE](LICENSE). Source files carry an SPDX header; the gate
fails on a file that has neither a header nor an entry in `REUSE.toml`.
