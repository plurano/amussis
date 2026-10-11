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
| `exceptions.toml`, `tools/exceptions_check.py` | The one file that lowers a workspace lint, with its reason and end date, and the check that holds it to that entry. |
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

Limits as of this state: a held action cannot be approved or rejected through
the binding and an operator cannot halt or release the engine through it; one
engine decides 4,096 proposals and then blocks (the bound of its in-memory
chain); and the binding has run on Linux amd64 only.

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
