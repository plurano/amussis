<!--
SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
SPDX-License-Identifier: EUPL-1.2
-->

# Verification gate

```sh
make verify-all
```

One target, the same one CI runs: three jobs, on Linux, macOS and Windows,
share one step list in `.github/workflows/ci.yml`, and the rule set in
`.github/rulesets/main.json` requires all three. Its first half, `make verify`, needs no
engine: it checks the shared settings and the exception list, then formats,
builds, tests (default and all features), lints with warnings refused and
builds the documentation on the toolchain `rust-toolchain.toml` pins. It then
lints the export crate for `wasm32-unknown-unknown`, builds the WebAssembly
module and compares it with the committed one, formats, vets and tests the Go
binding and the examples in `examples/go-consumer`, checks that every Go block
of the README stands line for line in those examples, holds the third-party notices of the module to the lock file, holds
every locked crate to the licences `deny.toml` allows, checks the licence
headers with `reuse lint` and scans every commit of the clone for credentials
with [gitleaks](https://github.com/gitleaks/gitleaks), which has to find a
token planted at run time. It checks the repository against its own HISS rules
with [semgrep](https://github.com/semgrep/semgrep) (`.config/semgrep/hiss.yml`),
which has to find a planted finding per rule; its hash-locked install
(`tools/semgrep/requirements.txt`, compiled from `requirements.in`) is refused
when one pin breaks the bounds of another. Ruff checks tracked Python against
`ruff.toml` after planted import-order and security findings are detected
(`make verify-ruff`). It scans dependencies offline for
vulnerabilities with [trivy](https://github.com/aquasecurity/trivy), which
requires a database pinned by digest from `make fetch` and has to find planted Go
and Rust advisories. It compares the public API of the published crates with
the last release tag using
[cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks), which
fails on a breaking change the workspace version does not announce and has to
refuse a public method made private on a scratch clone. Its second half is
the Praetor standards audit, which needs `praetorctl`; CI builds it from the
commit pinned in the workflow.

`make verify-message-ids` tests the private plan ID check and checks reachable history; the pull request workflow also checks its title, body and commits without printing matches. The same target refuses an analyser excuse in tracked source that names no rule id or gives no reason of at least three words.

Trivy findings are excused only by a dated `vulnerability` entry in `exceptions.toml`, valid for at most 90 days.

The gate needs the `wasm32-unknown-unknown` target of the pinned toolchain
(`rustup target add wasm32-unknown-unknown`), Go at the version
`bindings/go/go.mod` names, Node.js 22.12 or later with npm, and
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny), cargo-semver-checks,
gitleaks, semgrep, ruff and trivy at the versions `.github/workflows/ci.yml` pins. It installs none of them,
and fails when one is missing.
The semgrep version pinned in `tools/semgrep/requirements.txt` has wheels for
Linux x86_64/aarch64, macOS arm64 and Windows x86_64. On Intel macOS, pip installs
a source archive without `semgrep-core`, so `make verify-semgrep` fails there.
Intel macOS is not a supported gate host; run the gate on a Linux host (container
or VM).

`make fetch` is the only step that reaches a third-party host: `cargo fetch
--locked` reads the crates.io registry for this tree and for the last release
tag, `go mod download` the Go module proxy,
a locked `npm ci` the npm registry for the packages of the documentation
gate, and `tools/scanners.py fetch-db` downloads the vulnerability database from
`ghcr.io` for trivy. Everything after it runs with `--offline`, `GOPROXY=off`,
npm's offline mode or trivy's offline scan. Builds
follow `CARGO_BUILD_JOBS`; set it when other work shares the machine.
