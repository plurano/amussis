<!--
SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
SPDX-License-Identifier: EUPL-1.2
-->

# Releases

`v0.1.0` is the first release. The path below was proven first on the
pre-release tag `v0.1.0-rc.1`
([run 38148288612](https://github.com/plurano/amussis/actions/runs/38148288612)),
and `v0.1.0` was set after that run had ended green
([run 38149459081](https://github.com/plurano/amussis/actions/runs/38149459081)).
This page says what the workflow files do.

A version tag, `v` and the version in `Cargo.toml` (`v0.2.0`), starts
`.github/workflows/release.yml`. It builds the release files and stores them
in a draft release on the forge. When a maintainer publishes that draft (not
a pre-release), `.github/workflows/publish.yml` publishes `amussis-decision`
and `amussis-decision-wasm` to crates.io and tags `bindings/go/v<version>`.

| File of a release | What it is |
| :--- | :--- |
| `amussis-decision-<version>.crate` | The library as `cargo package` packs it, compiled once more from the packed sources. |
| `amussis-decision-<version>.wasm` | The module the Go binding embeds, rebuilt from the tag and compared byte for byte (`tools/wasm_module.py check`). |
| `amussis-decision-<version>.wasm.third-party-notices.txt` | The notices that travel with the module: every crate it links and the Rust standard library, each with its licence text. See [Licence](https://github.com/plurano/amussis#licence). |
| `amussis-decision-<version>.cyclonedx.json`, `.spdx.json` | The dependencies of the packed crate, read from its lock file. |
| `checksums.txt` | The SHA-256 of the five files above. |
| `checksums.txt.sigstore.json` | The signature over `checksums.txt`. |

The files are built in `.github/workflows/release-build.yml`, which only the
release workflow calls and which only builds. The signature and the provenance
of every file name that workflow, so a file built anywhere else does not pass.
A tag that names another version than the manifest finds no crate file of its
name, and the run stops before anything is signed.

A tag with a hyphen after the version (`v0.2.0-rc.1`) runs the same path to
prove it. Its files carry the manifest version and its draft is marked as a
pre-release. A person publishes that draft as a pre-release, so the checks
below can be run on it the way a consumer runs them; it stays visible and
marked as a pre-release.

To check a release after downloading its files, name its tag in the signer
identity and the manifest version in the crate file. For release `v0.2.0`:

```sh
sha256sum --check --strict checksums.txt
cosign verify-blob \
  --certificate-identity https://github.com/plurano/amussis/.github/workflows/release-build.yml@refs/tags/v0.2.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
gh attestation verify amussis-decision-0.2.0.crate --repo plurano/amussis \
  --signer-workflow plurano/amussis/.github/workflows/release-build.yml
```

For pre-release `v0.2.0-rc.1` the identity ends in `@refs/tags/v0.2.0-rc.1`,
and the crate file is still `amussis-decision-0.2.0.crate`, because its files
carry the manifest version.

The run does the same before it stores the files (job `Read the release files
back`). It calls the shared read-back of plurano/horistes (`tools/readback.py`,
pinned by commit) on the built files with the parameters in
`.github/release-readback.toml`, without credentials. Each check runs once as
built and once with one expectation changed, which has to be refused. A last
step changes one file and requires the read-back to fail on it.

Limits as of this state:

- `praetorctl audit` measures the declared supply chain (build level 3, signed
  checksums, a dependency inventory) from the release workflow files; it reads
  no published signature. The signatures and attestations of a published release
  are checked by the commands above, not by the gate.
- Package publishing runs only when the draft release is published:
  `publish.yml` publishes `amussis-decision` and `amussis-decision-wasm` to
  crates.io and tags `bindings/go/v<version>` at the release commit. A
  pre-release does not publish to crates.io.
- Publishing to crates.io uses trusted publishing: each crate's settings on
  crates.io trust workflow `publish.yml` in environment `crates-io` of
  plurano/amussis, and the job takes a short-lived token through
  `rust-lang/crates-io-auth-action`. No registry token is stored in the
  repository. A new crate in the workspace needs one first publish with an
  API token before crates.io accepts its trusted-publisher entry.
