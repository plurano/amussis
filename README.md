# Amussis

Shared Rust crates of the Plurano framework family, kept in one workspace.

## Name

Latin *amussis*, the mason's levelling board; *ad amussim* means "exactly".
Pronounced ah-MOOS-sis.

## Status

Private while the workspace is set up; nothing is released yet. The first crate
is a decision engine (risk levels, second-person approval, tamper-evident log,
kill switch) that moves here from the operating-system repository.

## Layout

| Path | Holds |
| :--- | :--- |
| `crates/` | One directory per library crate; each joins the workspace by a written-out line in `Cargo.toml`. |
| `crates/aegis-justitia/` | The decision engine, imported with its history. It keeps its original name until the crate naming scheme is decided. |
| `tools/settings_sync.py` | Holds the shared toolchain and lint settings to their recorded source. |
| `settings-source.json` | The record: source repository, commit, file hashes and manifest settings. |
| `LICENSES/`, `REUSE.toml` | Licence text and the annotations for files that cannot carry a header. |

## Verification gate

```sh
make verify
```

One target, the same one CI runs. It checks the shared settings, then formats,
builds, tests (default and all features), lints with warnings refused and
builds the documentation on the toolchain `rust-toolchain.toml` pins, and
finally checks the licence headers with `reuse lint`.

`cargo fetch --locked` is the only step that reaches a third-party host (the
crates.io registry); everything after it runs with `--offline`. Builds follow
`CARGO_BUILD_JOBS`; set it when other work shares the machine.

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

`Cargo.lock` is committed and every cargo step runs with `--locked`. A release
of an outside dependency is taken up three days after its publication at the
earliest; releases of this workspace's own crates are taken up at once.

## Licence

EUPL-1.2, see [LICENSE](LICENSE). Source files carry an SPDX header; the gate
fails on a file that has neither a header nor an entry in `REUSE.toml`.
