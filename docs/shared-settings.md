<!--
SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
SPDX-License-Identifier: EUPL-1.2
-->

# Shared settings

The toolchain pin, the formatter and lint configuration and the workspace lint
tables are not written here. They are taken from the operating-system
repository at the commit recorded in `settings-source.json`:

- `rust-toolchain.toml`, `clippy.toml` and `rustfmt.toml` are byte copies, held
  by their SHA-256 hashes.
- `resolver`, `edition`, `rust-version` and the lint tables of `Cargo.toml` are
  compared as parsed values.

They stay in step in three places:

- The gate runs `tools/settings_sync.py check`, which needs no network and
  refuses any local edit of a shared setting.
- On a pull request that changes one of those files or the record, the Linux
  job of the *Verification gate* workflow clones the source repository and
  runs `check --source`. That check refuses a record that no longer equals
  the source, so such a pull request cannot merge out of step with it.
  `changed --base --head` names the files that decide whether the check runs.
- The weekly *Settings drift* workflow runs the same `check --source`, for
  changes made in the source repository.

A change therefore starts in the source repository and arrives here with:

```sh
python3 tools/settings_sync.py update --source "/path/to/source-checkout"
```

with `/path/to/source-checkout` replaced by the path of a checkout of the
source repository.

`selftest` plants one defect per setting and requires each to be refused. It
also requires `changed` to name a changed setting and nothing else. The gate
runs it before the check.
