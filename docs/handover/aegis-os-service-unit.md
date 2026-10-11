<!--
SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
SPDX-License-Identifier: EUPL-1.2
-->

# Handover: the service-unit contract stays with the operating system

The decision engine was cut from the operating-system repository
(`cordanaLLM/Aegis-OS`, crate `aegis-justitia`). Three of its files describe how
that system runs the engine as a hardened systemd service. They are not part of
the library and were removed here before the first release.

## What was removed

| File in the source crate | Lines | SHA-256 |
| :--- | ---: | :--- |
| `contracts/justitia-interceptor.service` | 61 | `cba1b3fb150d72e9068f7117b1c1e2cda8cd10b92e598c596e821f05d00990bf` |
| `src/contracts/unit.rs` | 140 | `d09fad9fa1436acb39e2286ba4d7e941233d7f8546128032122e403b73cbbb29` |
| `tests/contract_unit.rs` | 198 | `0b6aea3525b391caf7429aa5abe2e6becbcff7af373da2c0d6fc5663c150b493` |

The operating-system repository holds all three with exactly these bytes under
`crates/aegis-justitia/` at commit `4acc511d9675bb984c4f68aa9b32931e565db35d`
(compared on 2026-10-11). No copy is kept in this tree: an uncompiled copy would
not be built, linted or tested here. The last commit of this repository that
carries them is `6514aa4b5b6d6e7fbcba625e3d71216f60bcd65d`.

## What the operating system does when it switches to the released crate

1. Keep the three files in its own tree as the service adapter.
2. `unit.rs` needs nothing from the engine (its only dependency is
   `thiserror`), so it compiles as a module of the adapter crate unchanged.
3. `contract_unit.rs` imports eight names from the engine crate
   (`CONTRACT_MARKER`, `INSTALL_DIRECTORIES`, `MAX_UNIT_BYTES`,
   `MAX_UNIT_LINES`, `REQUIRED_DIRECTIVES`, `UnitContractError`,
   `is_installed_path`, `review`). Point that one `use` line at the adapter.
4. The library no longer exports those eight names or the module
   `contracts::unit`.

## Open finding that moves with the unit

The unit text declares `Restart=always` with `StartLimitIntervalSec=0`
(line 32), which restarts a failing service without a rate limit. This
repository recorded it as its one baselined finding; it leaves the baseline here
and stays open in the operating-system repository.
