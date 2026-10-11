# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
# SPDX-License-Identifier: EUPL-1.2

SHELL := /bin/sh
REUSE ?= reuse

.PHONY: verify verify-settings verify-rust verify-reuse fetch

# The one gate: CI runs exactly this target, so a local green run and a green
# status check mean the same thing.
verify: verify-settings verify-rust verify-reuse
	@printf '%s\n' 'PASS: settings, crate gate and licence headers.'

# The shared toolchain and lint settings equal the record in
# settings-source.json; the selftest plants one defect per setting first, so a
# check that stopped refusing anything fails here instead of passing quietly.
verify-settings:
	python3 -B tools/settings_sync.py selftest
	python3 -B tools/settings_sync.py check

# The only step that reaches the crates.io registry; it downloads every
# platform's locked packages, which the dependency-closure tests need because
# they read `cargo metadata` without a platform filter. Everything after it
# runs with --offline.
fetch:
	cargo fetch --locked

# The crate gate on the toolchain rust-toolchain.toml pins. The toolchain is
# printed first so the log names the rustc that actually ran.
verify-rust: fetch
	rustup show active-toolchain
	rustup which rustc
	cargo fmt --check
	cargo build --locked --offline
	cargo test --locked --offline
	cargo test --locked --offline --all-features
	cargo clippy --locked --offline --all-targets --all-features -- -D warnings
	RUSTDOCFLAGS='-D warnings' cargo doc --locked --offline --no-deps

# Every file carries its licence header or is named in REUSE.toml.
verify-reuse:
	$(REUSE) lint
