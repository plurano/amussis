# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
-include .config/praetor/engine.mk

SHELL := /bin/sh
REUSE ?= reuse

GO_BINDING := bindings/go
WASM_TARGET := wasm32-unknown-unknown
# The Go steps use the installed Go, change no go.mod and build without cgo.
GO_LOCAL := GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0

.PHONY: verify verify-settings verify-exceptions verify-rust verify-wasm verify-go verify-reuse fetch

# The one gate is `make verify-all`: CI runs exactly that target, so a local
# green run and a green status check mean the same thing. Its recipe, at the
# end of this file, belongs to the engine and runs the standards audit; the
# prerequisite here puts this workspace's own checks in front of it.
verify-all: verify

# This workspace's own checks; they need no engine.
verify: verify-settings verify-exceptions verify-rust verify-wasm verify-go verify-reuse
	@printf '%s\n' 'PASS: settings, exceptions, crate gate, module, Go binding and licence headers.'

# The shared toolchain and lint settings equal the record in
# settings-source.json; the selftest plants one defect per setting first, so a
# check that stopped refusing anything fails here instead of passing quietly.
verify-settings:
	python3 -B tools/settings_sync.py selftest
	python3 -B tools/settings_sync.py check

# The file that lowers a workspace lint is named in exceptions.toml with its
# reason and the date the allowance ends; an expired entry excuses nothing.
verify-exceptions:
	python3 -B tools/exceptions_check.py selftest
	python3 -B tools/exceptions_check.py check

# The only step that reaches a third-party host: the crates.io registry and
# the Go module proxy. It downloads every platform's locked crates, which the
# dependency-closure tests need because they read `cargo metadata` without a
# platform filter, and the Go modules go.sum names. Everything after it runs
# with --offline or GOPROXY=off.
fetch:
	cargo fetch --locked
	cd $(GO_BINDING) && $(GO_LOCAL) go mod download

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

# The WebAssembly module: the export crate is linted for the target it is
# built for (the host run above never compiles its export file), then the
# module is built and compared byte for byte with the one the Go binding
# embeds. The target must be installed; this step fetches nothing.
verify-wasm: fetch
	cargo clippy --locked --offline -p amussis-decision-wasm --target $(WASM_TARGET) -- -D warnings
	python3 -B tools/wasm_module.py selftest
	python3 -B tools/wasm_module.py check

# The Go binding, on the module verify-wasm has just held to the source.
# gofmt exits 0 when it lists files, so its output is the test; -count=1
# keeps a cached result from standing in for a run.
verify-go: fetch verify-wasm
	go version
	cd $(GO_BINDING) && unformatted="$$(gofmt -l .)" && test -z "$$unformatted" \
		|| { printf 'FAIL: gofmt: %s\n' "$$unformatted" >&2; exit 1; }
	cd $(GO_BINDING) && $(GO_LOCAL) GOPROXY=off go vet ./...
	cd $(GO_BINDING) && $(GO_LOCAL) GOPROXY=off go test -count=1 ./...

# Every file carries its licence header or is named in REUSE.toml.
verify-reuse:
	$(REUSE) lint

# Praetor declared verification; existing project recipes remain unchanged.
# Praetor ships one binary under two names; resolve whichever is installed.
PRAETORCTL ?= $(shell command -v praetorctl 2>/dev/null || command -v standardsctl 2>/dev/null || echo praetorctl)
.PHONY: verify-all
verify-all:
	@$(PRAETORCTL) compile-context --verify
	@$(PRAETORCTL) caveman check --configured-sources
	@$(PRAETORCTL) audit
	@exec 'cargo' 'build' '--locked'
	@exec 'cargo' 'test' '--locked'

compile-context:
	@$(PRAETORCTL) compile-context

audit:
	@$(PRAETORCTL) audit
