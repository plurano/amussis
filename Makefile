# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
-include .config/praetor/engine.mk

SHELL := /bin/sh
REUSE ?= reuse
CARGO_DENY ?= cargo deny
GITLEAKS ?= gitleaks

GO_BINDING := bindings/go
GO_CONSUMER := examples/go-consumer
WASM_TARGET := wasm32-unknown-unknown
# The Go steps use the installed Go, change no go.mod and build without cgo.
GO_LOCAL := GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0

.PHONY: verify verify-settings verify-exceptions verify-origin verify-rust verify-package verify-wasm verify-go
.PHONY: verify-readme
.PHONY: verify-notices verify-licences verify-reuse verify-secrets verify-signoff fetch
.PHONY: verify-engine-plants verify-api-plant verify-hook-scripts

# The one gate is `make verify-all`: CI runs exactly that target, so a local
# green run and a green status check mean the same thing. Its recipe, at the
# end of this file, belongs to the engine and runs the standards audit; the
# prerequisites here put this workspace's own checks in front of it, and then
# one planted defect per engine check, so an engine check that stopped
# refusing anything fails before its clean run is trusted.
verify-all: verify verify-engine-plants

# This workspace's own checks; they need no engine.
verify: verify-settings verify-exceptions verify-origin verify-rust verify-package verify-wasm verify-go \
		verify-readme verify-notices verify-licences verify-reuse verify-secrets verify-signoff
	@printf '%s\n' 'PASS: settings, exceptions, origin names, crate gate, packed crate, module, Go binding,' \
		'README Go blocks, third-party notices, dependency licences, licence headers, secrets and sign-off check.'

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

# The names of the system this library was cut from (its component numbers and
# its `aegis.` schema tags) stand in the sources only where the crate says where
# it came from. That system's adapter holds its schemas; a name that comes back
# here fails.
verify-origin:
	python3 -B tools/origin_names.py selftest
	python3 -B tools/origin_names.py check

# The only step that reaches a third-party host: the crates.io registry and
# the Go module proxy. It downloads every platform's locked crates, which the
# dependency-closure tests need because they read `cargo metadata` without a
# platform filter, and the Go modules go.sum names. Everything after it runs
# with --offline or GOPROXY=off.
fetch:
	cargo fetch --locked
	cd $(GO_BINDING) && $(GO_LOCAL) go mod download
	cd $(GO_CONSUMER) && $(GO_LOCAL) go mod download

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

# The library crate as the release packs it: cargo package compiles the packed
# sources on their own, so a source that reads a file outside the crate or a
# module the manifest leaves out fails here and not first on a tag. The
# selftest plants one of each on a copy of the committed tree first.
verify-package: fetch
	python3 -B tools/package_check.py selftest
	python3 -B tools/package_check.py check

# The WebAssembly module: the export crate is linted for the target it is
# built for (the host run above never compiles its export file), then the
# module is built and compared byte for byte with the one the Go binding
# embeds. The target must be installed; this step fetches nothing.
verify-wasm: fetch
	cargo clippy --locked --offline -p amussis-decision-wasm --target $(WASM_TARGET) -- -D warnings
	python3 -B tools/wasm_module.py selftest
	python3 -B tools/wasm_module.py check

# gofmt exits 0 when it lists files, so its output is the test. One
# definition serves the binding and the planted case below.
gofmt_clean = unformatted="$$(gofmt -l $(1))" && test -z "$$unformatted" \
	|| { printf 'FAIL: gofmt: %s\n' "$$unformatted" >&2; exit 1; }

# The Go binding, on the module verify-wasm has just held to the source, and
# the examples, a module outside the binding's that requires it as a
# consumer does and runs the README's code.
# -count=1 keeps a cached result from standing in for a run. The second gofmt
# run is the planted case: an unformatted file written at run time into a
# scratch directory has to be refused by name, so a gofmt that could not run
# and listed nothing is not counted as a refusal.
verify-go: fetch verify-wasm
	go version
	cd $(GO_BINDING) && $(call gofmt_clean,.)
	@dir=$$(mktemp -d) && printf 'package planted\n\nfunc  f( ) {}\n' > "$$dir/planted.go" \
		&& out="$$( $(call gofmt_clean,"$$dir") 2>&1 )"; status=$$?; rm -rf "$$dir"; \
		test "$$status" -eq 1 && case "$$out" in *planted.go*) true ;; *) false ;; esac \
		|| { printf 'FAIL: the planted unformatted file was not refused: exit %s: %s\n' \
		"$$status" "$$out" >&2; exit 1; }
	@printf '%s\n' 'PASS: the planted unformatted file is refused.'
	cd $(GO_BINDING) && $(GO_LOCAL) GOPROXY=off go vet ./...
	cd $(GO_BINDING) && $(GO_LOCAL) GOPROXY=off go test -count=1 ./...
	cd $(GO_CONSUMER) && $(call gofmt_clean,.)
	cd $(GO_CONSUMER) && $(GO_LOCAL) GOPROXY=off go vet ./...
	cd $(GO_CONSUMER) && $(GO_LOCAL) GOPROXY=off go test -count=1 ./...

# Every Go block of the README stands line for line in the examples that
# verify-go compiles and runs; the selftest plants one changed block per form
# first.
verify-readme:
	python3 -B tools/readme_snippets.py selftest
	python3 -B tools/readme_snippets.py check

# The compiled module holds code of the crates it links and of the Rust
# standard library. The notices beside it are generated from the lock file;
# a notices file that differs from what the lock file yields fails, and so
# does a linked crate that offers no MIT. No network: the crates are read
# where `fetch` unpacked them.
verify-notices: fetch
	python3 -B tools/third_party_notices.py selftest
	python3 -B tools/third_party_notices.py check

# Every crate of the locked graph, build-time crates included, carries a
# licence deny.toml allows. The second run is the planted case: a crate
# under a licence the list does not name. cargo-deny exits 4 when the licence
# check refuses and with another status when it could not run, so only 4
# counts as a refusal.
verify-licences: fetch
	$(CARGO_DENY) --version
	$(CARGO_DENY) --offline --locked --config $(CURDIR)/deny.toml check licenses
	@status=0; $(CARGO_DENY) --manifest-path tools/notices/refused/Cargo.toml \
		--offline --locked --config $(CURDIR)/deny.toml check licenses \
		>/dev/null 2>&1 || status=$$?; test "$$status" -eq 4 \
		|| { printf 'FAIL: the planted licence was not refused: cargo-deny exited %s, not 4\n' \
		"$$status" >&2; exit 1; }
	@printf '%s\n' 'PASS: the planted licence is refused.'

# Every file carries its licence header or is named in REUSE.toml, and LICENSE
# at the root is the text of the repository's own licence. The engine's audit
# compares the two only while LICENSES/ holds one text; it holds the texts of
# the module's notices too, so the comparison stands here. The last line is
# its planted case: another licence text has to compare as different, and cmp
# exits 1 for a difference and 2 when it could not read a file.
verify-reuse:
	$(REUSE) lint
	cmp LICENSE LICENSES/EUPL-1.2.txt
	@status=0; cmp -s LICENSE LICENSES/MIT.txt || status=$$?; test "$$status" -eq 1 \
		|| { printf 'FAIL: another licence text was not told apart: cmp exited %s, not 1\n' \
		"$$status" >&2; exit 1; }

# No credential stands in any commit the clone holds (HISS-12); CI checks out
# the whole history. The second run is the planted case: a GitHub token written
# at run time into a scratch directory has to be found. The recipe spells the
# token in two parts, so none stands in the tree. The planted run sets its own
# exit status for a finding, 3, so a scan that could not run is not counted as
# a refusal.
verify-secrets:
	$(GITLEAKS) version
	$(GITLEAKS) git --no-banner --redact --timeout 300 .
	@dir=$$(mktemp -d) && printf 'token = "%s_%s"\n' ghp R7k2Qw9Lm4Xz8Vb3Nc6Hd1Fj5Tg0Sy2Pa4Ue \
		> "$$dir/planted.txt" && status=0 && $(GITLEAKS) dir --no-banner --redact \
		--exit-code 3 --log-level error "$$dir" || status=$$?; rm -rf "$$dir"; \
		test "$$status" -eq 3 || { printf 'FAIL: the planted token was not found: gitleaks exited %s, not 3\n' \
		"$$status" >&2; exit 1; }
	@printf '%s\n' 'PASS: the planted token is found.'

# The sign-off check CI runs on a pull request's commits. The selftest builds
# a scratch history and requires an unsigned commit to be refused and a signed
# range to pass.
verify-signoff:
	python3 -B tools/signoff_check.py selftest

# One planted defect per engine check of the recipe below, each on a scratch
# clone of the committed tree: a vendor file that drifted from AGENTS.md, filler
# prose and a recursive Go function each have to be refused by name.
verify-engine-plants:
	python3 -B tools/gate_plants.py engine --praetorctl "$(PRAETORCTL)"

# The API compatibility gate the Go API workflow runs: an exported method
# removed on a scratch clone has to be refused. It builds the gate's checker
# from the Go module proxy, so it stands outside the offline gate and CI runs
# it on Linux.
verify-api-plant:
	python3 -B tools/gate_plants.py api-gate

# The checkpoint hook scripts are the engine's, copied in by adoption, and
# tested where they are written: each has to equal the pinned engine source
# PRAETOR_SRC names, and the engine's own test_checkpoint.py then runs on a
# copy, so the tests leave nothing in that checkout. CI runs it before the
# engine checkout is removed; locally PRAETOR_SRC is a checkout of the commit
# ci.yml pins. The planted case: a script that differs by one line has to
# compare as different, and cmp exits 1 for a difference and 2 when it could
# not read a file.
HOOK_SCRIPTS := checkpoint.py common.py
verify-hook-scripts:
	test -d "$(PRAETOR_SRC)/.config/lefthook/scripts" \
		|| { printf 'FAIL: PRAETOR_SRC names no engine checkout: %s\n' "$(PRAETOR_SRC)" >&2; exit 1; }
	for f in $(HOOK_SCRIPTS); do cmp ".config/lefthook/scripts/$$f" \
		"$(PRAETOR_SRC)/.config/lefthook/scripts/$$f" || exit 1; done
	@dir=$$(mktemp -d) && { cat .config/lefthook/scripts/common.py; echo '# planted'; } \
		> "$$dir/common.py" && status=0 && cmp -s "$$dir/common.py" \
		"$(PRAETOR_SRC)/.config/lefthook/scripts/common.py" || status=$$?; rm -rf "$$dir"; \
		test "$$status" -eq 1 || { printf 'FAIL: the planted script was not told apart: cmp exited %s, not 1\n' \
		"$$status" >&2; exit 1; }
	dir=$$(mktemp -d) && cp -R "$(PRAETOR_SRC)/.config/lefthook/scripts" "$$dir/scripts" \
		&& (cd "$$dir/scripts" && python3 -B -m unittest test_checkpoint); status=$$?; \
		rm -rf "$$dir"; exit $$status

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
