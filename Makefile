# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
-include .config/praetor/engine.mk

SHELL := /bin/sh
REUSE ?= reuse
CARGO_DENY ?= cargo deny
CARGO_SEMVER_CHECKS ?= cargo semver-checks
# The public API is compared with the last release: the nearest tag v* that is
# not a release candidate.
SEMVER_BASELINE ?= $(shell git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-*' 2>/dev/null)
GITLEAKS ?= gitleaks
SEMGREP ?= semgrep
TRIVY ?= trivy
export SEMGREP TRIVY

GO_BINDING := bindings/go
GO_CONSUMER := examples/go-consumer
WASM_TARGET := wasm32-unknown-unknown
# The Go steps use the installed Go, change no go.mod and build without cgo.
GO_LOCAL := GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0
# The documentation gate (the Praetor block at the end of this file) installs
# the npm packages its lock file names on every run. npm takes them from the
# cache `make fetch` fills and never from the registry: a package missing there
# fails the gate instead of being downloaded.
NPM_LOCKED := tools/markdownlint
export npm_config_offline := true

.PHONY: verify verify-settings verify-exceptions verify-origin verify-rust verify-package verify-wasm verify-regenerate verify-go
.PHONY: verify-go-lint verify-readme
.PHONY: verify-notices verify-licences verify-reuse verify-secrets verify-signoff fetch
.PHONY: verify-semgrep verify-trivy verify-semver
.PHONY: verify-engine-plants verify-api-plant verify-hook-scripts

# The one gate is `make verify-all`: CI runs exactly that target, so a local
# green run and a green status check mean the same thing. Its recipe, at the
# end of this file, belongs to the engine and runs the standards audit; the
# prerequisites here put this workspace's own checks in front of it, and then
# one planted defect per engine check, so an engine check that stopped
# refusing anything fails before its clean run is trusted.
verify-all: verify verify-engine-plants

# This workspace's own checks; they need no engine.
verify: verify-settings verify-exceptions verify-origin verify-rust verify-package verify-wasm verify-regenerate verify-go \
		verify-go-lint verify-readme verify-notices verify-licences verify-reuse verify-secrets verify-signoff \
		verify-semgrep verify-trivy verify-semver
	@printf '%s\n' 'PASS: settings, exceptions, origin names, crate gate, packed crate, module, Go binding,' \
		'Go linter, README Go blocks, third-party notices, dependency licences, licence headers, secrets,' \
		'sign-off check, semgrep and trivy scanner checks, Rust API against the last release.'

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

# The only step that reaches a third-party host: the crates.io registry, the
# Go module proxy, the npm registry and ghcr.io for the trivy vulnerability
# database. It downloads every platform's locked crates, which the
# dependency-closure tests need because they read `cargo metadata` without a
# platform filter, the Go modules go.sum names, the npm packages of the
# documentation gate's lock file into npm's cache, and the pinned vulnerability
# database for trivy. Everything after it runs with --offline, GOPROXY=off,
# npm's offline mode or trivy's offline scan.
fetch:
	cargo fetch --locked
	cd $(GO_BINDING) && $(GO_LOCAL) go mod download
	cd $(GO_CONSUMER) && $(GO_LOCAL) go mod download
	scratch="$$(mktemp -d)" && cp $(NPM_LOCKED)/package.json $(NPM_LOCKED)/package-lock.json "$$scratch" \
		&& (cd "$$scratch" && npm_config_offline=false npm ci --ignore-scripts --no-audit --no-fund); \
		status=$$?; rm -rf "$$scratch"; exit $$status
	python3 -B tools/scanners.py fetch-db
	test -n "$(SEMVER_BASELINE)" \
		|| { printf '%s\n' 'FAIL: no release tag v* is reachable from HEAD' >&2; exit 1; }
	scratch="$$(mktemp -d)" && git archive --format=tar "$(SEMVER_BASELINE)" | tar -x -C "$$scratch" \
		&& cargo fetch --locked --manifest-path "$$scratch/Cargo.toml"; \
		status=$$?; rm -rf "$$scratch"; exit $$status

# The documentation gate reads the npm cache that fetch fills.
docs-lint: fetch

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

# The regeneration tool holding the committed module and notices to updates
# on renovate branches; the selftest runs on a throwaway repository with
# fake update commands first.
verify-regenerate:
	python3 -B tools/regenerate.py selftest
	python3 -B tools/regenerate.py check

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
# and listed nothing is not counted as a refusal. The tests run on the Go
# release the modules declare as their oldest, so a newer Go in CI does not
# leave that release untested; the selftest plants one mismatch per form.
# The binding runs a second time as linux/386, an architecture wazero does
# not compile for, where a linux/amd64 kernel runs it: Interpreted has to
# pass every test there and New has to refuse Compiled. Other hosts say why
# they skip it.
verify-go: fetch verify-wasm
	go version
	python3 -B tools/go_minimum.py selftest
	python3 -B tools/go_minimum.py check
	cd $(GO_BINDING) && $(call gofmt_clean,.)
	@dir=$$(mktemp -d) && printf 'package planted\n\nfunc  f( ) {}\n' > "$$dir/planted.go" \
		&& out="$$( $(call gofmt_clean,"$$dir") 2>&1 )"; status=$$?; rm -rf "$$dir"; \
		test "$$status" -eq 1 && case "$$out" in *planted.go*) true ;; *) false ;; esac \
		|| { printf 'FAIL: the planted unformatted file was not refused: exit %s: %s\n' \
		"$$status" "$$out" >&2; exit 1; }
	@printf '%s\n' 'PASS: the planted unformatted file is refused.'
	cd $(GO_BINDING) && $(GO_LOCAL) GOPROXY=off go vet ./...
	cd $(GO_BINDING) && $(GO_LOCAL) GOPROXY=off go test -count=1 ./...
	@host="$$(go env GOHOSTOS)/$$(go env GOHOSTARCH)"; if [ "$$host" = linux/amd64 ]; then \
		cd $(GO_BINDING) && $(GO_LOCAL) GOPROXY=off GOARCH=386 go test -count=1 ./... \
		&& printf '%s\n' 'PASS: the binding on linux/386: Interpreted runs, Compiled is refused.'; \
	else printf 'SKIP: the linux/386 run needs a linux/amd64 host; this is %s.\n' "$$host"; fi
	cd $(GO_CONSUMER) && $(call gofmt_clean,.)
	cd $(GO_CONSUMER) && $(GO_LOCAL) GOPROXY=off go vet ./...
	cd $(GO_CONSUMER) && $(GO_LOCAL) GOPROXY=off go test -count=1 ./...

# The Go linter on the binding and its consumer module: golangci-lint checks
# standard linters together with gocyclo and gocognit for the HISS-04 complexity
# caps. The third run is the planted case: a scratch module with a function of
# cyclomatic complexity over 10 and one of cognitive complexity over 15 must be
# refused by gocyclo and gocognit, so a linter run that skipped either check is
# not counted as clean.
verify-go-lint: fetch
	golangci-lint version
	cd $(GO_BINDING) && $(GO_LOCAL) GOPROXY=off golangci-lint run ./...
	cd $(GO_CONSUMER) && $(GO_LOCAL) GOPROXY=off golangci-lint run ./...
	@dir=$$(mktemp -d) && printf 'module planted\n\ngo 1.27\n' > "$$dir/go.mod" \
		&& printf 'package planted\n\nfunc f(x int) int {\n\tif x == 1 { return 1 }\n\tif x == 2 { return 2 }\n\tif x == 3 { return 3 }\n\tif x == 4 { return 4 }\n\tif x == 5 { return 5 }\n\tif x == 6 { return 6 }\n\tif x == 7 { return 7 }\n\tif x == 8 { return 8 }\n\tif x == 9 { return 9 }\n\tif x == 10 { return 10 }\n\tif x == 11 { return 11 }\n\treturn 0\n}\n' > "$$dir/planted.go" \
		&& printf 'package planted\n\nfunc g(a, b, c, d int) int {\n\tif a > 0 {\n\t\tif b > 0 {\n\t\t\tif c > 0 {\n\t\t\t\tif d > 0 {\n\t\t\t\t\treturn 1\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n\tif d > 0 {\n\t\tif c > 0 {\n\t\t\tif b > 0 {\n\t\t\t\tif a > 0 {\n\t\t\t\t\treturn 2\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n\treturn 0\n}\n' > "$$dir/nested.go" \
		&& out="$$(cd "$$dir" && $(GO_LOCAL) GOPROXY=off golangci-lint run --config "$(CURDIR)/.golangci.yml" ./... 2>&1)"; status=$$?; rm -rf "$$dir"; \
		test "$$status" -ne 0 && case "$$out" in *gocyclo*) true ;; *) false ;; esac \
		&& case "$$out" in *gocognit*) true ;; *) false ;; esac \
		|| { printf 'FAIL: the planted complexity defects were not both refused: exit %s: %s\n' \
		"$$status" "$$out" >&2; exit 1; }
	@printf '%s\n' 'PASS: the planted cyclomatic and cognitive defects are refused.'

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

# Semgrep checks the repository against its own HISS invariant rules. The
# selftest plants one finding per rule in a scratch directory first, so a rule
# that stopped refusing anything fails before the tree scan is trusted.
verify-semgrep:
	python3 -B tools/scanners.py selftest semgrep
	python3 -B tools/scanners.py check semgrep

# Trivy scans dependencies offline for known vulnerabilities against the
# database pinned by digest. The selftest plants vulnerable Go and Rust
# manifests in a scratch directory first, so a scanner that stopped reporting
# advisories fails before the tree scan is trusted.
verify-trivy: fetch
	python3 -B tools/scanners.py selftest trivy
	python3 -B tools/scanners.py check trivy

# The public Rust API of the published crates against the last release tag:
# cargo-semver-checks fails on a change the workspace version does not allow,
# so a breaking change waits for the version bump that announces it. fetch has
# put the dependencies of both trees in the cache, so the run stays offline.
# The planted case: a public method made private on a scratch clone has to be
# refused by name.
verify-semver: fetch
	$(CARGO_SEMVER_CHECKS) --version
	CARGO_NET_OFFLINE=true $(CARGO_SEMVER_CHECKS) --workspace --baseline-rev "$(SEMVER_BASELINE)"
	CARGO_NET_OFFLINE=true python3 -B tools/gate_plants.py semver \
		--baseline "$(SEMVER_BASELINE)" --semver-checks "$(CARGO_SEMVER_CHECKS)"

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
# copy, so the tests leave nothing in that checkout. The copy keeps the
# engine's layout: the tests load the agent checkpoint adapter from the
# checkout root, three directories above themselves. CI runs it before the
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
	dir=$$(mktemp -d) && mkdir -p "$$dir/.config/lefthook" "$$dir/.config/agent/hooks" \
		&& cp -R "$(PRAETOR_SRC)/.config/lefthook/scripts" "$$dir/.config/lefthook/scripts" \
		&& cp "$(PRAETOR_SRC)/.config/agent/hooks/checkpoint.py" "$$dir/.config/agent/hooks/" \
		&& (cd "$$dir/.config/lefthook/scripts" && python3 -B -m unittest test_checkpoint); \
		status=$$?; rm -rf "$$dir"; exit $$status

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

# BEGIN praetor documentation gate
.PHONY: docs-lint docs-figures
verify-all: docs-lint docs-figures
docs-lint:
	@node tools/markdownlint/verify.mjs
docs-figures:
	@node tools/figures/build.mjs check
	@node tools/figures/build.mjs sources
# END praetor documentation gate
