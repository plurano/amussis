#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Plant one defect per gate the engine owns and require each gate to refuse it.

The engine's checks run in `make verify-all` and in the API compatibility
workflow, from files this repository may not change. A clean run shows only
that a check passed, not that it can fail. This tool copies the committed tree
into a scratch clone, plants one defect there and runs the check on the clone:

    engine      praetorctl compile-context --verify refuses a vendor file that
                drifted from AGENTS.md; praetorctl caveman check refuses filler
                prose; praetorctl audit refuses a recursive Go function
                (HISS-01). The unplanted clone has to pass the audit first, so
                a refusal for another reason is not counted.
    api-gate    the API compatibility gate (tools/apicompat/gate/main.go),
                built as the workflow runs it, refuses a removed exported Go
                method under -policy=reject and names it under -policy=auto.
                It builds the pinned checker, which reaches the Go module
                proxy, so CI runs it outside the offline gate.
    semver      cargo-semver-checks refuses a public method of amussis-decision
                made crate-private, compared with the release tag --baseline
                names, under release type minor whatever the tree's version.

The clone holds the committed tree only: uncommitted edits are not planted on.
The audit of a clone runs with CI=true, the engine's switch for a checkout
without installed hooks; a scratch clone has none.

Exit status: 0 every plant refused, 1 a plant passed, 2 the run could not start.
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FORGE_URL = "https://github.com/plurano/amussis.git"
DEADLINE_SECONDS = 600
PLANTED_GO = "bindings/go/decision/planted.go"
RECURSION = "package decision\n\nfunc planted(n int) int { return planted(n - 1) }\n"
FILLER = (
    "# Notes\n\nThe agent should always run the gate before it is going to conclude a"
    " turn, and the agent should then report the result to the operator in a full"
    " sentence with all of the details.\n"
)
API_SOURCE = "bindings/go/decision/decision.go"
API_METHOD = "func (m Mode) String() string {"
API_FINDING = "Mode.String: removed"
GATE_SOURCE = "tools/apicompat/gate/main.go"
SEMVER_SOURCE = "crates/amussis-decision/src/time.rs"
SEMVER_METHOD = "    pub const fn seconds(self) -> u32 {"
SEMVER_FINDINGS = ("inherent_method_missing", "Ttl::seconds")


class PlantError(Exception):
    """The run could not start; distinct from a plant that passed."""


def run(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> tuple[int, str]:
    """Run argv in cwd under the deadline; the exit status and the joined output."""
    try:
        done = subprocess.run(
            argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=DEADLINE_SECONDS
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PlantError(f"{' '.join(argv)}: {error}") from error
    return done.returncode, done.stdout + done.stderr


def must(argv: list[str], cwd: Path) -> str:
    status, output = run(argv, cwd)
    if status != 0:
        raise PlantError(f"{' '.join(argv)} exited {status}: {output.strip()[-400:]}")
    return output


def clone(root: Path, scratch: Path) -> Path:
    """A full copy of the committed tree. A full copy, not one that borrows the
    object store: the API checker reads the repository with a library that
    does not follow borrowed objects. The forge address and a main branch on
    origin let the engine resolve the default branch as in CI."""
    repo = scratch / "repo"
    must(["git", "clone", "--quiet", "--no-local", str(root), str(repo)], scratch)
    must(["git", "checkout", "--quiet", "--detach", must(["git", "rev-parse", "HEAD"], root).strip()], repo)
    must(["git", "remote", "set-url", "origin", FORGE_URL], repo)
    must(["git", "update-ref", "refs/remotes/origin/main", "HEAD"], repo)
    must(["git", "remote", "set-head", "origin", "main"], repo)
    return repo


def refused(name: str, status: int, output: str, *markers: str) -> list[str]:
    """No finding when the run failed and named the planted defect."""
    if status != 0 and all(marker in output for marker in markers):
        return []
    return [f"plant passed: {name}: exit {status}, {markers!r} not reported"]


def engine(root: Path, praetorctl: str) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="gate-plants-") as scratch:
        repo = clone(root, Path(scratch))
        audit_env = dict(os.environ, CI="true")
        status, output = run([praetorctl, "audit", "--offline"], repo, audit_env)
        if status != 0:
            raise PlantError(f"the unplanted clone fails the audit: {output.strip()[-400:]}")
        found = []
        with (repo / "CLAUDE.md").open("a", encoding="utf-8") as vendor:
            vendor.write("\nplanted line\n")
        status, output = run([praetorctl, "compile-context", "--verify"], repo)
        found += refused("vendor file drifted from AGENTS.md", status, output, "CLAUDE.md is out of sync")
        must(["git", "checkout", "--quiet", "--", "CLAUDE.md"], repo)
        filler = Path(scratch) / "filler.md"
        filler.write_text(FILLER, encoding="utf-8")
        status, output = run([praetorctl, "caveman", "check", "--kind=context", str(filler)], repo)
        found += refused("filler prose", status, output, "1 of 1 input(s) failed")
        (repo / PLANTED_GO).write_text(RECURSION, encoding="utf-8")
        status, output = run([praetorctl, "audit", "--offline"], repo, audit_env)
        # The path separator follows the platform; the line number does not.
        found += refused("recursive Go function", status, output, "[HISS-01]", "planted.go:3")
        return found


def remove_method(repo: Path) -> None:
    path = repo / API_SOURCE
    text = path.read_text(encoding="utf-8")
    start = text.find(API_METHOD)
    if start < 0:
        raise PlantError(f"{API_SOURCE} no longer declares {API_METHOD!r}; plant another method")
    end = text.index("\n}\n", start) + len("\n}\n")
    path.write_text(text[:start] + text[end:], encoding="utf-8")


def api_gate(root: Path) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="api-plant-") as scratch:
        repo = clone(root, Path(scratch))
        gate = str(Path(scratch) / "gate")
        must(["go", "build", "-tags", "apicompatgate", "-o", gate, GATE_SOURCE], repo)
        remove_method(repo)
        must(["git", "-c", "user.name=plant", "-c", "user.email=plant@example.invalid",
              "-c", "commit.gpgsign=false", "commit", "--quiet", "--all", "--message", "plant"], repo)
        status, output = run([gate, "-base=HEAD~1", "-policy=reject"], repo)
        found = [] if status == 1 and API_FINDING in output else [
            f"plant passed: removed method under -policy=reject: exit {status}, not 1 naming {API_FINDING!r}"
        ]
        status, output = run([gate, "-base=HEAD~1", "-policy=auto"], repo)
        if status not in (0, 1) or API_FINDING not in output:
            found.append(f"plant unreported: removed method under -policy=auto: exit {status}")
        return found


def semver(root: Path, baseline: str, semver_checks: str) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="semver-plant-") as scratch:
        repo = clone(root, Path(scratch))
        path = repo / SEMVER_SOURCE
        text = path.read_text(encoding="utf-8")
        if text.count(SEMVER_METHOD) != 1:
            raise PlantError(f"{SEMVER_SOURCE} no longer declares {SEMVER_METHOD.strip()!r}; plant another method")
        path.write_text(text.replace(SEMVER_METHOD, SEMVER_METHOD.replace("pub ", "pub(crate) ")), encoding="utf-8")
        # The release type is fixed at minor: derived from the version, a tree
        # whose version already announces a major change (0.1 to 0.2) allows
        # the plant, and the plant would pass on every release branch.
        argv = [
            *shlex.split(semver_checks),
            "--package", "amussis-decision", "--baseline-rev", baseline, "--release-type", "minor",
        ]
        status, output = run(argv, repo)
        return refused("public method made crate-private", status, output, *SEMVER_FINDINGS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("engine", "api-gate", "semver"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--praetorctl", default=os.environ.get("PRAETORCTL") or "praetorctl")
    parser.add_argument("--baseline", help="semver: the release tag to compare with")
    parser.add_argument("--semver-checks", default="cargo semver-checks")
    args = parser.parse_args()
    if shutil.which("git") is None:
        print("ERROR: git is not installed", file=sys.stderr)
        return 2
    if args.command == "semver" and not args.baseline:
        print("ERROR: semver needs --baseline", file=sys.stderr)
        return 2
    try:
        if args.command == "engine":
            found = engine(args.root, args.praetorctl)
        elif args.command == "api-gate":
            found = api_gate(args.root)
        else:
            found = semver(args.root, args.baseline, args.semver_checks)
    except PlantError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"PASS: gate plants {args.command} (every plant refused)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
