#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Refuse private plan identifiers in text and commit messages.

    check-text FILE...             check each line of each file
    check-range --base B --head H  check all commits in B..H, including merges
    check-history [--ref REF]      check reachable history and live exceptions
    selftest                       exercise synthetic plants in a scratch repo

Exit status: 0 held, 1 findings, 2 the check could not run.
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from exceptions_check import load_entries
from toolkit import CheckError, read_lines

MAX_COMMITS = 1000
MAX_HISTORY_COMMITS = 5000
DEADLINE_SECONDS = 60
DATED = re.compile(r"(?<![A-Za-z0-9_/.-])[a-z][a-z0-9]*(?:-[a-z0-9]+){2,}-20\d{6}(?:-\d{4})?(?![A-Za-z0-9_-])")
HEX = re.compile(r"(?<![A-Za-z0-9_/.-])[a-z][a-z0-9]*(?:-[a-z0-9]+){2,}-[0-9a-f]{12}(?![A-Za-z0-9_-])")
ORDER = re.compile(r"^[ \t]*Order: ", re.MULTILINE | re.IGNORECASE)
PATTERNS = (("dated", DATED), ("hex", HEX), ("order", ORDER))


def findings(label: str, text: str) -> list[str]:
    """Return locations and kinds without exposing matched content."""
    return [f"{label}:{number}: {kind}" for number, line in enumerate(text.splitlines(), 1)
            for kind, pattern in PATTERNS for _ in pattern.finditer(line)]


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    """Run Git with a deadline and report operational failures."""
    argv = ["git", "-C", str(repo), *args]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=DEADLINE_SECONDS, env=env)  # noqa: S603 - fixed executable and argv list without a shell
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"git could not run: {error}") from error
    if result.returncode:
        raise CheckError(f"git exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def revision(repo: Path, ref: str, env: dict[str, str] | None = None) -> str:
    """Resolve a revision to a commit before passing it to log."""
    return git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}", env=env).strip()


def commits(repo: Path, ref: str, limit: int, base: str | None = None,
            env: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """Read at most limit commits, rejecting a larger reachable set."""
    head = revision(repo, ref, env)
    selection = f"{revision(repo, base, env)}..{head}" if base is not None else head
    output = git(repo, "log", "-z", f"--max-count={limit + 1}", "--format=%H%x00%B", selection, "--", env=env)
    fields = output.split("\0")
    if fields[-1] == "":
        fields.pop()
    if len(fields) % 2:
        raise CheckError("git log returned an invalid record")
    records = list(zip(fields[::2], fields[1::2], strict=True))
    if len(records) > limit:
        raise CheckError(f"more than {limit} commits; raise the bound knowingly")
    return records


def check_range(repo: Path, base: str, head: str, env: dict[str, str] | None = None) -> list[str]:
    """Find private identifiers in all commits of the range."""
    return [line for sha, message in commits(repo, head, MAX_COMMITS, base, env)
            for line in findings(f"commit {sha}", message)]


def check_history(repo: Path, ref: str, today: datetime.date, env: dict[str, str] | None = None) -> list[str]:
    """Check reachable commits and ensure each live exception is necessary."""
    entries, errors = load_entries(repo, today)
    if errors:
        raise CheckError("; ".join(errors))
    entry = entries.get(("private-id", "tools/message_ids.py"))
    excused = set(entry["commits"]) if entry and datetime.date.fromisoformat(entry["expires"]) >= today else set()
    found, seen = [], set()
    for sha, message in commits(repo, ref, MAX_HISTORY_COMMITS, env=env):
        hits = findings(f"commit {sha}", message)
        if sha in excused:
            seen.add(sha)
            if not hits:
                found.append(f"commit {sha}: excuses nothing")
        else:
            found.extend(hits)
    found.extend(f"commit {sha}: not reachable from ref" for sha in sorted(excused - seen))
    return found


def fixture_env() -> dict[str, str]:
    """Isolate scratch Git operations from inherited Git configuration."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    return env


def fixture_commit(repo: Path, message: str) -> str:
    """Create a synthetic scratch commit and return its hash."""
    git(repo, "-c", "user.name=Plant", "-c", "user.email=plant@example.invalid", "-c", "commit.gpgsign=false",
        "commit", "--quiet", "--allow-empty", "-m", message, env=fixture_env())
    return git(repo, "rev-parse", "HEAD", env=fixture_env()).strip()


def fixture_exception(repo: Path, sha: str, expiry: datetime.date) -> None:
    """Write a synthetic exception for the scratch repository."""
    (repo / "exceptions.toml").write_text(
        f'[[exception]]\nrule = "private-id"\npath = "tools/message_ids.py"\ncommits = ["{sha}"]\n'
        f'reason = "synthetic"\nexpires = "{expiry}"\n', encoding="utf-8")


def selftest() -> list[str]:
    """Refuse synthetic plants and accept clean and excepted cases."""
    plants = ["example-planted-check-20260101", "example-planted-unit-0123456789ab", "Order: x"]
    clean = ["clean", "CVE-2026-116684", "2026-11-17", "engine a60326a18b15",
             "crates/amussis-decision-wasm", "renovate-engine-bumps", "/x-y-z-20260101"]
    failures = ["text plant passed" for value in plants if not findings("fixture", value)]
    failures += ["clean text refused" for value in clean if findings("fixture", value)]
    with tempfile.TemporaryDirectory(prefix="message-ids-") as scratch:
        repo = Path(scratch)
        git(repo, "init", "--quiet", env=fixture_env())
        (repo / "tools").mkdir()
        (repo / "tools/message_ids.py").touch()
        base = fixture_commit(repo, "clean")
        hit = fixture_commit(repo, plants[0])
        today = datetime.datetime.now(datetime.UTC).date()
        (repo / "exceptions.toml").write_text("", encoding="utf-8")
        cases = [(bool(check_range(repo, base, hit, fixture_env())), True),
                 (bool(check_history(repo, hit, today, fixture_env())), True)]
        fixture_exception(repo, hit, today)
        cases.append((bool(check_history(repo, hit, today, fixture_env())), False))
        fixture_exception(repo, base, today)
        cases.append((bool(check_history(repo, hit, today, fixture_env())), True))
        fixture_exception(repo, hit, today - datetime.timedelta(days=1))
        cases.append((bool(check_history(repo, hit, today, fixture_env())), True))
        failures += ["scratch history case failed" for actual, expected in cases if actual != expected]
    return failures


def parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    result = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("check-text").add_argument("files", nargs="+", type=Path)
    branch = commands.add_parser("check-range")
    branch.add_argument("--base", required=True)
    branch.add_argument("--head", required=True)
    commands.add_parser("check-history").add_argument("--ref", default="HEAD")
    commands.add_parser("selftest")
    return result


def main() -> int:
    """Run the requested check and map findings and errors to exit codes."""
    args = parser().parse_args()
    try:
        if args.command == "check-text":
            found = [hit for path in args.files for hit in findings(str(path), "\n".join(read_lines(path)))]
        elif args.command == "check-range":
            found = check_range(Path.cwd(), args.base, args.head)
        elif args.command == "check-history":
            found = check_history(Path.cwd(), args.ref, datetime.datetime.now(datetime.UTC).date())
        else:
            found = selftest()
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    detail = " (7 plants refused, 8 clean cases held)" if args.command == "selftest" else ""
    print(f"PASS: message IDs {args.command}{detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
