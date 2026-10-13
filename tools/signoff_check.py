#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Require a Signed-off-by trailer on every commit a pull request brings.

    check       every commit of --base..--head that is not a merge carries a
                line starting `Signed-off-by: ` in its message
    selftest    build a scratch repository and require an unsigned commit, a
                sign-off quoted inside a line and an empty sign-off to be
                refused, and a signed range, a range whose only unsigned commit
                is a merge, and an empty range to pass

CI runs `check` on the pull request's base and head; the gate runs `selftest`.

Exit status: 0 every commit signed off, 1 a commit lacks it, 2 the check itself
could not run.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_COMMITS = 1000
DEADLINE_SECONDS = 60
SIGNED = re.compile(r"^Signed-off-by: \S", re.MULTILINE)
SIGN_OFF = "Signed-off-by: Plant <plant@example.invalid>"


class CheckError(Exception):
    """The check could not run; distinct from a commit that lacks a sign-off."""


def git(repo: Path, *args: str) -> str:
    argv = ["git", "-C", str(repo), *args]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=DEADLINE_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"{' '.join(argv)}: {error}") from error
    if done.returncode != 0:
        raise CheckError(f"{' '.join(argv)} exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout


def check(repo: Path, base: str, head: str) -> tuple[list[str], int]:
    """The findings, and the number of commits read."""
    commits = git(repo, "rev-list", "--no-merges", f"{base}..{head}").split()
    if len(commits) > MAX_COMMITS:
        raise CheckError(f"more than {MAX_COMMITS} commits in {base}..{head}; raise MAX_COMMITS knowingly")
    found = []
    for sha in commits:
        if not SIGNED.search(git(repo, "log", "-1", "--format=%B", sha)):
            found.append(f"commit {sha} lacks a Signed-off-by trailer")
    return found, len(commits)


def commit(repo: Path, message: str) -> str:
    """One empty commit with message, unsigned by key, on the current branch."""
    git(repo, "-c", "user.name=Plant", "-c", "user.email=plant@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "--message", message)
    return git(repo, "rev-parse", "HEAD").strip()


def merge(repo: Path, branch: str) -> str:
    git(repo, "-c", "user.name=Plant", "-c", "user.email=plant@example.invalid",
        "-c", "commit.gpgsign=false", "merge", "--quiet", "--no-ff", "--no-edit", branch)
    return git(repo, "rev-parse", "HEAD").strip()


def scratch_ranges(repo: Path) -> dict[str, tuple[str, str, bool]]:
    """Name -> (base, head, refused) over one scratch history."""
    git(repo, "init", "--quiet", "--initial-branch=main")
    base = commit(repo, f"base\n\n{SIGN_OFF}")
    signed = commit(repo, f"signed\n\n{SIGN_OFF}")
    unsigned = commit(repo, "unsigned\n\nno trailer here")
    quoted = commit(repo, f"quoted\n\nsee the line {SIGN_OFF}")
    empty = commit(repo, "empty\n\nSigned-off-by: ")
    git(repo, "checkout", "--quiet", "-b", "side", signed)
    side = commit(repo, f"side\n\n{SIGN_OFF}")
    git(repo, "checkout", "--quiet", "--detach", signed)
    git(repo, "checkout", "--quiet", "-b", "merged")
    commit(repo, f"other\n\n{SIGN_OFF}")
    merged = merge(repo, side)
    return {
        "signed commit": (base, signed, False),
        "unsigned commit": (signed, unsigned, True),
        "sign-off quoted inside a line": (unsigned, quoted, True),
        "sign-off with no name": (quoted, empty, True),
        "unsigned commit among signed ones": (base, empty, True),
        "unsigned merge of signed commits": (signed, merged, False),
        "empty range": (signed, signed, False),
    }


def selftest() -> list[str]:
    failures = []
    with tempfile.TemporaryDirectory(prefix="signoff-") as scratch:
        repo = Path(scratch)
        for name, (base, head, refused) in scratch_ranges(repo).items():
            found = check(repo, base, head)[0]
            if refused and not found:
                failures.append(f"plant passed: {name}")
            if not refused and found:
                failures.append(f"clean range refused: {name}: {found[0]}")
        try:
            check(repo, "no-such-revision", "HEAD")
            failures.append("an unknown revision was read as an empty range")
        except CheckError:
            pass
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "selftest"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base")
    parser.add_argument("--head")
    args = parser.parse_args()
    if args.command == "check" and not (args.base and args.head):
        parser.error("check needs --base and --head")
    try:
        if args.command == "selftest":
            found, detail = selftest(), "4 plants refused, 3 clean ranges and 1 bad revision held"
        else:
            found, read = check(args.repo, args.base, args.head)
            detail = f"{read} commits signed off"
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"PASS: sign-off {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
