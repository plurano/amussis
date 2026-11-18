#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Refuse analyser suppression markers that carry no rule id or no reason.

    check [--repo DIR]   scan tracked *.py, *.sh, *.yml, *.yaml, *.toml, *.go, *.rs,
                         *.mjs, *.js files and Makefile under DIR (default: current directory)
    selftest             plant refused and clean markers in a scratch repository

A Bandit or gosec marker (the word nosec after a comment opener) names one or more
ids (B or G and three digits), then " -- " and a reason of at least 3 words.
A Semgrep marker (the word nosemgrep after a comment opener) names ": <rule id>", then
" -- " and a reason of at least 3 words. Semgrep reads everything after the colon as
a list of ids, so the trailing reason does not change which rule is excused; it must
be the last marker on its line.

No tracked path is skipped: the files in the supported formats hold no vendored markers.
Exit status: 0 held, 1 findings, 2 the check could not run.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

from message_ids import fixture_env, git
from toolkit import CheckError, read_lines

SUFFIXES = frozenset({".py", ".sh", ".yml", ".yaml", ".toml", ".go", ".rs", ".mjs", ".js"})
NAMES = frozenset({"Makefile"})
MIN_REASON_WORDS = 3
OPENER = r"(?:#|//|/\*)[ \t]*"
# Bandit ends the id list at the next comment opener, so the nosec tail does too.
NOSEC = re.compile(OPENER + r"nosec\b(?P<tail>[^#]*)", re.IGNORECASE)
NOSEC_IDS = re.compile(r":?[ \t]*[BG]\d{3}\b(?:[, \t]+[BG]\d{3}\b)*(?P<rest>.*)")
NOSEMGREP = re.compile(OPENER + r".*?\bnosem(?:grep)?\b(?P<tail>.*)", re.IGNORECASE)
SEMGREP_IDS = re.compile(r":[ \t]?[A-Za-z0-9_][\w.-]*(?:[, \t]+[A-Za-z0-9_][\w.-]*)*(?P<rest>.*)")
REASON = re.compile(r"[ \t]+--[ \t]+(?P<reason>\S.*)")
MARKERS = (("nosec", NOSEC, NOSEC_IDS), ("nosemgrep", NOSEMGREP, SEMGREP_IDS))


def reason_problem(name: str, rest: str) -> str | None:
    """Name what is wrong with the text after the ids, or None when the reason holds."""
    match = REASON.fullmatch(rest.rstrip().removesuffix("*/").rstrip())
    if match is None:
        return f"{name} without reason"
    if len(re.findall(r"\w+", match["reason"])) < MIN_REASON_WORDS:
        return f"{name} reason under {MIN_REASON_WORDS} words"
    return None


def marker_problem(name: str, ids: re.Pattern[str], tail: str) -> str | None:
    """Check the ids and the reason in the text after one marker word."""
    match = ids.fullmatch(tail)
    if match is None:
        return f"{name} without rule id"
    return reason_problem(name, match["rest"])


def findings(label: str, lines: list[str]) -> list[str]:
    """Return locations and kinds of refused markers, never the marker text."""
    found = []
    for number, line in enumerate(lines, 1):
        for name, pattern, ids in MARKERS:
            for match in pattern.finditer(line):
                problem = marker_problem(name, ids, match["tail"])
                if problem:
                    found.append(f"{label}:{number}: {problem}")
    return found


def tracked_files(repo: Path, env: dict[str, str] | None = None) -> list[str]:
    """List tracked paths in the supported formats; a path that is gone from disk holds nothing."""
    names = git(repo, "ls-files", "-z", env=env).split("\0")
    return [name for name in names if name and (Path(name).suffix in SUFFIXES or Path(name).name in NAMES)
            and (repo / name).is_file()]


def scan(repo: Path, env: dict[str, str] | None = None) -> list[str]:
    """Find refused markers in all tracked files of the repository."""
    found = []
    for name in tracked_files(repo, env):
        found.extend(findings(name, read_lines(repo / name)))
    return found


def planted_cases() -> dict[str, tuple[str, str | None]]:
    """Map a scratch file stem to its line and the finding it must give (None: held).

    The marker words are built here so no source line of this file holds a marker.
    """
    sec, semgrep = "no" + "sec", "no" + "semgrep"
    return {
        "bare_sec": (f"x = 1  # {sec}", f"{sec} without rule id"),
        "sec_id_only": (f"x = 1  # {sec} B404", f"{sec} without reason"),
        "bare_semgrep": (f"x = 1  # {semgrep}", f"{semgrep} without rule id"),
        "later_semgrep": (f"x = 1  # explanation: {semgrep}", f"{semgrep} without rule id"),
        "semgrep_id_only": (f"x = 1  # {semgrep}: example.rule-id", f"{semgrep} without reason"),
        "full_sec": (f"x = 1  # {sec} B404 -- fixed executable, no shell", None),
        "full_semgrep": (f"x = 1  # {semgrep}: example.rule-id -- fixed executable, no shell", None),
        "later_full": (f"x = 1  # explanation: {semgrep}: a.b -- fixed executable, no shell", None),
        "id_list": (f"x = 1  # {semgrep}: a.b, c.d -- fixed executable, no shell", None),
        "id_list_compact": (f"x = 1  # {semgrep}: a.b,c.d -- fixed executable, no shell", None),
        "id_list_dangling": (f"x = 1  # {semgrep}: a.b, -- fixed executable, no shell", f"{semgrep} without reason"),
    }


def selftest() -> list[str]:
    """Refuse the planted markers and hold the complete ones in a scratch repository."""
    cases = planted_cases()
    env = fixture_env()
    with tempfile.TemporaryDirectory(prefix="suppression-") as scratch:
        repo = Path(scratch)
        git(repo, "init", "--quiet", env=env)
        for stem, (line, _) in cases.items():
            (repo / f"{stem}.py").write_text(line + "\n", encoding="utf-8")
        git(repo, "add", "--all", env=env)
        found = scan(repo, env)
    failures = []
    for stem, (_, expected) in cases.items():
        want = [f"{stem}.py:1: {expected}"] if expected else []
        if [hit for hit in found if hit.startswith(f"{stem}.py:")] != want:
            failures.append(f"{'plant passed' if expected else 'clean case refused'}: {stem}")
    return failures


def parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    result = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("check").add_argument("--repo", type=Path, default=Path())
    commands.add_parser("selftest")
    return result


def main() -> int:
    """Run the requested check and map findings and errors to exit codes."""
    args = parser().parse_args()
    try:
        found = scan(args.repo) if args.command == "check" else selftest()
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    cases = planted_cases()
    refused = sum(1 for _, expected in cases.values() if expected)
    detail = f" ({refused} plants refused, {len(cases) - refused} clean cases held)" if args.command == "selftest" else ""
    print(f"PASS: suppression {args.command}{detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
