#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Hold every Go block of the README to code that compiles and runs.

A reader copies the README's Go blocks. Each one has to stand, line for line,
in a Go file of examples/go-consumer, the module that uses the binding as a
program outside this repository does; `make verify-go` compiles that module
and runs its examples. A block whose lines are not found there in that order,
with no other line between them, was changed in one place only.

    check       every Go block of README.md stands in an example file; an
                `import "..."` line is held to the imports of that file
    selftest    plant one change per form and require each to fail; require
                differences of indentation and blank lines to pass

Lines are compared without their indentation and with every run of white space
read as one space, so a block may be indented with spaces in the README and
with tabs in the code. Blank lines are not compared.

Exit status: 0 every block stands in the examples, 1 a block does not or the
README holds none, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

README = "README.md"
EXAMPLES = "examples/go-consumer"
MAX_EXAMPLES = 64
FENCE_OPEN = "```go"
FENCE_CLOSE = "```"
IMPORT = re.compile(r'^import "([^"]+)"$')


class CheckError(Exception):
    """The check could not run; distinct from a block that was not found."""


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise CheckError(f"cannot read {path}: {error}") from error


def normal(line: str) -> str:
    return " ".join(line.split())


def blocks(lines: list[str]) -> tuple[list[tuple[int, list[str]]], int]:
    """The Go blocks of a Markdown file, the line each opens on and its lines,
    and the line of a block never closed (0 for none)."""
    found: list[tuple[int, list[str]]] = []
    opened = 0
    body: list[str] = []
    for number, line in enumerate(lines, start=1):
        if not opened and line.strip() == FENCE_OPEN:
            opened, body = number, []
        elif opened and line.strip() == FENCE_CLOSE:
            found.append((opened, body))
            opened = 0
        elif opened:
            body.append(line)
    return found, opened


def stands_in(want: list[str], have: list[str]) -> bool:
    """Whether want is a run of consecutive lines of have."""
    span = len(want)
    return any(have[start : start + span] == want for start in range(len(have) - span + 1))


def check(root: Path) -> tuple[list[str], int]:
    """The findings, and the number of README blocks held."""
    files = sorted((root / EXAMPLES).glob("*.go"))
    if len(files) > MAX_EXAMPLES:
        raise CheckError(f"more than {MAX_EXAMPLES} example files; raise MAX_EXAMPLES knowingly")
    if not files:
        return [f"no Go file under {EXAMPLES}"], 0
    examples = {}
    for path in files:
        examples[path.relative_to(root).as_posix()] = [
            normal(line) for line in read_lines(path) if line.strip()
        ]
    found = []
    held, unclosed = blocks(read_lines(root / README))
    if unclosed:
        found.append(f"{README}:{unclosed}: the Go block is never closed")
    if not held:
        found.append(f"{README} holds no Go block; the check would hold nothing")
    for opened, body in held:
        imports = [match.group(1) for match in map(IMPORT.match, map(str.strip, body)) if match]
        want = [normal(line) for line in body if line.strip() and not IMPORT.match(line.strip())]
        places = [
            name
            for name, have in examples.items()
            if stands_in(want, have) and all(f'"{path}"' in have for path in imports)
        ]
        if not places:
            found.append(f"{README}:{opened}: the Go block does not stand in any file of {EXAMPLES}")
    return found, len(held)


def planted(root: Path, edit) -> Path:
    """A throwaway copy of the README and the examples with one edit applied."""
    copy = Path(tempfile.mkdtemp(prefix="readme-snippets-"))
    shutil.copyfile(root / README, copy / README)
    shutil.copytree(root / EXAMPLES, copy / EXAMPLES)
    edit(copy)
    return copy


def replace_in(name: str, old: str, new: str):
    def edit(copy: Path) -> None:
        text = (copy / name).read_text(encoding="utf-8")
        if old not in text:
            raise CheckError(f"selftest plant: {name} does not contain {old!r}")
        (copy / name).write_text(text.replace(old, new, 1), encoding="utf-8")

    return edit


def in_go_blocks(transform):
    """An edit that rewrites every line inside the README's Go blocks."""

    def edit(copy: Path) -> None:
        out, inside = [], False
        for line in read_lines(copy / README):
            if line.strip() in (FENCE_OPEN, FENCE_CLOSE):
                inside = line.strip() == FENCE_OPEN
                out.append(line)
            else:
                out.append(transform(line) if inside else line)
        (copy / README).write_text("\n".join(out) + "\n", encoding="utf-8")

    return edit


EXAMPLE = f"{EXAMPLES}/example_test.go"
VOTE = "\tVote:     decision.Approve,\n"
INTENT = '\tIntentID: "intent-0042",\n'
CHECKERS = '\tCheckers: []string{"carol"},\n'
IMPORT_LINE = 'import "github.com/plurano/amussis/bindings/go/decision"'


def remove_examples(copy: Path) -> None:
    for path in (copy / EXAMPLES).glob("*.go"):
        path.unlink()


PLANTS = {
    "a README line changed": replace_in(README, VOTE, VOTE.replace("Approve", "Reject")),
    "a line of the example changed": replace_in(
        EXAMPLE, 'Checkers: []string{"petra"}', 'Checkers: []string{"petra", "quinn"}'
    ),
    "two README lines swapped": replace_in(README, INTENT + VOTE, VOTE + INTENT),
    "a line added to a README block": replace_in(README, CHECKERS, CHECKERS + "\tLevel:    3,\n"),
    "an import the example does not have": replace_in(README, IMPORT_LINE, IMPORT_LINE[:-1] + 's"'),
    "a line inserted in the example inside a block": replace_in(
        EXAMPLE, "\t\tVote:     decision.Approve,\n", "\t\tVote:     decision.Approve,\n\t\tLevel:    3,\n"
    ),
    "a Go block never closed": lambda copy: (copy / README).write_text(
        (copy / README).read_text(encoding="utf-8") + "\n" + FENCE_OPEN + "\n", encoding="utf-8"
    ),
    "every Go block turned to text": lambda copy: (copy / README).write_text(
        (copy / README).read_text(encoding="utf-8").replace(FENCE_OPEN + "\n", "```text\n"),
        encoding="utf-8",
    ),
    "the example files removed": remove_examples,
}

LOOK_ALIKES = {
    "README blocks indented with spaces": in_go_blocks(lambda line: line.replace("\t", "    ")),
    "blank lines inside README blocks": in_go_blocks(lambda line: line + "\n" if line.strip() else line),
    "white space at the end of README lines": in_go_blocks(lambda line: line + "  "),
}


def selftest(root: Path) -> list[str]:
    """Each plant must be refused and each look-alike accepted."""
    failures = [f"the unplanted tree is refused: {line}" for line in check(root)[0]]
    cases = [(name, edit, True) for name, edit in PLANTS.items()]
    cases += [(name, edit, False) for name, edit in LOOK_ALIKES.items()]
    for name, edit, refused in cases:
        copy = planted(root, edit)
        try:
            found = check(copy)[0]
            if refused and not found:
                failures.append(f"plant passed: {name}")
            if not refused and found:
                failures.append(f"look-alike refused: {name}: {found[0]}")
        finally:
            shutil.rmtree(copy, ignore_errors=True)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "selftest"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        if args.command == "selftest":
            found = selftest(args.root)
            detail = f"{len(PLANTS)} plants refused, {len(LOOK_ALIKES)} look-alikes accepted"
        else:
            found, held = check(args.root)
            detail = f"{held} Go blocks of {README} stand in {EXAMPLES}"
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"PASS: README snippets {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
