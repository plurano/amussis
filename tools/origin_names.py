#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Refuse source-repository-only names throughout every crate Rust source.

The library came out of an operating system that numbers its components (P06,
P09), milestones (M02), and decisions (D02), tags its schemas `aegis.<...>`,
and keeps its requirements under `docs/roadmap/`. Those names belong to that
system's repository or adapter. Here component and system names may stand in
one place: the sentence that says where the crate came from, named line for
line in ORIGIN below. Milestone numbers, decision numbers, and the roadmap path
have no allowance.

    check       every line of every crates/**/*.rs source that carries such a
                name is an origin line, and every origin line is still there
    selftest    plant one name per form and place and require each to fail;
                require look-alikes (P256, M2, d02, SHA-256) to pass

Exit status: 0 no name outside the origin lines, 1 a name was found or an origin
line is gone, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

from toolkit import (
    CheckError,
    append_to,
    planted as toolkit_planted,
    read_lines,
    replace_in,
    run_selftest,
)

CRATES = "crates"
SOURCES = "**/*.rs"
MAX_SOURCES = 512
# A component number is P and two digits standing alone: `P06`, `p09-p06` and
# `P06_GATE` count, `P256` and `step06` do not.
NAMES = {
    "component number": re.compile(r"(?<![A-Za-z0-9])[Pp][0-9]{2}(?![A-Za-z0-9])"),
    "milestone number": re.compile(r"(?<![A-Za-z0-9])M[0-9]{2}(?![A-Za-z0-9])"),
    "decision number": re.compile(r"(?<![A-Za-z0-9])D[0-9]{2,3}(?![A-Za-z0-9])"),
    "roadmap path": re.compile(r"docs/roadmap/"),
    "schema tag": re.compile(r"aegis\."),
}
ORIGIN = {
    "crates/amussis-decision/src/lib.rs": (
        "//! It was cut from the Aegis OS repository, where it is component P06",
    ),
}


def sources(root: Path) -> list[Path]:
    """Every Rust source under crates/, refusing a tree it cannot bound."""
    found = sorted((root / CRATES).glob(SOURCES))
    if not found:
        raise CheckError(f"no source matches {CRATES}/{SOURCES} under {root}")
    if len(found) > MAX_SOURCES:
        raise CheckError(f"more than {MAX_SOURCES} sources; raise MAX_SOURCES knowingly")
    return found


def named(line: str) -> list[str]:
    """The kinds of origin name this line carries."""
    return [kind for kind, pattern in NAMES.items() if pattern.search(line)]


def check(root: Path) -> tuple[list[str], int]:
    """The findings, and the number of sources read."""
    found = []
    files = sources(root)
    for path in files:
        name = path.relative_to(root).as_posix()
        allowed = ORIGIN.get(name, ())
        lines = read_lines(path)
        for number, line in enumerate(lines, start=1):
            kinds = named(line)
            if kinds and line not in allowed:
                found.append(f"{name}:{number}: {' and '.join(kinds)} outside the origin lines")
        for line in allowed:
            if line not in lines:
                found.append(f"{name}: the origin line is gone, drop it from ORIGIN: {line!r}")
    read = {path.relative_to(root).as_posix() for path in files}
    for name in sorted(set(ORIGIN) - read):
        found.append(f"{name}: named in ORIGIN and not a source")
    for name, allowed in ORIGIN.items():
        for line in allowed:
            if not named(line):
                found.append(f"{name}: an origin line carries no name, drop it: {line!r}")
    return found, len(files)


def copy_sources(root: Path, copy: Path) -> None:
    for path in sources(root):
        target = copy / path.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def planted(root: Path, edit) -> Path:
    """A throwaway copy of every Rust source under crates/ with one edit applied."""
    return toolkit_planted(root, "origin-names-", copy_sources, edit)


ENGINE = "crates/amussis-decision/src/engine.rs"
NESTED = "crates/amussis-decision/src/ledger/mod.rs"
SECOND_CRATE = "crates/amussis-decision-wasm/src/wire.rs"
TEST_SOURCE = "crates/amussis-decision/tests/interface_triples.rs"
ORIGIN_FILE = "crates/amussis-decision/src/lib.rs"
ORIGIN_LINE = ORIGIN[ORIGIN_FILE][0]

PLANTS = {
    "component number in a comment": append_to(ENGINE, "// the gate of P09\n"),
    "component number in an identifier": append_to(ENGINE, "const P06_GATE: u8 = 0;\n"),
    "lower-case component numbers": append_to(ENGINE, 'const EDGE: &str = "x.p09-p06.y";\n'),
    "schema tag in a string": append_to(ENGINE, 'const TAG: &str = "aegis.audit-record.v1";\n'),
    "milestone number in a comment": append_to(ENGINE, "// production signer arrives in M20\n"),
    "decision number in a string": append_to(ENGINE, 'const RULE: &str = "decision D111";\n'),
    "roadmap path in a doc comment": append_to(NESTED, "/// See docs/roadmap/requirements.md."),
    "name in a nested module": append_to(NESTED, "// read by P16"),
    "name in the second crate": append_to(SECOND_CRATE, "// sent by P09"),
    "name in a tests source": append_to(TEST_SOURCE, "// sent by P09"),
    "second name beside the origin line": append_to(ORIGIN_FILE, "// see also P05"),
    "origin line reworded, its allowance left": replace_in(
        ORIGIN_FILE, ORIGIN_LINE, ORIGIN_LINE.replace("component P06", "the decision engine")
    ),
    "origin line with a second component": replace_in(
        ORIGIN_FILE, ORIGIN_LINE, ORIGIN_LINE + " and P09"
    ),
    "origin file removed": lambda copy: (copy / ORIGIN_FILE).unlink(),
}

LOOK_ALIKES = {
    "three digits": append_to(ENGINE, "// the curve P256 and the port p8080\n"),
    "inside a longer word": append_to(ENGINE, "// step06, mp06x and cp09\n"),
    "milestone look-alikes": append_to(ENGINE, "// M2, M123, and AM20x\n"),
    "decision look-alikes": append_to(ENGINE, "// D3D11 and lower-case d02\n"),
    "hash algorithm": append_to(ENGINE, "// SHA-256\n"),
    "the system's name without a tag": append_to(ENGINE, "// unlike aegis-style adapters\n"),
}


def selftest(root: Path) -> list[str]:
    """Each plant must be refused and each look-alike accepted."""
    return run_selftest(root, check, planted, PLANTS, LOOK_ALIKES)


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
            found, read = check(args.root)
            lines = sum(len(allowed) for allowed in ORIGIN.values())
            detail = (
                f"{read} Rust sources under crates/, {lines} origin line, "
                "0 source-repository names elsewhere"
            )
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"PASS: origin names {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
