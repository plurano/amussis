#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Hold every lowering of `unsafe_code` to one named, dated exception.

The workspace forbids unsafe code. A WebAssembly export crate cannot live under
a forbid, so it carries its own lint tables with `unsafe_code = "deny"` and one
file allows the lint. exceptions.toml names that file, the rule, the reason and
the day the exception ends. This tool holds the three places to each other:

    every member manifest inherits the workspace lints, or carries tables that
    equal them but for `unsafe_code = "deny"`, and then holds a live exception;
    every source file that lowers `unsafe_code` is named by a live exception;
    every exception names a file that lowers the lint, has a reason, and ends
    at most 90 days from today.

An exception past its day excuses nothing: the file it names fails as if the
entry were missing.

    check       the tree as it stands, against today's date
    selftest    plant one defect per rule and require each to be refused

Exit status: 0 held, 1 a rule is broken, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import re
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

LIST = "exceptions.toml"
MANIFEST = "Cargo.toml"
RULE = "unsafe_code"
RULES = (RULE,)
ENTRY_KEYS = {"rule", "path", "reason", "expires"}
MAX_DAYS = 90
MAX_REASON_BYTES = 1024
MAX_ENTRIES = 64
MAX_SOURCE_FILES = 4096
# A lint attribute that sets `unsafe_code` below deny, in any position: inner
# or outer, alone or in a list, direct or under cfg_attr. Text in a comment
# matches too, and that is meant: the check errs towards refusing.
LOWERING = re.compile(r"\b(?:allow|expect|warn)\s*\((?:[^()]|\([^()]*\))*\bunsafe_code\b")


class CheckError(Exception):
    """The check could not run; distinct from a rule that is broken."""


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CheckError(f"cannot read {path}: {error}") from error


def load_toml(path: Path) -> dict:
    try:
        return tomllib.loads(read_text(path))
    except tomllib.TOMLDecodeError as error:
        raise CheckError(f"{path} is not valid TOML: {error}") from error


def entry_problem(root: Path, entry: object, today: datetime.date) -> str:
    """Why one entry cannot be applied as written, or the empty string."""
    if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
        return f"must hold exactly the keys {sorted(ENTRY_KEYS)}"
    if any(not isinstance(value, str) for value in entry.values()):
        return "every value must be a string"
    if entry["rule"] not in RULES:
        return f"rule {entry['rule']!r} is not a rule this check reads (known: {list(RULES)})"
    path = Path(entry["path"])
    if path.is_absolute() or ".." in path.parts or path.as_posix() != entry["path"]:
        return f"path {entry['path']!r} must be one clean path below the repository root"
    if not (root / path).is_file():
        return f"path {entry['path']!r} names no file"
    reason = entry["reason"]
    if not reason.strip() or "\n" in reason or len(reason.encode("utf-8")) > MAX_REASON_BYTES:
        return f"reason must be one non-empty line of at most {MAX_REASON_BYTES} bytes"
    try:
        expires = datetime.date.fromisoformat(entry["expires"])
    except ValueError:
        return f"expires {entry['expires']!r} must be a YYYY-MM-DD date"
    latest = today + datetime.timedelta(days=MAX_DAYS)
    if expires > latest:
        return f"expires {expires} is more than {MAX_DAYS} days after today; latest is {latest}"
    return ""


def load_entries(root: Path, today: datetime.date) -> tuple[dict[str, str], list[str]]:
    """The live and the expired entries by path, and what is wrong with the list."""
    document = load_toml(root / LIST)
    entries = document.get("exception", [])
    if set(document) - {"exception"} or not isinstance(entries, list):
        raise CheckError(f"{LIST} must hold only [[exception]] tables")
    if len(entries) > MAX_ENTRIES:
        raise CheckError(f"{LIST} holds {len(entries)} entries; the bound is {MAX_ENTRIES}")
    found, by_path = [], {}
    for index, entry in enumerate(entries):
        problem = entry_problem(root, entry, today)
        if problem:
            found.append(f"{LIST} entry {index}: {problem}")
        elif entry["path"] in by_path:
            found.append(f"{LIST} entry {index}: repeats the entry for {entry['path']}")
        else:
            by_path[entry["path"]] = entry["expires"]
    return by_path, found


def members(root: Path) -> tuple[dict, list[str]]:
    workspace = load_toml(root / MANIFEST).get("workspace", {})
    try:
        lints, names = workspace["lints"], workspace["members"]
    except KeyError as error:
        raise CheckError(f"{MANIFEST} [workspace] lacks {error}") from error
    if not names or any(not isinstance(name, str) or "*" in name for name in names):
        raise CheckError(f"{MANIFEST} [workspace] members must be written out, never globbed")
    return lints, names


def source_roots(names: list[str]) -> list[str]:
    """The top-level directories that hold a member; a file shared by path lives there too."""
    return sorted({Path(name).parts[0] for name in names})


def source_files(root: Path, names: list[str]) -> list[Path]:
    files = sorted(
        path
        for top in source_roots(names)
        for path in (root / top).rglob("*.rs")
        if "target" not in path.parts
    )
    if not files or len(files) > MAX_SOURCE_FILES:
        raise CheckError(f"{len(files)} Rust files found; expected 1 to {MAX_SOURCE_FILES}")
    return files


def check(root: Path, today: datetime.date) -> list[str]:
    """Every broken rule in the tree under `root`, read on the day `today`."""
    by_path, found = load_entries(root, today)
    live = {path for path, expires in by_path.items() if datetime.date.fromisoformat(expires) >= today}
    lints, names = members(root)
    if lints.get("rust", {}).get(RULE) != "forbid":
        found.append(f"{MANIFEST}: the workspace must forbid {RULE}")
    lowered = copy.deepcopy(lints)
    lowered.setdefault("rust", {})[RULE] = "deny"
    lowering_files = set()
    for name in names:
        own = load_toml(root / name / MANIFEST).get("lints")
        if own == lowered:
            if not any(path.startswith(f"{name}/") for path in live):
                found.append(f"{name}/{MANIFEST}: lowers {RULE} to deny without a live exception")
        elif own != {"workspace": True}:
            found.append(
                f"{name}/{MANIFEST}: [lints] must inherit the workspace tables, "
                f'or equal them but for {RULE} = "deny"'
            )
    for path in source_files(root, names):
        if LOWERING.search(read_text(path)):
            lowering_files.add(path.relative_to(root).as_posix())
    for path in sorted(lowering_files - live):
        expired = f"; its exception ended on {by_path[path]}" if path in by_path else ""
        found.append(f"{path}: lowers {RULE} without a live exception{expired}")
    for path in sorted(set(by_path) - lowering_files):
        found.append(f"{LIST}: the entry for {path} excuses nothing; the file does not lower {RULE}")
    return found


def replace_in(name: str, old: str, new: str):
    def edit(tree: Path) -> None:
        text = read_text(tree / name)
        if old not in text:
            raise CheckError(f"selftest plant: {name} does not contain {old!r}")
        (tree / name).write_text(text.replace(old, new, 1), encoding="utf-8")

    return edit


def append_to(name: str, text: str):
    def edit(tree: Path) -> None:
        (tree / name).write_text(read_text(tree / name) + text, encoding="utf-8")

    return edit


def one_entry(tree: Path) -> str:
    text = read_text(tree / LIST)
    start = text.find("[[exception]]")
    if start < 0:
        raise CheckError(f"selftest plant: {LIST} holds no entry")
    return text[start:]


def drop_entries(tree: Path) -> None:
    text = read_text(tree / LIST)
    (tree / LIST).write_text(text.replace(one_entry(tree), ""), encoding="utf-8")


def repeat_entry(tree: Path) -> None:
    append_to(LIST, "\n" + one_entry(tree))(tree)


def lower_second_member(tree: Path) -> None:
    """Give the engine crate the export crate's lowered tables."""
    lowered = read_text(tree / WASM / MANIFEST)
    start = lowered.find("[lints.rust]")
    if start < 0:
        raise CheckError(f"selftest plant: {WASM}/{MANIFEST} holds no [lints.rust]")
    replace_in(f"{ENGINE}/{MANIFEST}", "[lints]\nworkspace = true\n", lowered[start:])(tree)


ENGINE = "crates/amussis-decision"
WASM = "crates/amussis-decision-wasm"
ABI = f"{WASM}/src/abi.rs"
EXPIRES = re.compile(r'expires = "(\d{4}-\d{2}-\d{2})"')

# name -> (edit, days added to today, text the refusal must contain)
PLANTS = {
    "allowance in a second file": (
        append_to(f"{WASM}/src/binding.rs", "\n#![allow(unsafe_code)]\n"),
        0,
        "src/binding.rs: lowers",
    ),
    "expectation on one item": (
        append_to(f"{WASM}/src/wire.rs", "\n#[expect(unsafe_code)]\nfn planted() {}\n"),
        0,
        "src/wire.rs: lowers",
    ),
    "allowance under cfg_attr in the engine": (
        append_to(f"{ENGINE}/src/lib.rs", "\n#[cfg_attr(test, allow(dead_code, unsafe_code))]\nfn p() {}\n"),
        0,
        f"{ENGINE}/src/lib.rs: lowers",
    ),
    "allowance in a file shared by path": (
        replace_in("crates/dependency_closure.rs", "#![allow(dead_code)]", "#![allow(dead_code, unsafe_code)]"),
        0,
        "crates/dependency_closure.rs: lowers",
    ),
    "allowance in a test file": (
        append_to(f"{WASM}/tests/host_effects.rs", "\n#![warn(\n    unsafe_code\n)]\n"),
        0,
        "tests/host_effects.rs: lowers",
    ),
    "exception one day past its end": (None, MAX_DAYS + 1, "its exception ended on"),
    "exception list emptied": (drop_entries, 0, f"{ABI}: lowers {RULE} without a live exception"),
    "exception repeated": (repeat_entry, 0, "repeats the entry"),
    "exception without a reason": (
        lambda tree: (tree / LIST).write_text(
            re.sub(r'reason = "[^"\n]*"', 'reason = " "', read_text(tree / LIST)), encoding="utf-8"
        ),
        0,
        "reason must be",
    ),
    "exception ends after the bound": (None, -1, "days after today"),
    "exception end is no date": (
        lambda tree: (tree / LIST).write_text(
            EXPIRES.sub('expires = "never"', read_text(tree / LIST)), encoding="utf-8"
        ),
        0,
        "must be a YYYY-MM-DD date",
    ),
    "exception for another rule": (
        replace_in(LIST, f'rule = "{RULE}"', 'rule = "missing_docs"'),
        0,
        "is not a rule this check reads",
    ),
    "exception with a further key": (append_to(LIST, 'glob = "crates/**"\n'), 0, "exactly the keys"),
    "exception names no file": (replace_in(LIST, "src/abi.rs", "src/gone.rs"), 0, "names no file"),
    "exception names a file outside": (
        replace_in(LIST, f'"{ABI}"', f'"../amussis/{ABI}"'),
        0,
        "below the repository root",
    ),
    "exception left after the allowance went": (
        replace_in(ABI, "#![allow(unsafe_code)]", ""),
        0,
        "excuses nothing",
    ),
    "export crate allows the lint": (
        replace_in(f"{WASM}/{MANIFEST}", f'{RULE} = "deny"', f'{RULE} = "allow"'),
        0,
        f"{WASM}/{MANIFEST}: [lints] must",
    ),
    "export crate drops a lint": (
        replace_in(f"{WASM}/{MANIFEST}", 'unwrap_used = "deny"\n', ""),
        0,
        f"{WASM}/{MANIFEST}: [lints] must",
    ),
    "export crate relaxes a lint": (
        replace_in(f"{WASM}/{MANIFEST}", 'panic = "deny"', 'panic = "warn"'),
        0,
        f"{WASM}/{MANIFEST}: [lints] must",
    ),
    "engine crate without lint tables": (
        replace_in(f"{ENGINE}/{MANIFEST}", "[lints]\nworkspace = true\n", ""),
        0,
        f"{ENGINE}/{MANIFEST}: [lints] must",
    ),
    "engine crate lowered without an exception": (
        lower_second_member,
        0,
        f"{ENGINE}/{MANIFEST}: lowers {RULE} to deny without a live exception",
    ),
    "workspace no longer forbids": (
        replace_in(MANIFEST, f'{RULE} = "forbid"', f'{RULE} = "deny"'),
        0,
        f"the workspace must forbid {RULE}",
    ),
}


def planted(root: Path, edit) -> Path:
    """A throwaway copy of the manifests, the list and the member sources."""
    tree = Path(tempfile.mkdtemp(prefix="exceptions-check-"))
    for name in (MANIFEST, LIST):
        shutil.copyfile(root / name, tree / name)
    for top in source_roots(members(root)[1]):
        shutil.copytree(root / top, tree / top, ignore=shutil.ignore_patterns("target"))
    if edit is not None:
        edit(tree)
    return tree


def selftest(root: Path, today: datetime.date) -> list[str]:
    """Each plant must be refused, and for the reason it was planted for."""
    failures = [f"the unplanted tree is refused: {line}" for line in check(root, today)]
    ends = EXPIRES.findall(read_text(root / LIST))
    if len(ends) != 1:
        return [*failures, f"the selftest is written for one exception; {LIST} holds {len(ends)}"]
    end = datetime.date.fromisoformat(ends[0])
    if check(root, end):
        failures.append("the exception does not hold on its last day")
    for name, (edit, days, expected) in PLANTS.items():
        tree = planted(root, edit)
        try:
            # A date plant is read relative to the entry's end, an edit plant on that end day.
            day = end - datetime.timedelta(days=MAX_DAYS) + datetime.timedelta(days=days)
            found = check(tree, day if edit is None else end)
        finally:
            shutil.rmtree(tree, ignore_errors=True)
        if not found:
            failures.append(f"plant passed: {name}")
        elif not any(expected in line for line in found):
            failures.append(f"plant refused for another reason: {name}: {found}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "selftest"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    today = datetime.datetime.now(datetime.UTC).date()
    try:
        found = selftest(args.root, today) if args.command == "selftest" else check(args.root, today)
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    detail = f"{len(PLANTS)} plants refused" if args.command == "selftest" else f"as of {today}"
    print(f"PASS: exceptions {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
