#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Hold every exception of this workspace to one named, dated entry.

Three rules are read. The first is `unsafe_code`:

The workspace forbids unsafe code. A WebAssembly export crate cannot live under
a forbid, so it carries its own lint tables with `unsafe_code = "deny"` and one
file allows the lint. exceptions.toml names that file, the rule, the reason and
the day the exception ends. This tool holds the three places to each other:

    every member manifest inherits the workspace lints, or carries tables that
    equal them but for `unsafe_code = "deny"`, and then holds a live exception;
    every source file that lowers `unsafe_code` is named by a live exception;
    every exception names a file that lowers the lint, has a reason, and ends
    at most 90 days from today.

The second is `required-check-is-reported`. The declared rule set
(.github/rulesets/main.json) is written by the Praetor engine, and for a job
that calls another workflow it requires the calling job's own name. The forge
reports such a job as `<calling job> / <called job>`, so no run ever reports
the required name (cordanaLLM/praetor#1212):

    a required check that a job with steps reports under its own name holds;
    a required check that is the bare name of a calling job needs a live
    exception for the rule-set file;
    a required check that no job of any workflow carries is refused, with or
    without an exception;
    an exception left after the last such name went excuses nothing.

No job of this workspace calls another workflow today, so the list holds no
entry for this rule. The selftest gives every planted tree one calling job,
its required name and its entry, so the rule stays proven until a job needs it.

The third is `module-byte-comparison`. A Windows host cannot build the data
section bytes of the committed WebAssembly module (separators, string-pool order,
Location pointers), so tools/wasm_module.py skips the data section comparison on
Windows while a live entry names the module; code is held order-free on all hosts,
and a macOS host is held with no exception; this tool holds the entry to that
one file and hands it to the module check (`live_exception`). Whether the entry
still excuses anything is decided where it applies: on a Windows host whose
build equals the module, the module check refuses the entry.

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
import json
import re
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

LIST = "exceptions.toml"
MANIFEST = "Cargo.toml"
RULE = "unsafe_code"
REPORTED = "required-check-is-reported"
COMPARED = "module-byte-comparison"
RULES = (RULE, REPORTED, COMPARED)
RULESET = ".github/rulesets/main.json"
MODULE = "bindings/go/decision/amussis_decision.wasm"
# The one file each of these rules excuses.
ONLY_FILE = {REPORTED: RULESET, COMPARED: MODULE}
WORKFLOWS = ".github/workflows"
MAX_WORKFLOWS = 64
ENTRY_KEYS = {"rule", "path", "reason", "expires"}
MAX_DAYS = 90
MAX_REASON_BYTES = 1024
MAX_ENTRIES = 64
MAX_SOURCE_FILES = 4096
# A lint attribute that sets `unsafe_code` below deny, in any position: inner
# or outer, alone or in a list, direct or under cfg_attr. Text in a comment
# matches too, and that is meant: the check errs towards refusing.
LOWERING = re.compile(r"\b(?:allow|expect|warn)\s*\((?:[^()]|\([^()]*\))*\bunsafe_code\b")
# A workflow is read by its layout, two spaces a level, as every workflow here
# is written: the job identifier, then the three keys that decide what a job
# reports. A job this cannot place stops the check instead of passing.
JOB = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*(?:#.*)?$")
JOB_KEY = re.compile(r"^    (name|uses|runs-on):\s*(\S.*)$")
CALL = re.compile(r"^    uses: ", re.MULTILINE)


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
    only = ONLY_FILE.get(entry["rule"], entry["path"])
    if entry["path"] != only:
        return f"rule {entry['rule']!r} excuses only {only}, not {entry['path']!r}"
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


def load_entries(root: Path, today: datetime.date) -> tuple[dict[tuple[str, str], dict[str, str]], list[str]]:
    """The live and the expired entries by rule and path, and what is wrong with the list."""
    document = load_toml(root / LIST)
    entries = document.get("exception", [])
    if set(document) - {"exception"} or not isinstance(entries, list):
        raise CheckError(f"{LIST} must hold only [[exception]] tables")
    if len(entries) > MAX_ENTRIES:
        raise CheckError(f"{LIST} holds {len(entries)} entries; the bound is {MAX_ENTRIES}")
    found, by_key = [], {}
    for index, entry in enumerate(entries):
        problem = entry_problem(root, entry, today)
        if problem:
            found.append(f"{LIST} entry {index}: {problem}")
        elif (entry["rule"], entry["path"]) in by_key:
            found.append(f"{LIST} entry {index}: repeats the entry for {entry['path']}")
        else:
            by_key[(entry["rule"], entry["path"])] = entry
    return by_key, found


def live_exception(root: Path, rule: str, path: str, today: datetime.date) -> dict[str, str] | None:
    """The entry for one rule and file while it is live on `today`, or None.

    An entry the list check refuses is not live, and neither is one past its day.
    """
    by_key, _ = load_entries(root, today)
    entry = by_key.get((rule, path))
    if entry is None or datetime.date.fromisoformat(entry["expires"]) < today:
        return None
    return entry


def of_rule(by_key: dict[tuple[str, str], dict[str, str]], rule: str) -> dict[str, str]:
    """The last day of each entry of one rule, by path."""
    return {path: entry["expires"] for (named, path), entry in by_key.items() if named == rule}


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


def scalar(value: str) -> str:
    """One YAML scalar as written on its line: the quotes and a trailing comment go."""
    if value[0] in "'\"":
        end = value.find(value[0], 1)
        if end < 0:
            raise CheckError(f"a workflow value opens a quote it does not close: {value!r}")
        return value[1:end]
    return value.split(" #", 1)[0].strip()


def jobs_of(name: str, text: str) -> list[dict[str, str]]:
    """The jobs of one workflow: identifier, and `name`, `uses`, `runs-on` where written."""
    jobs, inside = [], False
    for line in text.splitlines():
        if line[:1] not in ("", " ", "#"):
            inside = line.split("#", 1)[0].rstrip() == "jobs:"
        elif inside and JOB.match(line):
            jobs.append({"id": JOB.match(line).group(1)})
        elif inside and jobs and JOB_KEY.match(line):
            key, value = JOB_KEY.match(line).groups()
            jobs[-1][key] = scalar(value)
    for job in jobs:
        if ("uses" in job) == ("runs-on" in job):
            raise CheckError(f"{name}: job {job['id']!r} neither runs steps nor calls a workflow, or does both")
        if "${{" in job.get("name", ""):
            raise CheckError(f"{name}: the name of job {job['id']!r} is computed; this check reads fixed names")
    if not jobs:
        raise CheckError(f"{name}: no job found")
    return jobs


def job_names(root: Path) -> tuple[set[str], dict[str, str]]:
    """The names jobs report themselves, and the bare names of calling jobs by workflow."""
    files = sorted((root / WORKFLOWS).glob("*.y*ml"))
    if not files or len(files) > MAX_WORKFLOWS:
        raise CheckError(f"{len(files)} workflows found; expected 1 to {MAX_WORKFLOWS}")
    reported, calling = set(), {}
    for path in files:
        for job in jobs_of(path.name, read_text(path)):
            name = job.get("name", job["id"])
            if "uses" in job:
                calling[name] = path.name
            else:
                reported.add(name)
    return reported, calling


def required_checks(root: Path) -> list[str]:
    """The status checks the declared rule set requires."""
    try:
        document = json.loads(read_text(root / RULESET))
        names = [
            required["context"]
            for rule in document["rules"]
            if rule["type"] == "required_status_checks"
            for required in rule["parameters"]["required_status_checks"]
        ]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise CheckError(f"{RULESET} cannot be read as a rule set: {error!r}") from error
    if not names or any(not isinstance(name, str) for name in names):
        raise CheckError(f"{RULESET} requires no status check; this check expects at least one")
    return names


def reported_findings(root: Path, by_path: dict[str, str], today: datetime.date) -> list[str]:
    """Every required check no run reports, read on the day `today`."""
    reported, calling = job_names(root)
    live = RULESET in by_path and datetime.date.fromisoformat(by_path[RULESET]) >= today
    expired = f"; its exception ended on {by_path[RULESET]}" if RULESET in by_path else ""
    found, excused = [], 0
    for name in required_checks(root):
        if name in reported:
            continue
        if name not in calling:
            found.append(f"{RULESET}: requires check {name!r}, a name no job of any workflow carries")
        elif live:
            excused += 1
        else:
            found.append(
                f"{RULESET}: requires check {name!r}, which no run reports (the job in "
                f"{calling[name]} calls another workflow), without a live exception{expired}"
            )
    if live and not excused:
        found.append(f"{LIST}: the entry for {RULESET} excuses nothing; every required check is reported")
    return found


def check(root: Path, today: datetime.date) -> list[str]:
    """Every broken rule in the tree under `root`, read on the day `today`."""
    by_key, found = load_entries(root, today)
    found.extend(unsafe_findings(root, of_rule(by_key, RULE), today))
    found.extend(reported_findings(root, of_rule(by_key, REPORTED), today))
    return found


def unsafe_findings(root: Path, by_path: dict[str, str], today: datetime.date) -> list[str]:
    """Every lowering of `unsafe_code` without a live exception, read on the day `today`."""
    found = []
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


def drop_entry(path: str):
    """Take the one entry that names `path` out of the list."""

    def edit(tree: Path) -> None:
        head, *blocks = read_text(tree / LIST).split("[[exception]]")
        kept = [block for block in blocks if f'path = "{path}"' not in block]
        if len(kept) + 1 != len(blocks):
            raise CheckError(f"selftest plant: {LIST} holds no single entry for {path}")
        (tree / LIST).write_text("[[exception]]".join([head, *kept]), encoding="utf-8")

    return edit


def same_end(tree: Path, end: datetime.date) -> None:
    """Give every entry one last day, so a date plant reads all of them alike."""
    text = EXPIRES.sub(f'expires = "{end}"', read_text(tree / LIST))
    (tree / LIST).write_text(text, encoding="utf-8")


def repeat_entry(tree: Path) -> None:
    append_to(LIST, "\n" + one_entry(tree))(tree)


def every_call_runs(tree: Path) -> None:
    """Turn each job that calls a workflow into one that runs steps, in every workflow."""
    files = sorted((tree / WORKFLOWS).glob("*.y*ml"))[:MAX_WORKFLOWS]
    turned = 0
    for path in files:
        text = read_text(path)
        runs = CALL.sub("    runs-on: ", text)
        turned += runs != text
        path.write_text(runs, encoding="utf-8")
    if not turned:
        raise CheckError(f"selftest plant: no job under {WORKFLOWS} calls a workflow")


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
CALLER = f"{WORKFLOWS}/planted-caller.yml"
CALLING_JOB = "Planted caller"
CALLER_TEXT = f"""\
name: Planted
on: [push]
jobs:
  planted:
    name: {CALLING_JOB}
    uses: example/shared/.github/workflows/check.yml@0000000000000000000000000000000000000000
"""
GATE = f"{WORKFLOWS}/ci.yml"
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
    "unsafe exception dropped alone": (drop_entry(ABI), 0, f"{ABI}: lowers {RULE} without a live exception"),
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
    "calling job's name required without an entry": (
        drop_entry(RULESET),
        0,
        f"{RULESET}: requires check {CALLING_JOB!r}, which no run reports",
    ),
    "rule-set exception one day past its end": (
        None,
        MAX_DAYS + 1,
        "calls another workflow), without a live exception; its exception ended on",
    ),
    "rule-set exception names another file": (
        replace_in(LIST, f'path = "{RULESET}"', f'path = "{CALLER}"'),
        0,
        f"excuses only {RULESET}",
    ),
    "required check that no job carries": (
        replace_in(RULESET, '"context": "Verification gate"', '"context": "Verification gat"'),
        0,
        "requires check 'Verification gat', a name no job of any workflow carries",
    ),
    "required job renamed in its workflow": (
        replace_in(GATE, "    name: Verification gate\n", "    name: Gate\n"),
        0,
        "requires check 'Verification gate', a name no job of any workflow carries",
    ),
    "required job without a name of its own": (
        replace_in(GATE, "    name: Verification gate\n", ""),
        0,
        "requires check 'Verification gate', a name no job of any workflow carries",
    ),
    "rule-set exception left after the last calling job went": (
        every_call_runs,
        0,
        f"the entry for {RULESET} excuses nothing",
    ),
    "job that neither runs nor calls": (
        replace_in(CALLER, "    uses: example/shared/", "    usez: example/shared/"),
        0,
        "neither runs steps nor calls a workflow",
    ),
    "job name that is computed": (
        replace_in(GATE, "    name: Verification gate\n", "    name: Gate on ${{ matrix.os }}\n"),
        0,
        "is computed",
    ),
    "module exception names another file": (
        replace_in(LIST, f'path = "{MODULE}"', f'path = "{ABI}"'),
        0,
        f"excuses only {MODULE}",
    ),
    "rule set that requires no check": (
        replace_in(RULESET, '"type": "required_status_checks"', '"type": "required_checks"'),
        0,
        "requires no status check",
    ),
    "rule set that is no JSON": (append_to(RULESET, "}"), 0, "cannot be read as a rule set"),
    "workflow without a job": (replace_in(CALLER, "jobs:\n", "job:\n"), 0, "no job found"),
    "workspace no longer forbids": (
        replace_in(MANIFEST, f'{RULE} = "forbid"', f'{RULE} = "deny"'),
        0,
        f"the workspace must forbid {RULE}",
    ),
}


def plant_caller(tree: Path, end: datetime.date) -> None:
    """Give a copy one calling job, its required name and its entry."""
    (tree / CALLER).write_text(CALLER_TEXT, encoding="utf-8")
    try:
        document = json.loads(read_text(tree / RULESET))
        for rule in document["rules"]:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"].append({"context": CALLING_JOB})
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise CheckError(f"selftest plant: {RULESET} cannot be read as a rule set: {error!r}") from error
    (tree / RULESET).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    entry = f'\n[[exception]]\nrule = "{REPORTED}"\npath = "{RULESET}"\nreason = "planted"\nexpires = "{end}"\n'
    append_to(LIST, entry)(tree)


def plant_module_entry(tree: Path, end: datetime.date) -> None:
    """Give a copy the entry for the module, unless the list holds it."""
    if f'rule = "{COMPARED}"' not in read_text(tree / LIST):
        entry = f'\n[[exception]]\nrule = "{COMPARED}"\npath = "{MODULE}"\nreason = "planted"\nexpires = "{end}"\n'
        append_to(LIST, entry)(tree)


def planted(root: Path, end: datetime.date, edit) -> Path:
    """A throwaway copy of the manifests, the list, the rule set, the module, the workflows and the member sources."""
    tree = Path(tempfile.mkdtemp(prefix="exceptions-check-"))
    (tree / RULESET).parent.mkdir(parents=True)
    (tree / MODULE).parent.mkdir(parents=True)
    for name in (MANIFEST, LIST, RULESET, MODULE):
        shutil.copyfile(root / name, tree / name)
    for top in (WORKFLOWS, *source_roots(members(root)[1])):
        shutil.copytree(root / top, tree / top, ignore=shutil.ignore_patterns("target"))
    plant_caller(tree, end)
    plant_module_entry(tree, end)
    same_end(tree, end)
    if edit is not None:
        edit(tree)
    return tree


def refusals(root: Path, end: datetime.date, edit, day: datetime.date) -> list[str]:
    """What the check says of one planted tree on `day`; a check that cannot run refuses too."""
    tree = planted(root, end, edit)
    try:
        return check(tree, day)
    except CheckError as error:
        return [f"the check could not run: {error}"]
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def reader_failures(root: Path, end: datetime.date) -> list[str]:
    """What `live_exception` gets wrong on a planted tree whose entries end on `end`."""
    tree = planted(root, end, None)
    after = end + datetime.timedelta(days=1)
    try:
        cases = {
            "the module entry is not live on its last day": live_exception(tree, COMPARED, MODULE, end) is None,
            "the module entry is live past its day": live_exception(tree, COMPARED, MODULE, after) is not None,
            "the module entry is live for another file": live_exception(tree, COMPARED, ABI, end) is not None,
            "the module entry is live for another rule": live_exception(tree, RULE, MODULE, end) is not None,
        }
    finally:
        shutil.rmtree(tree, ignore_errors=True)
    return [name for name, wrong in cases.items() if wrong]


def selftest(root: Path, today: datetime.date) -> list[str]:
    """Each plant must be refused, and for the reason it was planted for."""
    failures = [f"the unplanted tree is refused: {line}" for line in check(root, today)]
    ends = sorted(set(EXPIRES.findall(read_text(root / LIST))))
    if len(ends) != 1:
        return [*failures, f"the selftest is written for one end date in {LIST}; it holds {len(ends)}"]
    # Every planted tree carries that end on all entries, the committed ones
    # and the planted ones: a date plant is read relative to that day, an edit
    # plant on it.
    end = datetime.date.fromisoformat(ends[0])
    last_day = refusals(root, end, None, end)
    failures.extend(f"the exceptions do not hold on their last day: {line}" for line in last_day)
    failures.extend(reader_failures(root, end))
    for name, (edit, days, expected) in PLANTS.items():
        day = end - datetime.timedelta(days=MAX_DAYS) + datetime.timedelta(days=days)
        found = refusals(root, end, edit, day if edit is None else end)
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
