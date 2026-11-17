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
(.github/rulesets/main.json) is written by the Praetor engine, which now requires
the forge's reported name, `<calling job> / <called job>`, for a job that calls
another workflow. The called workflow can live outside this workspace, so its
job names cannot be checked offline:

    a required check that a job with steps reports under its own name holds;
    a required check with a calling job's name before the first ` / ` holds
    when the called part is non-empty after stripping whitespace;
    a required check that is the bare name of a calling job needs a live
    exception for the rule-set file, for older rule sets;
    a required check that no job of any workflow carries is refused, with or
    without an exception;
    an exception left after the last such name went excuses nothing.

reuse.yml calls the horistes licence workflow, whose reported name is required
without an exception. The selftest also gives every planted tree one calling
job, its bare required name and its entry, keeping the older rule-set path
covered alongside reported names.

The third is `vulnerability`. Each entry names one existing scanned file and
a non-empty list of unique CVE, GHSA or PYSEC advisory IDs. The reason and
90-day expiry cap apply as for the other rules. tools/scanners.py uses only
live entries to generate a Trivy YAML ignore file scoped to those paths.
The `advisories` key is refused on every other rule.

A rule that is no longer read, such as `module-byte-comparison` (retired when
every host came to build the module's data section, issue #2), is refused like
any unknown rule, so its entry cannot return.

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
import tomllib
from pathlib import Path

import toolkit
from toolkit import CheckError, append_to, replace_in

LIST = "exceptions.toml"
MANIFEST = "Cargo.toml"
RULE = "unsafe_code"
REPORTED = "required-check-is-reported"
VULNERABILITY = "vulnerability"
RUFF = "ruff"
RULES = (RULE, REPORTED, VULNERABILITY, RUFF)
RULESET = ".github/rulesets/main.json"
# The one file each of these rules excuses.
ONLY_FILE = {REPORTED: RULESET}
WORKFLOWS = ".github/workflows"
MAX_WORKFLOWS = 64
ENTRY_KEYS = {"rule", "path", "reason", "expires"}
ADVISORY = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+)")
SCANNED_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
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


def advisory_problem(advisories: object) -> str:
    """Require a non-empty list of unique advisory IDs from the allowed formats."""
    if not isinstance(advisories, list) or not advisories:
        return "advisories must be a non-empty list"
    if any(not isinstance(value, str) or not ADVISORY.fullmatch(value) for value in advisories):
        return "every advisory ID must match the CVE, GHSA or PYSEC format"
    if len(set(advisories)) != len(advisories):
        return "advisories must be unique"
    return ""


def entry_problem(root: Path, entry: object, today: datetime.date) -> str:
    """Why one entry cannot be applied as written, or the empty string."""
    if not isinstance(entry, dict):
        return "must be an exception table"
    keys = ENTRY_KEYS | {"advisories"} if entry.get("rule") == VULNERABILITY else ENTRY_KEYS
    if entry.get("rule") == RUFF:
        keys = ENTRY_KEYS | {"codes"}
    if set(entry) != keys:
        return f"must hold exactly the keys {sorted(keys)}"
    if any(not isinstance(entry[key], str) for key in ENTRY_KEYS):
        return "rule, path, reason and expires must be strings"
    if entry["rule"] not in RULES:
        return f"rule {entry['rule']!r} is not a rule this check reads (known: {list(RULES)})"
    path = Path(entry["path"])
    if path.is_absolute() or ".." in path.parts or path.as_posix() != entry["path"]:
        return f"path {entry['path']!r} must be one clean path below the repository root"
    if entry["rule"] == VULNERABILITY:
        if not SCANNED_PATH.fullmatch(entry["path"]):
            return "vulnerability path must contain only letters, digits, dots, underscores, hyphens and slashes"
        problem = advisory_problem(entry["advisories"])
        if problem:
            return problem
    if entry["rule"] == RUFF:
        codes = entry["codes"]
        if not isinstance(codes, list) or not codes:
            return "codes must be a non-empty list"
        if any(not isinstance(code, str) or not re.fullmatch(r"[A-Z]+[0-9]+", code) for code in codes):
            return "every code must be a Ruff rule code"
        if len(set(codes)) != len(codes):
            return "codes must be unique"
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


def load_entries(root: Path, today: datetime.date) -> tuple[dict[tuple[str, str], dict], list[str]]:
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


def of_rule(by_key: dict[tuple[str, str], dict], rule: str) -> dict[str, str]:
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
    """Exact steps-job names, and calling-job prefixes by workflow; called jobs are unknown."""
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


def is_reported(name: str, reported: set[str], calling: dict[str, str]) -> bool:
    """An exact steps-job name or a caller followed by a non-empty called name."""
    caller, _, called = name.partition(" / ")
    return name in reported or (caller in calling and bool(called.strip()))


def reported_findings(root: Path, by_path: dict[str, str], today: datetime.date) -> list[str]:
    """Every required check no run reports, read on the day `today`."""
    reported, calling = job_names(root)
    listed = RULESET in by_path
    live = listed and datetime.date.fromisoformat(by_path[RULESET]) >= today
    expired = f"; its exception ended on {by_path[RULESET]}" if listed else ""
    found, needed = [], 0
    for name in required_checks(root):
        if is_reported(name, reported, calling):
            continue
        if name not in calling:
            found.append(f"{RULESET}: requires check {name!r}, a name no job of any workflow carries")
            continue
        needed += 1
        if not live:
            found.append(
                f"{RULESET}: requires check {name!r}, which no run reports (the job in "
                f"{calling[name]} calls another workflow), without a live exception{expired}"
            )
    # Whether a check still needs the entry does not depend on its day: an
    # entry nothing needs fails before and after it ends.
    if listed and not needed:
        found.append(f"{LIST}: the entry for {RULESET} excuses nothing; every required check is reported")
    return found


def ruff_findings(root: Path, by_key: dict, today: datetime.date) -> list[str]:
    """Match each configured path and code to a live exception, in both directions."""
    config = load_toml(root / "ruff.toml")
    ignores = config.get("lint", {}).get("per-file-ignores", {})
    if not isinstance(ignores, dict):
        raise CheckError("ruff.toml per-file-ignores must be a table")
    configured = set()
    for path, codes in ignores.items():
        if not isinstance(codes, list) or any(not isinstance(code, str) for code in codes):
            raise CheckError(f"ruff.toml: invalid ignores for {path}")
        configured.update((path, code) for code in codes)
    live = {(path, code) for (rule, path), entry in by_key.items()
            if rule == RUFF and datetime.date.fromisoformat(entry["expires"]) >= today
            for code in entry["codes"]}
    return ([f"ruff.toml: {path} {code} without a live exception" for path, code in sorted(configured - live)]
            + [f"{LIST}: {path} {code} excuses nothing" for path, code in sorted(live - configured)])


def check(root: Path, today: datetime.date) -> list[str]:
    """Every broken rule in the tree under `root`, read on the day `today`."""
    by_key, found = load_entries(root, today)
    found.extend(unsafe_findings(root, of_rule(by_key, RULE), today))
    found.extend(reported_findings(root, of_rule(by_key, REPORTED), today))
    found.extend(ruff_findings(root, by_key, today))
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


def one_entry(tree: Path) -> str:
    text = read_text(tree / LIST)
    start = text.find("[[exception]]")
    if start < 0:
        raise CheckError(f"selftest plant: {LIST} holds no entry")
    return text[start:]


def drop_entries(tree: Path) -> None:
    text = read_text(tree / LIST)
    (tree / LIST).write_text(text.replace(one_entry(tree), ""), encoding="utf-8")


def entry_blocks(tree: Path, path: str) -> tuple[list[str], int]:
    """The list split at its entries (the head first), and the index of the one entry naming `path`."""
    blocks = read_text(tree / LIST).split("[[exception]]")
    hits = [index for index, block in enumerate(blocks) if index and f'path = "{path}"' in block]
    if len(hits) != 1:
        raise CheckError(f"selftest plant: {LIST} holds no single entry for {path}")
    return blocks, hits[0]


def drop_entry(path: str):
    """Take the one entry that names `path` out of the list."""

    def edit(tree: Path) -> None:
        """Write the list back without that entry."""
        blocks, index = entry_blocks(tree, path)
        del blocks[index]
        (tree / LIST).write_text("[[exception]]".join(blocks), encoding="utf-8")

    return edit


def end_entry(path: str):
    """Move the last day of the one entry that names `path` to the day before it."""

    def edit(tree: Path) -> None:
        """Write the list back with that entry ending one day earlier."""
        blocks, index = entry_blocks(tree, path)
        match = EXPIRES.search(blocks[index])
        if not match:
            raise CheckError(f"selftest plant: the entry for {path} names no last day")
        day = datetime.date.fromisoformat(match[1]) - datetime.timedelta(days=1)
        blocks[index] = EXPIRES.sub(f'expires = "{day}"', blocks[index])
        (tree / LIST).write_text("[[exception]]".join(blocks), encoding="utf-8")

    return edit


def every_call_runs_after_end(tree: Path) -> None:
    """Leave the rule-set entry needed by no check, one day after its end."""
    every_call_runs(tree)
    end_entry(RULESET)(tree)


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


def require_called_name(name: str):
    """Require a composite name in place of the bare caller, without its exception."""

    def edit(tree: Path) -> None:
        replace_in(RULESET, f'"context": "{CALLING_JOB}"', f'"context": "{name}"')(tree)
        drop_entry(RULESET)(tree)

    return edit


REPORTED_NAMES = {
    "calling job's reported name without an entry": require_called_name(f"{CALLING_JOB} / Check"),
    "called name with another separator": require_called_name(f"{CALLING_JOB} / Check / Detail"),
}

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
    "ruff ignore without entry": (replace_in(LIST, '"S603", "S607"', '"S603"'), 0, "S607 without a live exception"),
    "ruff entry without ignore": (replace_in("ruff.toml", '"S603", "S607"', '"S603"'), 0, "S607 excuses nothing"),
    "ruff empty codes": (replace_in(LIST, 'codes = ["S603", "S607"]', 'codes = []'), 0, "codes must be a non-empty list"),
    "ruff bad code": (replace_in(LIST, 'codes = ["S603", "S607"]', 'codes = ["S*"]'), 0, "Ruff rule code"),
    "ruff unknown key": (replace_in(LIST, 'codes = ["S603", "S607"]', 'codes = ["S603", "S607"]\nextra = true'), 0, "exactly the keys"),
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
    "steps job used as a calling prefix": (
        require_called_name("Verification gate / Check"),
        0,
        "requires check 'Verification gate / Check', a name no job of any workflow carries",
    ),
    "unknown calling prefix": (
        require_called_name("Unknown caller / Check"),
        0,
        "requires check 'Unknown caller / Check', a name no job of any workflow carries",
    ),
    "calling name with an empty called part": (
        require_called_name(f"{CALLING_JOB} / "),
        0,
        f"requires check '{CALLING_JOB} / ', a name no job of any workflow carries",
    ),
    "calling name with a whitespace called part": (
        require_called_name(f"{CALLING_JOB} /   "),
        0,
        f"requires check '{CALLING_JOB} /   ', a name no job of any workflow carries",
    ),
    "rule-set exception left after the reported name is required": (
        replace_in(RULESET, f'"context": "{CALLING_JOB}"', f'"context": "{CALLING_JOB} / Check"'),
        0,
        f"the entry for {RULESET} excuses nothing",
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
    "rule-set exception left after the last calling job went, past its end": (
        every_call_runs_after_end,
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
    "entry of the retired module rule": (
        append_to(
            LIST,
            f'\n[[exception]]\nrule = "module-byte-comparison"\npath = "{ABI}"\nreason = "planted"\nexpires = "2000-01-01"\n',
        ),
        0,
        "rule 'module-byte-comparison' is not a rule this check reads",
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


def copy_exceptions_tree(root: Path, tree: Path, end: datetime.date) -> None:
    """Copy exception inputs into a fixture tree and plant a caller."""
    (tree / RULESET).parent.mkdir(parents=True)
    for name in (MANIFEST, LIST, RULESET, "ruff.toml"):
        shutil.copyfile(root / name, tree / name)
    for top in (WORKFLOWS, *source_roots(members(root)[1])):
        shutil.copytree(root / top, tree / top, ignore=shutil.ignore_patterns("target"))
    by_key, _ = load_entries(root, end)
    for (rule, name) in by_key:
        if rule in (VULNERABILITY, RUFF) and not (tree / name).is_file():
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, tree / name)
    plant_caller(tree, end)
    same_end(tree, end)


def planted(root: Path, end: datetime.date, edit) -> Path:
    """A throwaway copy of the manifests, the list, the rule set, the workflows and the member sources."""
    return toolkit.planted(
        root, "exceptions-check-", lambda r, c: copy_exceptions_tree(r, c, end), edit
    )


def refusals(root: Path, end: datetime.date, edit, day: datetime.date) -> list[str]:
    """What the check says of one planted tree on `day`; a check that cannot run refuses too."""
    tree = planted(root, end, edit)
    try:
        return check(tree, day)
    except CheckError as error:
        return [f"the check could not run: {error}"]
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def reported_name_failures(root: Path, end: datetime.date) -> list[str]:
    """Reported composite names must hold without a rule-set exception."""
    return [
        f"reported name refused: {name}: {line}"
        for name, edit in REPORTED_NAMES.items()
        for line in refusals(root, end, edit, end)
    ]


def vulnerability_selftest(root: Path, today: datetime.date) -> list[str]:
    """Require advisory validation refusals and acceptance at the 90-day boundary."""
    entry = {
        "rule": "vulnerability",
        "path": "tools/semgrep/requirements.txt",
        "advisories": ["CVE-2026-116684", "GHSA-ab12-cd34-ef56", "PYSEC-2026-123"],
        "reason": "planted boundary case",
        "expires": str(today + datetime.timedelta(days=MAX_DAYS)),
    }
    cases = {
        "90-day boundary": ({}, ""),
        "missing advisories": ({"advisories": None}, "exactly the keys"),
        "empty advisories": ({"advisories": []}, "non-empty list"),
        "scalar advisories": ({"advisories": "CVE-2026-116684"}, "non-empty list"),
        "bad advisory": ({"advisories": ["CVE-2026-*"]}, "advisory ID"),
        "non-string advisory": ({"advisories": [42]}, "advisory ID"),
        "duplicate advisories": ({"advisories": ["CVE-2026-116684"] * 2}, "unique"),
        "unknown path": ({"path": "tools/semgrep/missing.txt"}, "names no file"),
        "empty reason": ({"reason": " "}, "reason must be"),
        "91-day expiry": ({"expires": str(today + datetime.timedelta(days=MAX_DAYS + 1))}, "days after today"),
        "advisories on another rule": ({"rule": RULE, "path": ABI}, "exactly the keys"),
    }
    failures = []
    for name, (changes, expected) in cases.items():
        planted_entry = entry | changes
        if planted_entry["advisories"] is None:
            del planted_entry["advisories"]
        found = entry_problem(root, planted_entry, today)
        if (not expected and found) or (expected and expected not in found):
            failures.append(f"vulnerability {name}: expected {expected!r}, got {found!r}")
    return failures


def selftest(root: Path, today: datetime.date) -> list[str]:
    """Each plant must be refused, and for the reason it was planted for."""
    failures = vulnerability_selftest(root, today)
    failures.extend(f"the unplanted tree is refused: {line}" for line in check(root, today))
    ends = sorted(set(EXPIRES.findall(read_text(root / LIST))))
    if not ends:
        return [*failures, f"the selftest needs an end date in {LIST}"]
    # Every planted tree carries the earliest end on all entries, the committed ones
    # and the planted ones: a date plant is read relative to that day, an edit
    # plant on it.
    end = datetime.date.fromisoformat(ends[0])
    last_day = refusals(root, end, None, end)
    failures.extend(f"the exceptions do not hold on their last day: {line}" for line in last_day)
    for name, (edit, days, expected) in PLANTS.items():
        day = end - datetime.timedelta(days=MAX_DAYS) + datetime.timedelta(days=days)
        found = refusals(root, end, edit, day if edit is None else end)
        if not found:
            failures.append(f"plant passed: {name}")
        elif not any(expected in line for line in found):
            failures.append(f"plant refused for another reason: {name}: {found}")
    failures.extend(reported_name_failures(root, end))
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
    detail = (
        f"{len(PLANTS)} tree plants refused, {len(REPORTED_NAMES)} reported names held; vulnerability cases held"
        if args.command == "selftest" else f"as of {today}"
    )
    print(f"PASS: exceptions {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
