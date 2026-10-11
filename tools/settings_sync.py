#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
# SPDX-License-Identifier: EUPL-1.2
"""Hold the shared toolchain and lint settings to one recorded source.

The toolchain pin, the formatter and lint configuration and the workspace lint
tables are not written here; they are taken from the repository named in
settings-source.json. Three files are byte copies (rust-toolchain.toml,
clippy.toml, rustfmt.toml) and four keys of the workspace manifest are compared
as parsed values (resolver, edition, rust-version and the lint tables).

    check                 local settings equal the record; no network, no checkout
    check --source DIR    additionally: the record equals a checkout of the source
    update --source DIR   copy the files from DIR and rewrite the record
    selftest              plant one defect per setting and require each to fail

Exit status: 0 in step, 1 a setting differs, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

RECORD = "settings-source.json"
MANIFEST = "Cargo.toml"
COPIED_FILES = ("rust-toolchain.toml", "clippy.toml", "rustfmt.toml")
GIT_DEADLINE_SECONDS = 30


class CheckError(Exception):
    """The check could not run; distinct from a setting that differs."""


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise CheckError(f"cannot read {path}: {error}") from error


def refuse_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    repeated = sorted({key for key in keys if keys.count(key) > 1})
    if repeated:
        raise CheckError(f"{RECORD} repeats the keys {repeated}")
    return dict(pairs)


def load_record(root: Path) -> dict:
    text = read_bytes(root / RECORD).decode("utf-8")
    try:
        record = json.loads(text, object_pairs_hook=refuse_duplicates)
    except json.JSONDecodeError as error:
        raise CheckError(f"{RECORD} is not valid JSON: {error}") from error
    try:
        files = record["files"]
        missing = [name for name in COPIED_FILES if name not in files]
        record["manifest_settings"], record["source"]["commit"]
    except (KeyError, TypeError) as error:
        raise CheckError(f"{RECORD} lacks the field {error}") from error
    if missing or len(files) != len(COPIED_FILES):
        raise CheckError(f"{RECORD} must list exactly {list(COPIED_FILES)}")
    return record


def manifest_settings(root: Path) -> dict:
    """The manifest keys shared with the source, as parsed values."""
    try:
        workspace = tomllib.loads(read_bytes(root / MANIFEST).decode("utf-8"))["workspace"]
        return {
            "resolver": workspace["resolver"],
            "edition": workspace["package"]["edition"],
            "rust-version": workspace["package"]["rust-version"],
            "lints": workspace["lints"],
        }
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise CheckError(f"{root / MANIFEST} lacks a shared setting: {error}") from error


def differences(root: Path, record: dict, label: str) -> list[str]:
    """Every setting under `root` that differs from the record."""
    found = []
    for name in COPIED_FILES:
        if sha256(read_bytes(root / name)) != record["files"][name]:
            found.append(f"{label}: {name} differs from the record")
    actual = manifest_settings(root)
    for key, expected in record["manifest_settings"].items():
        if actual.get(key) != expected:
            found.append(f"{label}: {MANIFEST} [workspace] {key} differs from the record")
    if set(actual) != set(record["manifest_settings"]):
        found.append(f"{label}: the record does not hold exactly the keys {sorted(actual)}")
    return found


def source_commit(source: Path) -> str:
    try:
        done = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=GIT_DEADLINE_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"git could not read {source}: {error}") from error
    if done.returncode != 0:
        raise CheckError(f"{source} is not a git checkout: {done.stderr.strip()}")
    return done.stdout.strip()


def check(root: Path, source: Path | None) -> list[str]:
    record = load_record(root)
    found = differences(root, record, "local")
    if source is not None:
        found += differences(source, record, f"source at {source_commit(source)[:12]}")
    return found


def update(root: Path, source: Path) -> list[str]:
    record = load_record(root)
    for name in COPIED_FILES:
        shutil.copyfile(source / name, root / name)
    record["source"]["commit"] = source_commit(source)
    record["files"] = {name: sha256(read_bytes(source / name)) for name in COPIED_FILES}
    record["manifest_settings"] = manifest_settings(source)
    (root / RECORD).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return differences(root, record, "local")


def planted(root: Path, edit) -> Path:
    """A throwaway copy of the tracked settings with one edit applied."""
    copy = Path(tempfile.mkdtemp(prefix="settings-sync-"))
    for name in (*COPIED_FILES, MANIFEST, RECORD):
        shutil.copyfile(root / name, copy / name)
    edit(copy)
    return copy


def replace_in(name: str, old: str, new: str):
    def edit(copy: Path) -> None:
        text = (copy / name).read_text(encoding="utf-8")
        if old not in text:
            raise CheckError(f"selftest plant: {name} does not contain {old!r}")
        (copy / name).write_text(text.replace(old, new, 1), encoding="utf-8")

    return edit


PLANTS = {
    "toolchain channel moved": replace_in("rust-toolchain.toml", 'channel = "', 'channel = "9'),
    "clippy threshold relaxed": replace_in("clippy.toml", "threshold = 60", "threshold = 600"),
    "formatter width changed": replace_in("rustfmt.toml", "max_width = 100", "max_width = 120"),
    "lint level lowered": replace_in(MANIFEST, 'unwrap_used = "deny"', 'unwrap_used = "warn"'),
    "lint removed": replace_in(MANIFEST, 'panic = "deny"\n', ""),
    "rust-version raised": replace_in(MANIFEST, 'rust-version = "', 'rust-version = "9'),
    "edition changed": replace_in(MANIFEST, 'edition = "2024"', 'edition = "2021"'),
    "resolver changed": replace_in(MANIFEST, 'resolver = "3"', 'resolver = "2"'),
    "record hash edited": replace_in(RECORD, '"sha256:', '"sha256:0'),
}


def selftest(root: Path) -> list[str]:
    """Each plant must be refused, in the local and in the source position."""
    failures = [f"the unplanted tree is refused: {line}" for line in check(root, None)]
    for name, edit in PLANTS.items():
        copy = planted(root, edit)
        try:
            if not check(copy, None):
                failures.append(f"local plant passed: {name}")
            if name != "record hash edited" and not differences(
                copy, load_record(root), "source"
            ):
                failures.append(f"source plant passed: {name}")
        finally:
            shutil.rmtree(copy, ignore_errors=True)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "update", "selftest"))
    parser.add_argument("--source", type=Path, help="checkout of the source repository")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        if args.command == "selftest":
            found = selftest(args.root)
        elif args.command == "update":
            if args.source is None:
                raise CheckError("update needs --source")
            found = update(args.root, args.source)
        else:
            found = check(args.root, args.source)
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    scope = "local and source" if args.source and args.command == "check" else "local"
    detail = f"{len(PLANTS)} plants refused" if args.command == "selftest" else scope
    print(f"PASS: settings {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
