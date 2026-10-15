#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Hold the library crate to sources that build once they are packed.

The release packs amussis-decision with `cargo package` and compiles the
packed sources on their own (.github/workflows/release-build.yml). A source
that reads a file outside the crate directory, or a manifest that leaves a
module out of the package, builds in the workspace and fails only there, on a
tag. This runs the same step in the gate, without the network:

    check       `cargo package --locked --offline` packs the crate from the
                working tree and compiles the packed sources with warnings
                denied, as the release does
    selftest    plant one defect per form on a copy of the committed tree and
                require each to fail for its own reason; require a look-alike
                that stays inside the crate to pass

The runs build in target/package-check, a directory of this checkout of its
own: the release's warning flags then do not rebuild the gate's other builds.

Exit status: 0 the packed crate builds, 1 it does not or a plant passed,
2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from toolkit import CheckError

CRATE = "amussis-decision"
LIB = f"crates/{CRATE}/src/lib.rs"
MANIFEST = f"crates/{CRATE}/Cargo.toml"
TARGET = "target/package-check"
DEADLINE_SECONDS = 900
OUTSIDE = '\n/// Planted.\n#[doc = include_str!("../../../README.md")]\npub mod planted {}\n'
INSIDE = '\n/// Planted.\n#[doc = include_str!("../Cargo.toml")]\npub mod planted {}\n'
LEFT_OUT = 'exclude = ["src/ledger/hash.rs"]\n\n[lib]\n'


def package(tree: Path, target: Path) -> tuple[int, str]:
    """Pack and compile the crate of tree; the exit status and the output."""
    argv = ["cargo", "package", "--locked", "--offline", "--allow-dirty", "-p", CRATE,
            "--target-dir", str(target)]
    env = dict(os.environ, RUSTFLAGS="-D warnings")
    try:
        done = subprocess.run(argv, cwd=tree, env=env, capture_output=True, text=True,
                              timeout=DEADLINE_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"{' '.join(argv)}: {error}") from error
    return done.returncode, done.stdout + done.stderr


def committed(root: Path, into: Path) -> None:
    """Unpack the committed tree of root into the empty directory into."""
    try:
        done = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=root,
                              capture_output=True, timeout=DEADLINE_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"git archive: {error}") from error
    if done.returncode != 0:
        raise CheckError(f"git archive exited {done.returncode}: {done.stderr.decode()[-400:]}")
    with tarfile.open(fileobj=io.BytesIO(done.stdout)) as archive:
        archive.extractall(into, filter="data")


def append(name: str, text: str):
    def edit(tree: Path) -> None:
        with (tree / name).open("a", encoding="utf-8") as file:
            file.write(text)

    return edit


def replace(name: str, old: str, new: str):
    def edit(tree: Path) -> None:
        source = (tree / name).read_text(encoding="utf-8")
        if source.count(old) != 1:
            raise CheckError(f"selftest plant: {name} holds {old!r} {source.count(old)} times")
        (tree / name).write_text(source.replace(old, new), encoding="utf-8")

    return edit


# Each plant builds in the workspace and has to fail packed, with the marker
# that names its own cause in the output.
PLANTS = {
    "a source reads a file outside the crate": (append(LIB, OUTSIDE), "README.md"),
    "the manifest leaves a module out of the package": (
        replace(MANIFEST, "[lib]\n", LEFT_OUT), "hash.rs"),
}

LOOK_ALIKES = {
    "a source reads a file inside the crate": append(LIB, INSIDE),
}


def selftest(root: Path) -> list[str]:
    """Each plant must fail packed for its own reason; the unplanted copy and
    each look-alike must pass."""
    target = root / TARGET
    cases = [("the unplanted tree", None, "")]
    cases += [(name, edit, marker) for name, (edit, marker) in PLANTS.items()]
    cases += [(name, edit, "") for name, edit in LOOK_ALIKES.items()]
    failures = []
    for name, edit, marker in cases:
        tree = Path(tempfile.mkdtemp(prefix="package-check-"))
        try:
            committed(root, tree)
            if edit:
                edit(tree)
            status, output = package(tree, target)
        finally:
            shutil.rmtree(tree, ignore_errors=True)
        if marker and (status == 0 or marker not in output):
            failures.append(f"plant not refused for its cause: {name}: exit {status}: {output.strip()[-400:]}")
        if not marker and status != 0:
            failures.append(f"refused: {name}: exit {status}: {output.strip()[-400:]}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "selftest"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        if args.command == "selftest":
            found = selftest(args.root)
            detail = f"{len(PLANTS)} plants refused, {len(LOOK_ALIKES)} look-alike accepted"
        else:
            status, output = package(args.root, args.root / TARGET)
            found = [] if status == 0 else [f"{CRATE} does not build packed: exit {status}: {output.strip()[-1200:]}"]
            detail = f"{CRATE} builds from its packed sources"
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"PASS: package {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
