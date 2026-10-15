#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Hold the Go that runs the binding's tests to the Go the binding declares.

The binding's go.mod names the oldest Go release it supports (`go 1.27`). CI
installs the Go that the engine's go.mod declares, because the engine is
built with it, and runs the binding's tests on that Go. While both name the
same release the binding is tested on its minimum; once the engine moves on,
nothing would show that the binding is no longer. This compares the release
of the running Go with the `go` line of every Go module the gate tests:

    check       `go env GOVERSION` (GOTOOLCHAIN=local) names the major.minor
                release of each module's `go` line; the patch level may differ
    selftest    plant one mismatch per form and require each to fail; require
                patch levels and build suffixes to pass

Exit status: 0 the releases are equal, 1 they differ or one cannot be read,
2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

from toolkit import CheckError

MODULES = ("bindings/go/go.mod", "examples/go-consumer/go.mod")
DIRECTIVE = re.compile(r"^go (\d+)\.(\d+)(?:\.\d+)?$")
GOVERSION = re.compile(r"^go(\d+)\.(\d+)(?:\.\d+)?(?:[-+ ].*)?$")
DEADLINE_SECONDS = 60


def directive(text: str) -> tuple[int, int] | None:
    """The release of the `go` line of a go.mod, or None for no such line."""
    for line in text.splitlines():
        match = DIRECTIVE.match(line.strip())
        if match:
            return int(match.group(1)), int(match.group(2))
    return None


def findings(declared: dict[str, str], goversion: str) -> list[str]:
    """Each module whose `go` line names another release than goversion."""
    match = GOVERSION.match(goversion.strip())
    if not match:
        return [f"the running Go names no release: {goversion.strip()!r}"]
    running = (int(match.group(1)), int(match.group(2)))
    found = []
    for name, text in declared.items():
        release = directive(text)
        if release is None:
            found.append(f"{name}: no `go` line")
        elif release != running:
            found.append(f"{name}: declares go {release[0]}.{release[1]}, "
                         f"the tests run on {goversion.strip()}")
    return found


def running_go() -> str:
    env = dict(os.environ, GOTOOLCHAIN="local")
    try:
        done = subprocess.run(["go", "env", "GOVERSION"], env=env, capture_output=True,
                              text=True, timeout=DEADLINE_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"go env GOVERSION: {error}") from error
    if done.returncode != 0:
        raise CheckError(f"go env GOVERSION exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout


def check(root: Path) -> list[str]:
    declared = {}
    for name in MODULES:
        try:
            declared[name] = (root / name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise CheckError(f"cannot read {name}: {error}") from error
    return findings(declared, running_go())


BINDING = "module example\n\ngo 1.27\n"

PLANTS = {
    "a newer release runs the tests": ({"go.mod": BINDING}, "go1.28.0"),
    "an older release runs the tests": ({"go.mod": BINDING}, "go1.26.9"),
    "a newer major release runs the tests": ({"go.mod": BINDING}, "go2.27.0"),
    "the running Go names no release": ({"go.mod": BINDING}, "devel go1.28-0123abcd"),
    "a module without a go line": ({"go.mod": "module example\n"}, "go1.27.1"),
    "a second module declares another release": (
        {"go.mod": BINDING, "consumer/go.mod": "module consumer\n\ngo 1.28\n"}, "go1.27.1"),
}

LOOK_ALIKES = {
    "a patch level on the running Go": ({"go.mod": BINDING}, "go1.27.2"),
    "a build suffix on the running Go": ({"go.mod": BINDING}, "go1.27.1-X:nodwarf5\n"),
    "a patch level on the go line": ({"go.mod": "module example\n\ngo 1.27.0\n"}, "go1.27.1"),
    "a toolchain line beside the go line": (
        {"go.mod": "module example\n\ngo 1.27\n\ntoolchain go1.28.1\n"}, "go1.27.1"),
}


def selftest() -> list[str]:
    failures = [f"plant passed: {name}" for name, (declared, goversion) in PLANTS.items()
                if not findings(declared, goversion)]
    failures += [f"look-alike refused: {name}: {findings(declared, goversion)[0]}"
                 for name, (declared, goversion) in LOOK_ALIKES.items()
                 if findings(declared, goversion)]
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "selftest"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        if args.command == "selftest":
            found = selftest()
            detail = f"{len(PLANTS)} plants refused, {len(LOOK_ALIKES)} look-alikes accepted"
        else:
            found = check(args.root)
            detail = f"{len(MODULES)} modules declare the release of the running Go"
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"PASS: Go minimum {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
