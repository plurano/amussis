#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Hold the committed WebAssembly module to the source it is built from.

bindings/go embeds the module of crates/amussis-decision-wasm, so a Go consumer
needs no Rust toolchain. A committed binary is only as good as the proof that
it is the build of the source beside it: this tool builds the module on the
pinned toolchain and compares it with the committed file byte for byte.

The build names no machine path. Three prefixes are rewritten (the standard
library source, the cargo home and the checkout), so two machines that build
the same commit get the same bytes; a module that still holds one of the three
is refused.

    check       build, then compare with the committed module; no network
    update      build, then replace the committed module
    selftest    plant one defect per rule and require each to be refused

Exit status: 0 equal, 1 the module differs, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

TARGET = "wasm32-unknown-unknown"
PROFILE = "wasm"
PACKAGE = "amussis-decision-wasm"
BUILT_NAME = "amussis_decision_wasm.wasm"
COMMITTED = "bindings/go/decision/amussis_decision.wasm"
MAGIC = b"\x00asm\x01\x00\x00\x00"
BUILD_DEADLINE_SECONDS = 900
QUERY_DEADLINE_SECONDS = 30
MAX_MODULE_BYTES = 4 * 1024 * 1024


class CheckError(Exception):
    """The check could not run; distinct from a module that differs."""


def run(args: list[str], root: Path, env: dict[str, str], deadline: int) -> str:
    try:
        done = subprocess.run(
            args, cwd=root, env=env, capture_output=True, text=True, timeout=deadline, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"{' '.join(args)} could not run: {error}") from error
    if done.returncode != 0:
        raise CheckError(f"{' '.join(args)} exited {done.returncode}:\n{done.stderr.strip()}")
    return done.stdout


def machine_prefixes(root: Path, env: dict[str, str]) -> list[tuple[Path, str]]:
    """Each path of this machine a build can embed, and the name it is given."""
    sysroot = Path(run(["rustc", "--print", "sysroot"], root, env, QUERY_DEADLINE_SECONDS).strip())
    version = run(["rustc", "-vV"], root, env, QUERY_DEADLINE_SECONDS)
    commits = [line.split(": ", 1)[1] for line in version.splitlines() if line.startswith("commit-hash: ")]
    if len(commits) != 1 or len(commits[0]) != 40:
        raise CheckError(f"rustc -vV names no commit hash:\n{version}")
    if not (sysroot / "lib" / "rustlib" / TARGET / "lib").is_dir():
        raise CheckError(
            f"the pinned toolchain has no {TARGET} target; install it with "
            f"`rustup target add {TARGET}` (the gate itself fetches nothing)"
        )
    cargo_home = Path(env.get("CARGO_HOME") or Path.home() / ".cargo")
    return [
        (sysroot / "lib" / "rustlib" / "src" / "rust", f"/rustc/{commits[0]}"),
        (cargo_home, "/cargo"),
        (root, "/amussis"),
    ]


def build(root: Path) -> tuple[bytes, list[bytes]]:
    """The module built from the tree, and the machine paths it must not hold."""
    env = dict(os.environ)
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    prefixes = machine_prefixes(root, env)
    env["RUSTFLAGS"] = " ".join(f"--remap-path-prefix={path}={name}" for path, name in prefixes)
    if any(" " in str(path) for path, _ in prefixes):
        raise CheckError("a machine path holds a space; RUSTFLAGS cannot carry it")
    cargo = ["cargo", "build", "--locked", "--offline", "-p", PACKAGE]
    run([*cargo, "--target", TARGET, "--profile", PROFILE], root, env, BUILD_DEADLINE_SECONDS)
    target_dir = Path(env.get("CARGO_TARGET_DIR") or root / "target")
    built = target_dir / TARGET / PROFILE / BUILT_NAME
    try:
        data = built.read_bytes()
    except OSError as error:
        raise CheckError(f"the build left no module at {built}: {error}") from error
    return data, [str(path).encode() for path, _ in prefixes]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def differences(built: bytes, committed: bytes | None, forbidden: list[bytes]) -> list[str]:
    """Every reason the committed module is not the build of this tree."""
    found = []
    if not built.startswith(MAGIC) or len(built) > MAX_MODULE_BYTES:
        found.append(f"the build is no WebAssembly module of at most {MAX_MODULE_BYTES} bytes")
    for path in forbidden:
        if path in built:
            found.append(f"the build holds the machine path {path.decode(errors='replace')}")
    if committed is None:
        found.append(f"{COMMITTED} is missing; write it with `tools/wasm_module.py update`")
    elif committed != built:
        found.append(
            f"{COMMITTED} ({len(committed)} bytes, sha256 {digest(committed)}) is not the build "
            f"of this tree ({len(built)} bytes, sha256 {digest(built)}); "
            "rebuild it with `tools/wasm_module.py update` and commit the result"
        )
    return found


def committed_module(root: Path) -> bytes | None:
    try:
        return (root / COMMITTED).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CheckError(f"cannot read {COMMITTED}: {error}") from error


def selftest(root: Path) -> tuple[list[str], int]:
    """Each plant must be refused, and for the reason it was planted for."""
    built, forbidden = build(root)
    committed = committed_module(root)
    failures = [f"the unplanted tree is refused: {line}" for line in differences(built, committed, forbidden)]
    middle = len(built) // 2
    flipped = built[:middle] + bytes([built[middle] ^ 1]) + built[middle + 1 :]
    plants = {
        "one bit of the committed module flipped": (built, flipped, "is not the build"),
        "committed module cut short": (built, built[:-1], "is not the build"),
        "committed module empty": (built, b"", "is not the build"),
        "committed module missing": (built, None, "is missing"),
        "build holds the checkout path": (built + forbidden[-1], built + forbidden[-1], "machine path"),
        "build holds the cargo home": (built + forbidden[1], built + forbidden[1], "machine path"),
        "build is no module": (b"\x7fELF" + built, b"\x7fELF" + built, "no WebAssembly module"),
    }
    for name, (planted_build, planted_committed, expected) in plants.items():
        found = differences(planted_build, planted_committed, forbidden)
        if not found:
            failures.append(f"plant passed: {name}")
        elif not any(expected in line for line in found):
            failures.append(f"plant refused for another reason: {name}: {found}")
    return failures, len(plants)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "update", "selftest"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.command == "selftest":
            found, count = selftest(root)
            detail = f"{count} plants refused"
        else:
            built, forbidden = build(root)
            if args.command == "update":
                (root / COMMITTED).parent.mkdir(parents=True, exist_ok=True)
                (root / COMMITTED).write_bytes(built)
            found = differences(built, committed_module(root), forbidden)
            detail = f"{len(built)} bytes, sha256 {digest(built)}"
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"PASS: module {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
