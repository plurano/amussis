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

A Windows host cannot build those bytes: rustc embeds the rest of each source
path with the host's separators, and six functions come out in another order.
On such a host the comparison is skipped for as long as exceptions.toml holds a
live entry for the module under the rule `module-byte-comparison`; the skip is
printed with the entry's reason. Every other rule still binds there, an entry
past its day excuses nothing, and an entry excuses nothing on a host whose
build equals the module.

    check       build, then compare with the committed module; no network
    update      build, then replace the committed module
    selftest    plant one defect per rule and require each to be refused

`--cargo-log FILE` writes cargo's record of the build to FILE: every compiler
call with its arguments, which is what two hosts are compared by when they
build other bytes. A build that compiled nothing records no call and is
refused, so the option needs an empty target directory.

Exit status: 0 equal, 1 the module differs, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import subprocess
import sys
from pathlib import Path

# The list of exceptions has one reader; both tools run from this directory.
import exceptions_check

TARGET = "wasm32-unknown-unknown"
PROFILE = "wasm"
PACKAGE = "amussis-decision-wasm"
BUILT_NAME = "amussis_decision_wasm.wasm"
# How cargo's verbose record names the compiler call that builds the module.
MODULE_CALL = "--crate-name amussis_decision_wasm "
COMMITTED = exceptions_check.MODULE
MAGIC = b"\x00asm\x01\x00\x00\x00"
BUILD_DEADLINE_SECONDS = 900
QUERY_DEADLINE_SECONDS = 30
MAX_MODULE_BYTES = 4 * 1024 * 1024
# The host triple of a toolchain that cannot build the committed bytes.
DIFFERING_HOST = "-windows-"


class CheckError(Exception):
    """The check could not run; distinct from a module that differs."""


def finished(
    args: list[str], root: Path, env: dict[str, str], deadline: int
) -> subprocess.CompletedProcess[str]:
    try:
        done = subprocess.run(
            args, cwd=root, env=env, capture_output=True, text=True, timeout=deadline, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"{' '.join(args)} could not run: {error}") from error
    if done.returncode != 0:
        raise CheckError(f"{' '.join(args)} exited {done.returncode}:\n{done.stderr.strip()}")
    return done


def run(args: list[str], root: Path, env: dict[str, str], deadline: int) -> str:
    return finished(args, root, env, deadline).stdout


def toolchain(root: Path, env: dict[str, str]) -> tuple[str, str]:
    """The commit and the host triple of the rustc that builds here."""
    version = run(["rustc", "-vV"], root, env, QUERY_DEADLINE_SECONDS)
    named = {}
    for line in version.splitlines():
        key, _, value = line.partition(": ")
        named.setdefault(key, []).append(value)
    commits, hosts = named.get("commit-hash", []), named.get("host", [])
    if len(commits) != 1 or len(commits[0]) != 40 or len(hosts) != 1 or not hosts[0]:
        raise CheckError(f"rustc -vV names no one commit hash and host:\n{version}")
    return commits[0], hosts[0]


def machine_prefixes(root: Path, env: dict[str, str], commit: str) -> list[tuple[Path, str]]:
    """Each path of this machine a build can embed, and the name it is given."""
    sysroot = Path(run(["rustc", "--print", "sysroot"], root, env, QUERY_DEADLINE_SECONDS).strip())
    if not (sysroot / "lib" / "rustlib" / TARGET / "lib").is_dir():
        raise CheckError(
            f"the pinned toolchain has no {TARGET} target; install it with "
            f"`rustup target add {TARGET}` (the gate itself fetches nothing)"
        )
    cargo_home = Path(env.get("CARGO_HOME") or Path.home() / ".cargo")
    return [
        (sysroot / "lib" / "rustlib" / "src" / "rust", f"/rustc/{commit}"),
        (cargo_home, "/cargo"),
        (root, "/amussis"),
    ]


def record_calls(log: Path, record: str) -> None:
    """Write cargo's record of the build; a record without the module's compiler call is refused."""
    if MODULE_CALL not in record:
        raise CheckError(
            f"the build compiled nothing, so its record names no compiler call of the module "
            f"({MODULE_CALL}); build into an empty target directory"
        )
    try:
        log.write_text(record, encoding="utf-8")
    except OSError as error:
        raise CheckError(f"cannot write {log}: {error}") from error


def build(root: Path, log: Path | None = None) -> tuple[bytes, list[bytes], str]:
    """The module built from the tree, the machine paths it must not hold, and the host triple."""
    env = dict(os.environ)
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    commit, host = toolchain(root, env)
    prefixes = machine_prefixes(root, env, commit)
    env["RUSTFLAGS"] = " ".join(f"--remap-path-prefix={path}={name}" for path, name in prefixes)
    if any(" " in str(path) for path, _ in prefixes):
        raise CheckError("a machine path holds a space; RUSTFLAGS cannot carry it")
    cargo = ["cargo", "build", "--locked", "--offline", "-p", PACKAGE, "--target", TARGET, "--profile", PROFILE]
    if log is None:
        run(cargo, root, env, BUILD_DEADLINE_SECONDS)
    else:
        record_calls(log, finished([*cargo, "--verbose"], root, env, BUILD_DEADLINE_SECONDS).stderr)
    target_dir = Path(env.get("CARGO_TARGET_DIR") or root / "target")
    built = target_dir / TARGET / PROFILE / BUILT_NAME
    try:
        data = built.read_bytes()
    except OSError as error:
        raise CheckError(f"the build left no module at {built}: {error}") from error
    return data, [str(path).encode() for path, _ in prefixes], host


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def excuse(root: Path, host: str) -> dict[str, str] | None:
    """The live exception of a host that cannot build the committed bytes, or None."""
    if DIFFERING_HOST not in host:
        return None
    today = datetime.datetime.now(datetime.UTC).date()
    try:
        return exceptions_check.live_exception(root, exceptions_check.COMPARED, COMMITTED, today)
    except exceptions_check.CheckError as error:
        raise CheckError(str(error)) from error


def build_faults(built: bytes, forbidden: list[bytes]) -> list[str]:
    """Every reason the build itself is refused, on any host."""
    found = []
    if not built.startswith(MAGIC) or len(built) > MAX_MODULE_BYTES:
        found.append(f"the build is no WebAssembly module of at most {MAX_MODULE_BYTES} bytes")
    for path in forbidden:
        if path in built:
            found.append(f"the build holds the machine path {path.decode(errors='replace')}")
    return found


def committed_fault(built: bytes, committed: bytes | None) -> str:
    """Why the committed module is not this build, or the empty string."""
    if committed is None:
        return f"{COMMITTED} is missing; write it with `tools/wasm_module.py update`"
    if committed != built:
        return (
            f"{COMMITTED} ({len(committed)} bytes, sha256 {digest(committed)}) is not the build "
            f"of this tree ({len(built)} bytes, sha256 {digest(built)}); "
            "rebuild it with `tools/wasm_module.py update` and commit the result"
        )
    return ""


def differences(
    built: bytes, committed: bytes | None, forbidden: list[bytes], excused: dict[str, str] | None
) -> tuple[list[str], str]:
    """Every reason the committed module is not the build of this tree, and the notice of a skipped comparison.

    `excused` is the live exception of a host that cannot build the committed
    bytes. It skips the comparison of two modules that differ and nothing
    else: a missing module and a faulty build are refused as on any host, and
    so is the exception itself once the build equals the module.
    """
    found = build_faults(built, forbidden)
    fault = committed_fault(built, committed)
    if excused is None or committed is None:
        return ([*found, fault] if fault else found), ""
    if not fault:
        nothing = f"{exceptions_check.LIST}: the entry for {COMMITTED} excuses nothing; this host builds the module"
        return [*found, nothing], ""
    notice = (
        f"the byte comparison of {COMMITTED} with this host's build ({len(built)} bytes, sha256 "
        f"{digest(built)}) is skipped until {excused['expires']}: {excused['reason']}"
    )
    return found, notice


def committed_module(root: Path) -> bytes | None:
    try:
        return (root / COMMITTED).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CheckError(f"cannot read {COMMITTED}: {error}") from error


def selftest(root: Path, built: bytes, forbidden: list[bytes]) -> tuple[list[str], int]:
    """Each plant must be refused, and for the reason it was planted for."""
    middle = len(built) // 2
    flipped = built[:middle] + bytes([built[middle] ^ 1]) + built[middle + 1 :]
    excused = {"reason": "planted reason", "expires": "9999-12-31"}
    plants = {
        "one bit of the committed module flipped": (built, flipped, None, "is not the build"),
        "committed module cut short": (built, built[:-1], None, "is not the build"),
        "committed module empty": (built, b"", None, "is not the build"),
        "committed module missing": (built, None, None, "is missing"),
        "build holds the checkout path": (built + forbidden[-1], built + forbidden[-1], None, "machine path"),
        "build holds the cargo home": (built + forbidden[1], built + forbidden[1], None, "machine path"),
        "build is no module": (b"\x7fELF" + built, b"\x7fELF" + built, None, "no WebAssembly module"),
        "excused host that builds the module": (built, built, excused, "excuses nothing"),
        "excused host, committed module missing": (built, None, excused, "is missing"),
        "excused host, build holds the checkout path": (built + forbidden[-1], flipped, excused, "machine path"),
        "excused host, build is no module": (b"\x7fELF" + built, flipped, excused, "no WebAssembly module"),
    }
    failures = []
    for name, (planted_build, planted_committed, planted_excuse, expected) in plants.items():
        found, _ = differences(planted_build, planted_committed, forbidden, planted_excuse)
        if not found:
            failures.append(f"plant passed: {name}")
        elif not any(expected in line for line in found):
            failures.append(f"plant refused for another reason: {name}: {found}")
    # The one skip there is: two modules that differ, on an excused host, and
    # the notice carries the entry's reason. No other host is ever excused.
    found, notice = differences(built, flipped, forbidden, excused)
    if found or excused["reason"] not in notice:
        failures.append(f"an excused host is refused, or skips without its reason: {found} {notice!r}")
    for host in ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin"):
        if excuse(root, host) is not None:
            failures.append(f"a host that builds the committed bytes is excused: {host}")
    return failures, len(plants) + 2


def report(command: str, found: list[str], notice: str, detail: str) -> int:
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    if notice:
        print(f"SKIPPED: {notice}")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::notice title=Module byte comparison skipped::{notice}")
    print(f"PASS: module {command} ({detail})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "update", "selftest"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--cargo-log", type=Path, help="write cargo's record of every compiler call here")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        built, forbidden, host = build(root, args.cargo_log)
        excused = excuse(root, host)
        if args.command == "update":
            if excused is not None:
                raise CheckError(f"a {host} host cannot build the committed bytes; update on Linux or macOS")
            (root / COMMITTED).parent.mkdir(parents=True, exist_ok=True)
            (root / COMMITTED).write_bytes(built)
        found, notice = differences(built, committed_module(root), forbidden, excused)
        detail = f"{len(built)} bytes, sha256 {digest(built)}, host {host}"
        if args.command == "selftest":
            failures, count = selftest(root, built, forbidden)
            found = [f"the unplanted tree is refused: {line}" for line in found] + failures
            detail = f"{count} plants refused"
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return report(args.command, found, notice, detail)


if __name__ == "__main__":
    sys.exit(main())
