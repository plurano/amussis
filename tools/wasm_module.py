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

Two hosts do not build those bytes byte for byte. On a Windows host rustc embeds
the rest of each source path with the host's separators, string-pool order and
panic Location pointers in the data section, and functions come out in another
order. On a macOS host only the order differs, and only for some lock files: it
follows values cargo derives on each host. When a host in DIFFERING_HOSTS builds
bytes that differ from the committed module, tools/module-compare
(amussis-module-compare) runs an order-free comparison. Code differences fail
on any host. On a macOS host an equal code and data section passes with a notice
("equal up to function order"); macOS needs no exception anymore. On a Windows
host, order-free code equivalence is held, and data section differences are
skipped only while exceptions.toml holds a live entry for the module under the
rule `module-byte-comparison`; an equal code and data build excuses nothing and
is refused. Every other host is held to the bytes.

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
import tempfile
from pathlib import Path

# The list of exceptions has one reader; both tools run from this directory.
import exceptions_check

TARGET = "wasm32-unknown-unknown"
PROFILE = "wasm"
PACKAGE = "amussis-decision-wasm"
COMPARE_PACKAGE = "amussis-module-compare"
BUILT_NAME = "amussis_decision_wasm.wasm"
# How cargo's verbose record names the compiler call that builds the module.
MODULE_CALL = "--crate-name amussis_decision_wasm "
COMMITTED = exceptions_check.MODULE
MAGIC = b"\x00asm\x01\x00\x00\x00"
BUILD_DEADLINE_SECONDS = 900
QUERY_DEADLINE_SECONDS = 30
MAX_MODULE_BYTES = 4 * 1024 * 1024
# The hosts whose toolchain does not build the committed bytes byte for byte,
# by a part of the host triple, and whether such a host requires an exception
# for its data section. A Windows host never builds the committed data section
# (separators, string-pool order, Location pointers), so it needs a live exception
# and an equal build refutes the entry. A macOS host builds identical code and data
# up to function order, so it is held order-free without an exception.
DIFFERING_HOSTS = {"-windows-": True, "-apple-darwin": False}


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


def build_env(root: Path) -> tuple[dict[str, str], list[bytes], str]:
    """The build environment with rewritten path prefixes, forbidden machine paths, and host triple."""
    env = dict(os.environ)
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    commit, host = toolchain(root, env)
    prefixes = machine_prefixes(root, env, commit)
    env["RUSTFLAGS"] = " ".join(f"--remap-path-prefix={path}={name}" for path, name in prefixes)
    if any(" " in str(path) for path, _ in prefixes):
        raise CheckError("a machine path holds a space; RUSTFLAGS cannot carry it")
    return env, [str(path).encode() for path, _ in prefixes], host


def built_path(root: Path, env: dict[str, str]) -> Path:
    """The path where cargo places the compiled WebAssembly module."""
    target_dir = Path(env.get("CARGO_TARGET_DIR") or root / "target")
    return target_dir / TARGET / PROFILE / BUILT_NAME


def build(root: Path, log: Path | None = None) -> tuple[bytes, list[bytes], str]:
    """The module built from the tree, the machine paths it must not hold, and the host triple."""
    env, forbidden, host = build_env(root)
    cargo = ["cargo", "build", "--locked", "--offline", "-p", PACKAGE, "--target", TARGET, "--profile", PROFILE]
    if log is None:
        run(cargo, root, env, BUILD_DEADLINE_SECONDS)
    else:
        record_calls(log, finished([*cargo, "--verbose"], root, env, BUILD_DEADLINE_SECONDS).stderr)
    built = built_path(root, env)
    try:
        data = built.read_bytes()
    except OSError as error:
        raise CheckError(f"the build left no module at {built}: {error}") from error
    return data, forbidden, host


def run_comparator(
    root: Path, committed_path: Path, built_target: Path, env: dict[str, str], deadline: int
) -> str:
    """Run amussis-module-compare and return stdout; exit 0 or 1 is normal comparison output."""
    cargo = [
        "cargo",
        "run",
        "--locked",
        "--offline",
        "-q",
        "-p",
        COMPARE_PACKAGE,
        "--",
        str(committed_path),
        str(built_target),
    ]
    try:
        done = subprocess.run(
            cargo, cwd=root, env=env, capture_output=True, text=True, timeout=deadline, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"{' '.join(cargo)} could not run: {error}") from error
    if done.returncode not in (0, 1):
        raise CheckError(f"{' '.join(cargo)} exited {done.returncode}:\n{done.stderr.strip()}")
    return done.stdout


def parse_verdict(output: str) -> tuple[bool, bool, str]:
    """Parse comparator output into (code_equal, data_equal, verdict_line)."""
    verdict_line = ""
    for line in output.splitlines():
        if line.startswith("verdict:"):
            verdict_line = line
    if not verdict_line:
        raise CheckError(f"comparator produced no verdict line:\n{output.strip()}")
    code_equal = "code equal" in verdict_line
    data_equal = "data equal" in verdict_line
    return code_equal, data_equal, verdict_line


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def never_equal(host: str) -> bool | None:
    """Whether `host` never builds the committed bytes; None for a host that is held to them."""
    for part, never in DIFFERING_HOSTS.items():
        if part in host:
            return never
    return None


def excuse(root: Path, host: str) -> dict[str, str] | None:
    """The live exception of a host that does not build the committed bytes, or None."""
    if never_equal(host) is not True:
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


def evaluate_verdict(
    built: bytes,
    verdict: str,
    excused: dict[str, str] | None,
    never: bool,
) -> tuple[list[str], str]:
    """Evaluate comparator verdict on a differing host."""
    code_equal, data_equal, line = parse_verdict(verdict)
    if not code_equal:
        return [f"{COMMITTED}: code differs from this host's build ({line})"], ""
    if not never:
        # macOS host: held order-free for both code and data without exception
        if not data_equal:
            return [f"{COMMITTED}: data section differs from this host's build ({line})"], ""
        return [], f"equal up to function order ({COMMITTED})"
    # Windows host: code held order-free; data section excused while live entry exists
    if not data_equal:
        if excused is None:
            return [
                f"{COMMITTED}: data section differs from this host's build without a live exception ({line})"
            ], ""
        notice = (
            f"the byte comparison of {COMMITTED} with this host's build ({len(built)} bytes, sha256 "
            f"{digest(built)}) is skipped until {excused['expires']}: {excused['reason']}"
        )
        return [], notice
    # code equal + data equal on Windows
    nothing = f"{exceptions_check.LIST}: the entry for {COMMITTED} excuses nothing; this host builds the module"
    return [nothing], ""


def differences(
    built: bytes,
    committed: bytes | None,
    forbidden: list[bytes],
    excused: dict[str, str] | None,
    never: bool | None,
    verdict: str | None = None,
) -> tuple[list[str], str]:
    """Every reason the committed module is not the build of this tree, and the notice of a skipped comparison."""
    found = build_faults(built, forbidden)
    if committed is None:
        missing = f"{COMMITTED} is missing; write it with `tools/wasm_module.py update`"
        return [*found, missing], ""
    if built == committed:
        if never is True:
            nothing = f"{exceptions_check.LIST}: the entry for {COMMITTED} excuses nothing; this host builds the module"
            return [*found, nothing], ""
        return found, ""
    if found:
        return found, ""
    if never is None:
        return [*found, committed_fault(built, committed)], ""
    if verdict is None:
        raise CheckError("comparator verdict required when built != committed on a differing host")
    eval_found, notice = evaluate_verdict(built, verdict, excused, never)
    return [*found, *eval_found], notice


def committed_module(root: Path) -> bytes | None:
    try:
        return (root / COMMITTED).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CheckError(f"cannot read {COMMITTED}: {error}") from error


# What `never_equal` must answer for a host triple: the rule of the hosts.
HOST_RULE = {
    "x86_64-unknown-linux-gnu": None,
    "aarch64-unknown-linux-gnu": None,
    "x86_64-pc-windows-msvc": True,
    "aarch64-apple-darwin": False,
    "x86_64-apple-darwin": False,
}


def skip_failures(built: bytes, flipped: bytes, forbidden: list[bytes], excused: dict[str, str]) -> list[str]:
    """The skips there are, and the hosts they are for; anything else is a failure of the selftest."""
    failures = []
    # Windows host with data difference: skipped, and the notice carries the entry's reason.
    found, notice = differences(
        built, flipped, forbidden, excused, True, verdict="verdict: code equal, data differ (251 bytes)"
    )
    if found or excused["reason"] not in notice:
        failures.append(f"a Windows host with data difference is refused, or skips without reason: {found} {notice!r}")
    # macOS host that builds code equal + data equal: passes with notice.
    found, notice = differences(
        built, flipped, forbidden, None, False, verdict="verdict: code equal, data equal"
    )
    if found or "equal up to function order" not in notice:
        failures.append(f"a macOS host with code+data equal is refused or lacks notice: {found} {notice!r}")
    # A macOS host that builds byte-for-byte equal module: passes, no skip notice.
    found, notice = differences(built, built, forbidden, None, False)
    if found or notice:
        failures.append(f"a macOS host that builds identical bytes is refused or announces a skip: {found} {notice!r}")
    for host, expected in HOST_RULE.items():
        if never_equal(host) is not expected:
            failures.append(f"the host rule answers {never_equal(host)} for {host}, not {expected}")
    return failures


def section_span(module: bytes, section_id: int) -> tuple[int, int] | None:
    """The (start, end) byte span of a section payload in module, or None if absent."""
    if module[:8] != MAGIC:
        raise CheckError("invalid WebAssembly header")
    offset = 8
    for _ in range(65536):
        if offset >= len(module):
            return None
        sec_id = module[offset]
        offset += 1
        size = 0
        shift = 0
        for _ in range(5):
            if offset >= len(module):
                raise CheckError("truncated LEB128 section size in module")
            byte = module[offset]
            offset += 1
            size |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        else:
            raise CheckError("LEB128 section size with more than 5 bytes")
        if offset + size > len(module):
            raise CheckError("section extends beyond end of module")
        if sec_id == section_id:
            return offset, offset + size
        offset += size
    return None


def real_comparator_failures(root: Path) -> list[str]:
    """Runs the real comparator tool once on committed vs flipped-byte module."""
    committed = committed_module(root)
    if committed is None:
        return [f"{COMMITTED} is missing"]
    span = section_span(committed, 11)
    if span is None or span[0] == span[1]:
        return ["committed module contains no data section (section 11)"]

    flipped_data = bytearray(committed)
    flipped_data[span[1] - 1] ^= 1

    with tempfile.TemporaryDirectory(prefix="wasm-module-selftest-") as scratch:
        c_path = Path(scratch) / "committed.wasm"
        f_path = Path(scratch) / "flipped.wasm"
        c_path.write_bytes(committed)
        f_path.write_bytes(flipped_data)
        env, _, _ = build_env(root)
        verdict = run_comparator(root, c_path, f_path, env, BUILD_DEADLINE_SECONDS)
        if "code equal" not in verdict or "data differ" not in verdict:
            return [f"real comparator run did not report 'code equal' and 'data differ': {verdict!r}"]
    return []


def section_span_failures(root: Path) -> list[str]:
    """Verifies section_span on header-only module, truncated LEB, and committed module."""
    failures = []
    if section_span(MAGIC, 11) is not None:
        failures.append("section_span on header-only module did not return None")
    try:
        section_span(MAGIC + b"\x0b\x80", 11)
        failures.append("section_span on truncated LEB did not raise CheckError")
    except CheckError:
        pass
    try:
        section_span(MAGIC + b"\x0b\x80\x80\x80\x80\x80", 11)
        failures.append("section_span on 5-byte continuation LEB did not raise CheckError")
    except CheckError:
        pass
    committed = committed_module(root)
    if committed is None:
        failures.append(f"{COMMITTED} is missing")
    else:
        span = section_span(committed, 11)
        if span is None or not (8 <= span[0] < span[1] <= len(committed)):
            failures.append(f"section_span on committed module returned invalid span: {span}")
    return failures


def selftest(root: Path, built: bytes, forbidden: list[bytes]) -> tuple[list[str], int]:
    """Each plant must be refused, and for the reason it was planted for."""
    middle = len(built) // 2
    flipped = built[:middle] + bytes([built[middle] ^ 1]) + built[middle + 1 :]
    excused = {"reason": "planted reason", "expires": "9999-12-31"}
    path, elf = built + forbidden[-1], b"\x7fELF" + built
    plants = {
        "one bit of the committed module flipped": (built, flipped, None, None, None, "is not the build"),
        "committed module cut short": (built, built[:-1], None, None, None, "is not the build"),
        "committed module empty": (built, b"", None, None, None, "is not the build"),
        "committed module missing": (built, None, None, None, None, "is missing"),
        "build holds the checkout path": (path, path, None, None, None, "machine path"),
        "build holds the cargo home": (built + forbidden[1], built + forbidden[1], None, None, None, "machine path"),
        "build is no module": (elf, elf, None, None, None, "no WebAssembly module"),
        "Windows host that builds the module byte-for-byte": (built, built, excused, True, None, "excuses nothing"),
        "Windows host, committed module missing": (built, None, excused, True, None, "is missing"),
        "Windows host, build holds the checkout path": (path, flipped, excused, True, None, "machine path"),
        "Windows host, build is no module": (elf, flipped, excused, True, None, "no WebAssembly module"),
        "Windows host, code differ": (built, flipped, excused, True, "verdict: code differ, data equal", "code differs"),
        "Windows host, data differ without entry": (
            built,
            flipped,
            None,
            True,
            "verdict: code equal, data differ (251 bytes)",
            "without a live exception",
        ),
        "Windows host, code and data equal": (
            built,
            flipped,
            excused,
            True,
            "verdict: code equal, data equal",
            "excuses nothing",
        ),
        "macOS host, committed module missing": (built, None, None, False, None, "is missing"),
        "macOS host, build holds the checkout path": (path, flipped, None, False, None, "machine path"),
        "macOS host, build is no module": (elf, flipped, None, False, None, "no WebAssembly module"),
        "macOS host, code differ": (built, flipped, None, False, "verdict: code differ, data equal", "code differs"),
        "macOS host, data differ": (
            built,
            flipped,
            None,
            False,
            "verdict: code equal, data differ (1 byte)",
            "data section differs",
        ),
    }
    failures = []
    for name, (planted_build, planted_committed, planted_excuse, never, verdict, expected) in plants.items():
        found, _ = differences(planted_build, planted_committed, forbidden, planted_excuse, never, verdict=verdict)
        if not found:
            failures.append(f"plant passed: {name}")
        elif not any(expected in line for line in found):
            failures.append(f"plant refused for another reason: {name}: {found}")
    failures += skip_failures(built, flipped, forbidden, excused)
    failures += real_comparator_failures(root)
    failures += section_span_failures(root)
    return failures, len(plants) + 3 + len(HOST_RULE) + 1 + 3


def report(command: str, found: list[str], notice: str, detail: str) -> int:
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    if notice:
        if "equal up to function order" in notice:
            print(f"NOTICE: {notice}")
            if os.environ.get("GITHUB_ACTIONS") == "true":
                print(f"::notice title=Module order-free comparison::{notice}")
        else:
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
        excused, never = excuse(root, host), never_equal(host)
        if args.command == "update":
            if never is not None:
                raise CheckError(f"a {host} host does not build the committed bytes; update on a Linux x86_64 host")
            (root / COMMITTED).parent.mkdir(parents=True, exist_ok=True)
            (root / COMMITTED).write_bytes(built)
        committed = committed_module(root)
        verdict = None
        if never is not None and committed is not None and built != committed:
            env, _, _ = build_env(root)
            built_file = built_path(root, env)
            committed_path = root / COMMITTED
            verdict = run_comparator(root, committed_path, built_file, env, BUILD_DEADLINE_SECONDS)
        found, notice = differences(built, committed, forbidden, excused, never, verdict=verdict)
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
