#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Regenerate generated repository files and write an artifact manifest.

When runtime dependencies are bumped on renovate branches, generated files
(the WebAssembly module and its third-party notices) must be updated to match
the new build. This tool executes the individual update commands, verifies that
no unexpected files were modified or deleted, and writes a directory containing
the regenerated files and a manifest describing them.

    write       run update commands, verify changes, and write artifact to --out
    check       hold the table below to the declared list .github/generated-files
    selftest    verify plant refusals and accepted cases on a fixture repository

The merge train of plurano/horistes commits the artifact to the dependency
update; it reads .github/generated-files from the default branch and commits
no path missing there, so that file and GENERATED must name the same paths.

Exit status: 0 success or nothing to regenerate, 1 unexpected changes or
generated file deleted, 2 the tool could not run or command failed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from toolkit import CheckError

WASM_PATH = "bindings/go/decision/amussis_decision.wasm"
NOTICES_PATH = "bindings/go/decision/THIRD-PARTY-NOTICES.txt"

GENERATED: dict[str, list[str]] = {
    WASM_PATH: [sys.executable, "-B", "tools/wasm_module.py", "update"],
    NOTICES_PATH: [sys.executable, "-B", "tools/third_party_notices.py", "update"],
}
SCHEMA = "horistes.generated-files.v1"
DECLARED = ".github/generated-files"
MODULE_TIMEOUT_SECONDS = 1200
DEFAULT_TIMEOUT_SECONDS = 300
GIT_TIMEOUT_SECONDS = 60
MAX_STATUS_ENTRIES = 2048


def declared_paths(text: str) -> list[str]:
    """The paths of a .github/generated-files text: no comments, no blank lines."""
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def check_declared(root: Path, commands: dict[str, list[str]] = GENERATED) -> list[str]:
    try:
        text = (root / DECLARED).read_text(encoding="utf-8")
    except OSError as error:
        raise CheckError(f"{DECLARED} could not be read: {error}") from error
    listed = declared_paths(text)
    if sorted(listed) != sorted(commands) or len(listed) != len(set(listed)):
        return [f"{DECLARED} names {sorted(listed)}, the table names {sorted(commands)}"]
    return []


def run_git(args: list[str], root: Path, timeout: int = GIT_TIMEOUT_SECONDS) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"git {' '.join(args)} could not run: {error}") from error
    if proc.returncode != 0:
        err = proc.stderr.strip()
        raise CheckError(f"git {' '.join(args)} exited {proc.returncode}: {err}")
    return proc.stdout


def git_status_bytes(root: Path, timeout: int = GIT_TIMEOUT_SECONDS) -> bytes:
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z"],
            cwd=root,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"git status could not run: {error}") from error
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")
        raise CheckError(f"git status exited {proc.returncode}: {err}")
    return proc.stdout


def parse_status_entries(raw: bytes) -> list[tuple[str, str, str | None]]:
    if not raw:
        return []
    tokens = raw.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    entries: list[tuple[str, str, str | None]] = []
    idx = 0
    bound = min(len(tokens), MAX_STATUS_ENTRIES)
    for _ in range(bound):
        if idx >= len(tokens):
            break
        item = tokens[idx]
        idx += 1
        if len(item) < 3:
            continue
        code = item[:2].decode("ascii", errors="replace")
        path = item[3:].decode("utf-8", errors="replace")
        orig_path = None
        if "R" in code or "C" in code:
            if idx < len(tokens):
                orig_path = tokens[idx].decode("utf-8", errors="replace")
                idx += 1
        entries.append((code, path, orig_path))
    return entries


def evaluate_changes(
    entries: list[tuple[str, str, str | None]],
    root: Path,
    allowed: set[str],
) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    changed: list[str] = []
    for code, path, orig in entries:
        if path not in allowed:
            failures.append(f"unexpected changed path: {path}")
        if orig is not None and orig not in allowed:
            failures.append(f"unexpected changed path: {orig}")
        if "D" in code or not (root / path).is_file():
            if path in allowed:
                failures.append(f"generated path was deleted: {path}")
        elif path in allowed:
            changed.append(path)
    return failures, sorted(set(changed))


def run_update_command(cmd: list[str], root: Path, timeout: int) -> None:
    try:
        proc = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise CheckError(f"{' '.join(cmd)} timed out after {timeout} s") from error
    except OSError as error:
        raise CheckError(f"{' '.join(cmd)} could not run: {error}") from error
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip()
        raise CheckError(f"{' '.join(cmd)} exited {proc.returncode}:\n{err}")


def command_timeout(path: str, cmd: list[str]) -> int:
    if path.endswith(".wasm") or any("wasm_module.py" in arg for arg in cmd):
        return MODULE_TIMEOUT_SECONDS
    return DEFAULT_TIMEOUT_SECONDS


def format_command(cmd: list[str]) -> list[str]:
    return ["python3" if arg == sys.executable else arg for arg in cmd]


def build_manifest(head: str, files: list[dict[str, Any]], commands: list[list[str]]) -> str:
    manifest = {
        "commands": [format_command(cmd) for cmd in commands],
        "files": sorted(files, key=lambda item: item["path"]),
        "head": head,
        "schema": SCHEMA,
    }
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def write_regenerated(
    out: Path,
    root: Path,
    commands: dict[str, list[str]] = GENERATED,
) -> tuple[list[str], str | None]:
    head = run_git(["rev-parse", "HEAD"], root).strip()
    if len(head) != 40 or not all(c in "0123456789abcdefABCDEF" for c in head):
        raise CheckError(f"git rev-parse HEAD returned invalid commit: {head!r}")
    if git_status_bytes(root):
        raise CheckError("working tree is dirty before regeneration")
    executed: list[list[str]] = []
    for path, cmd in commands.items():
        timeout = command_timeout(path, cmd)
        run_update_command(cmd, root, timeout)
        executed.append(cmd)
    raw_status = git_status_bytes(root)
    if not raw_status:
        return [], "nothing to regenerate"
    entries = parse_status_entries(raw_status)
    failures, changed = evaluate_changes(entries, root, set(commands))
    if failures:
        return failures, None
    if not changed:
        return [], "nothing to regenerate"
    file_records: list[dict[str, Any]] = []
    for path_str in changed:
        src = root / path_str
        dst = out / "files" / path_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        dst.write_bytes(data)
        file_records.append({
            "bytes": len(data),
            "path": path_str,
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    manifest_text = build_manifest(head, file_records, executed)
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(manifest_text, encoding="utf-8")
    return [], f"{len(file_records)} files at {head}"


def setup_fixture_repo(repo: Path) -> str:
    run_git(["init"], repo)
    run_git(["config", "user.name", "Amussis Tester"], repo)
    run_git(["config", "user.email", "test@example.com"], repo)
    (repo / ".gitignore").write_text("target/\n", encoding="utf-8")
    (repo / "tracked.txt").write_text("tracked fixture\n", encoding="utf-8")
    wasm_file = repo / WASM_PATH
    wasm_file.parent.mkdir(parents=True, exist_ok=True)
    wasm_file.write_bytes(b"\x00asm\x01\x00\x00\x00original-wasm")
    notices_file = repo / NOTICES_PATH
    notices_file.write_text("original notices\n", encoding="utf-8")
    run_git(["add", "."], repo)
    run_git(["commit", "-m", "initial fixture"], repo)
    return run_git(["rev-parse", "HEAD"], repo).strip()


def reset_fixture_repo(repo: Path) -> None:
    run_git(["reset", "--hard", "HEAD"], repo)
    run_git(["clean", "-fdx"], repo)


def run_plant_cases_ab(repo: Path, temp_dir: Path) -> list[str]:
    failures: list[str] = []
    # (a) command edits a non-generated tracked file
    reset_fixture_repo(repo)
    out_a = temp_dir / "out-a"
    cmd_a = {
        WASM_PATH: [
            sys.executable,
            "-c",
            "import pathlib; pathlib.Path('tracked.txt').write_text('dirty\\n')",
        ]
    }
    fails, _ = write_regenerated(out_a, repo, cmd_a)
    if not fails or not any("tracked.txt" in f for f in fails):
        failures.append(f"plant (a) not refused with tracked.txt: {fails}")
    if (out_a / "manifest.json").exists():
        failures.append("plant (a) wrote manifest.json")

    # (b) command creates an untracked non-generated file
    reset_fixture_repo(repo)
    out_b = temp_dir / "out-b"
    cmd_b = {
        WASM_PATH: [
            sys.executable,
            "-c",
            "import pathlib; pathlib.Path('untracked.txt').write_text('new\\n')",
        ]
    }
    fails, _ = write_regenerated(out_b, repo, cmd_b)
    if not fails or not any("untracked.txt" in f for f in fails):
        failures.append(f"plant (b) not refused with untracked.txt: {fails}")
    if (out_b / "manifest.json").exists():
        failures.append("plant (b) wrote manifest.json")

    return failures


def run_plant_case_c(repo: Path, temp_dir: Path) -> list[str]:
    failures: list[str] = []
    # (c) command deletes a generated file
    reset_fixture_repo(repo)
    out_c = temp_dir / "out-c"
    cmd_c = {
        WASM_PATH: [
            sys.executable,
            "-c",
            f"import pathlib; pathlib.Path({WASM_PATH!r}).unlink()",
        ]
    }
    fails, _ = write_regenerated(out_c, repo, cmd_c)
    if not fails or not any(WASM_PATH in f for f in fails):
        failures.append(f"plant (c) not refused with deleted generated file: {fails}")
    if (out_c / "manifest.json").exists():
        failures.append("plant (c) wrote manifest.json")
    return failures


def run_plant_cases_de(repo: Path, temp_dir: Path) -> list[str]:
    failures: list[str] = []
    # (d) command exits 1
    reset_fixture_repo(repo)
    out_d = temp_dir / "out-d"
    cmd_d = {WASM_PATH: [sys.executable, "-c", "import sys; sys.exit(1)"]}
    refused_d = False
    try:
        write_regenerated(out_d, repo, cmd_d)
    except CheckError as error:
        if "sys.exit(1)" in str(error):
            refused_d = True
        else:
            failures.append(f"plant (d) error did not name command: {error}")
    if not refused_d:
        failures.append("plant (d) command exit 1 was not refused")
    if (out_d / "manifest.json").exists():
        failures.append("plant (d) wrote manifest.json")

    # (e) tree dirty before run
    reset_fixture_repo(repo)
    (repo / "dirty_pre.txt").write_text("pre-existing dirty file\n")
    out_e = temp_dir / "out-e"
    cmd_e = {WASM_PATH: [sys.executable, "-c", ""]}
    refused_e = False
    try:
        write_regenerated(out_e, repo, cmd_e)
    except CheckError as error:
        if "dirty" in str(error):
            refused_e = True
        else:
            failures.append(f"plant (e) error did not mention dirty: {error}")
    if not refused_e:
        failures.append("plant (e) dirty tree was not refused")
    if (out_e / "manifest.json").exists():
        failures.append("plant (e) wrote manifest.json")

    return failures


def run_plant_cases(repo: Path, temp_dir: Path) -> list[str]:
    failures = run_plant_cases_ab(repo, temp_dir)
    failures.extend(run_plant_case_c(repo, temp_dir))
    failures.extend(run_plant_cases_de(repo, temp_dir))
    return failures


def run_accepted_case_f(repo: Path, temp_dir: Path, head: str) -> list[str]:
    failures: list[str] = []
    # (f) command rewrites a generated file
    reset_fixture_repo(repo)
    out_f = temp_dir / "out-f"
    new_wasm = b"\x00asm\x01\x00\x00\x00new-wasm-bytes"
    cmd_f = {
        WASM_PATH: [
            sys.executable,
            "-c",
            f"import pathlib; pathlib.Path({WASM_PATH!r}).write_bytes({new_wasm!r})",
        ],
        NOTICES_PATH: [sys.executable, "-c", ""],
    }
    fails, _ = write_regenerated(out_f, repo, cmd_f)
    if fails:
        failures.append(f"case (f) unexpectedly failed: {fails}")
    manifest_file = out_f / "manifest.json"
    if not manifest_file.exists():
        failures.append("case (f) manifest.json missing")
        return failures
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    if manifest_data.get("schema") != SCHEMA:
        failures.append(f"case (f) bad schema: {manifest_data.get('schema')}")
    if manifest_data.get("head") != head:
        failures.append(f"case (f) bad head: {manifest_data.get('head')} != {head}")
    manifest_files = manifest_data.get("files", [])
    if len(manifest_files) != 1:
        failures.append(f"case (f) expected 1 file in manifest, got {len(manifest_files)}")
    elif manifest_files[0]["path"] != WASM_PATH:
        failures.append(f"case (f) wrong path: {manifest_files[0]['path']}")
    elif manifest_files[0]["sha256"] != hashlib.sha256(new_wasm).hexdigest():
        failures.append("case (f) sha256 mismatch")
    elif manifest_files[0]["bytes"] != len(new_wasm):
        failures.append("case (f) bytes mismatch")
    copied = out_f / "files" / WASM_PATH
    if not copied.exists() or copied.read_bytes() != new_wasm:
        failures.append("case (f) copied file mismatch")
    expected_text = json.dumps(manifest_data, indent=2, sort_keys=True) + "\n"
    if manifest_file.read_text(encoding="utf-8") != expected_text:
        failures.append("case (f) manifest JSON not formatted deterministically")
    return failures


def run_accepted_cases_gh(repo: Path, temp_dir: Path) -> list[str]:
    failures: list[str] = []
    # (g) command writes nothing
    reset_fixture_repo(repo)
    out_g = temp_dir / "out-g"
    cmd_g = {
        WASM_PATH: [sys.executable, "-c", ""],
        NOTICES_PATH: [sys.executable, "-c", ""],
    }
    fails, msg = write_regenerated(out_g, repo, cmd_g)
    if fails:
        failures.append(f"case (g) unexpectedly failed: {fails}")
    if msg != "nothing to regenerate":
        failures.append(f"case (g) expected 'nothing to regenerate', got {msg!r}")
    if (out_g / "manifest.json").exists() or (out_g / "files").exists():
        failures.append("case (g) wrote output to DIR")

    # (h) command writes under ignored target/
    reset_fixture_repo(repo)
    out_h = temp_dir / "out-h"
    cmd_h = {
        WASM_PATH: [
            sys.executable,
            "-c",
            "import pathlib; p = pathlib.Path('target/t.txt'); "
            "p.parent.mkdir(parents=True, exist_ok=True); p.write_text('build\\n')",
        ],
        NOTICES_PATH: [sys.executable, "-c", ""],
    }
    fails, msg = write_regenerated(out_h, repo, cmd_h)
    if fails:
        failures.append(f"case (h) unexpectedly failed: {fails}")
    if msg != "nothing to regenerate":
        failures.append(f"case (h) expected 'nothing to regenerate', got {msg!r}")
    if (out_h / "manifest.json").exists() or (out_h / "files").exists():
        failures.append("case (h) wrote output to DIR")

    return failures


def run_accepted_cases(repo: Path, temp_dir: Path, head: str) -> list[str]:
    failures = run_accepted_case_f(repo, temp_dir, head)
    failures.extend(run_accepted_cases_gh(repo, temp_dir))
    return failures


def run_declared_cases(repo: Path) -> list[str]:
    """A declared list equal to the table passes; a missing or extra path is refused."""
    failures: list[str] = []
    cases = (
        (f"# comment\n\n{WASM_PATH}\n{NOTICES_PATH}\n", False),
        (f"{WASM_PATH}\n", True),
        (f"{WASM_PATH}\n{NOTICES_PATH}\ntracked.txt\n", True),
    )
    for text, refused in cases:
        (repo / ".github").mkdir(exist_ok=True)
        (repo / DECLARED).write_text(text, encoding="utf-8")
        found = check_declared(repo)
        if bool(found) != refused:
            failures.append(f"declared list {text!r}: refused={bool(found)}, expected {refused}")
    return failures


def selftest(root: Path | None = None) -> tuple[list[str], int, int]:
    del root
    with tempfile.TemporaryDirectory(prefix="amussis-regen-selftest-") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        repo = temp_dir / "repo"
        repo.mkdir()
        head = setup_fixture_repo(repo)
        failures = run_plant_cases(repo, temp_dir)
        failures.extend(run_accepted_cases(repo, temp_dir, head))
        failures.extend(run_declared_cases(repo))
        return failures, 7, 4


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("command", choices=("write", "check", "selftest"))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.command == "selftest":
            failures, refused, accepted = selftest(root)
            for failure in failures:
                print(f"FAIL: {failure}", file=sys.stderr)
            if failures:
                return 1
            print(f"PASS: regenerate selftest ({refused} plants refused, {accepted} accepted)")
            return 0
        if args.command == "check":
            failures = check_declared(root)
            for failure in failures:
                print(f"FAIL: {failure}", file=sys.stderr)
            if failures:
                return 1
            print(f"PASS: regenerate check ({len(GENERATED)} generated files, {DECLARED} equal)")
            return 0
        if not args.out:
            raise CheckError("--out DIR is required for write")
        out = args.out.resolve()
        failures = check_declared(root)
        if failures:
            for failure in failures:
                print(f"FAIL: {failure}", file=sys.stderr)
            return 1
        failures, message = write_regenerated(out, root)
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        if failures:
            return 1
        if message == "nothing to regenerate":
            print("PASS: nothing to regenerate")
        else:
            print(f"PASS: regenerate write ({message})")
        return 0
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
