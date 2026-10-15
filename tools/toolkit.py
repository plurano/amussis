# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Shared helper functions and types for repository verification tools.

This module is imported by tools/*.py; it has no command-line interface.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any


class CheckError(Exception):
    """The check could not run; distinct from a defect found by the check."""


def read_lines(path: Path) -> list[str]:
    """Read a text file and return its lines stripped of line terminators."""
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise CheckError(f"cannot read {path}: {error}") from error


def append_to(name: str, text: str) -> Callable[[Path], None]:
    """An edit that appends text to root / name."""

    def edit(copy: Path) -> None:
        path = copy / name
        if not path.is_file():
            raise CheckError(f"selftest plant: {name} is not a file")
        path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")

    return edit


def replace_in(name: str, old: str, new: str) -> Callable[[Path], None]:
    """An edit that replaces the first occurrence of old with new in root / name."""

    def edit(copy: Path) -> None:
        text = (copy / name).read_text(encoding="utf-8")
        if old not in text:
            raise CheckError(f"selftest plant: {name} does not contain {old!r}")
        (copy / name).write_text(text.replace(old, new, 1), encoding="utf-8")

    return edit


def planted(
    root: Path,
    prefix: str,
    copy_fn: Callable[[Path, Path], None],
    edit: Callable[[Path], None] | None = None,
) -> Path:
    """A throwaway copy of root populated by copy_fn, with edit applied."""
    copy = Path(tempfile.mkdtemp(prefix=prefix))
    copy_fn(root, copy)
    if edit is not None:
        edit(copy)
    return copy


def run_selftest(
    root: Path,
    check_fn: Callable[[Path], tuple[list[str], ...]],
    plant_fn: Callable[[Path, Any], Path],
    plants: dict[str, Any],
    look_alikes: dict[str, Any],
) -> list[str]:
    """Run check_fn against unplanted tree, then each plant and look-alike."""
    failures = [f"the unplanted tree is refused: {line}" for line in check_fn(root)[0]]
    cases = [(name, edit, True) for name, edit in plants.items()]
    cases += [(name, edit, False) for name, edit in look_alikes.items()]
    for name, edit, refused in cases:
        copy = plant_fn(root, edit)
        try:
            found = check_fn(copy)[0]
            if refused and not found:
                failures.append(f"plant passed: {name}")
            if not refused and found:
                failures.append(f"look-alike refused: {name}: {found[0]}")
        finally:
            shutil.rmtree(copy, ignore_errors=True)
    return failures


def run_command(
    args: list[str],
    cwd: Path,
    deadline: int,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a command with timeout, raising CheckError on failure or non-zero exit."""
    try:
        done = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=deadline,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"{' '.join(args)} could not run: {error}") from error
    if done.returncode != 0:
        raise CheckError(f"{' '.join(args)} exited {done.returncode}:\n{done.stderr.strip()}")
    return done
