#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Unit tests for tools/scanners.py vulnerability database cache handling."""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

SCANNERS_PATH = TOOLS_DIR / "scanners.py"
spec = importlib.util.spec_from_file_location("scanners", SCANNERS_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load spec from {SCANNERS_PATH}")
scanners = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanners)


def make_fake_trivy(dest_dir: Path) -> Path:
    """Create an executable fake trivy script for testing."""
    script_path = dest_dir / "fake_trivy"
    code = """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

log_path = os.environ.get("FAKETRIVY_LOG")
if log_path:
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(" ".join(sys.argv) + "\\n")

if "--version" in sys.argv:
    print("fake-trivy 0.50.0")
    sys.exit(0)

if os.environ.get("FAKETRIVY_FAIL") == "1":
    sys.stderr.write("simulated trivy download failure\\n")
    sys.exit(1)

race_target = os.environ.get("FAKETRIVY_RACE_CACHE")
if race_target:
    race_path = Path(race_target)
    race_path.mkdir(parents=True, exist_ok=True)
    stamp = os.environ.get("FAKETRIVY_RACE_STAMP", "")
    (race_path / "db.stamp").write_text(stamp + "\\n", encoding="utf-8")
    (race_path / "data.bin").write_text("race winner\\n", encoding="utf-8")

sys.exit(0)
"""
    script_path.write_text(code, encoding="utf-8")
    script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script_path


REAL_RUN_CMD = scanners.run_cmd


def run_through_python(argv: list[str], *args: object, **kwargs: object) -> object:
    """Run the fake trivy through this interpreter: Windows cannot run a shebang script."""
    if Path(argv[0]).name == "fake_trivy":
        argv = [sys.executable, *argv]
    return REAL_RUN_CMD(argv, *args, **kwargs)


class TestScanners(unittest.TestCase):
    """Test suite covering trivy database cache behaviour."""

    def setUp(self) -> None:
        """Route every scanner subprocess through the interpreter wrapper."""
        runner = patch.object(scanners, "run_cmd", run_through_python)
        runner.start()
        self.addCleanup(runner.stop)

    def test_default_cache_xdg(self) -> None:
        """Case a: default_cache under XDG_CACHE_HOME."""
        custom_xdg = Path("/custom/cache/dir")
        with patch.dict(os.environ, {"XDG_CACHE_HOME": str(custom_xdg)}):
            cache = scanners.default_cache()
            digest_suffix = scanners.TRIVY_DB_DIGEST.removeprefix("sha256:")
            expected = custom_xdg / "plurano" / "trivy-db" / digest_suffix
            self.assertEqual(cache, expected)

    def test_default_cache_no_xdg(self) -> None:
        """Case b: without XDG_CACHE_HOME -> ~/.cache."""
        env = os.environ.copy()
        env.pop("XDG_CACHE_HOME", None)
        with patch.dict(os.environ, env, clear=True):
            cache = scanners.default_cache()
            digest_suffix = scanners.TRIVY_DB_DIGEST.removeprefix("sha256:")
            expected = Path.home() / ".cache" / "plurano" / "trivy-db" / digest_suffix
            self.assertEqual(cache, expected)

    def test_fetch_writes_stamp_and_caches(self) -> None:
        """Case c: fetch writes stamp, second fetch calls trivy no more (log file)."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            trivy_bin = make_fake_trivy(temp_dir)
            cache_dir = temp_dir / "cache" / "db"
            log_file = temp_dir / "trivy.log"

            with patch.dict(os.environ, {"FAKETRIVY_LOG": str(log_file)}):
                res1 = scanners.fetch_db(cache_dir, str(trivy_bin))
                self.assertEqual(res1, 0)
                stamp_file = cache_dir / "db.stamp"
                self.assertTrue(stamp_file.is_file())
                self.assertEqual(
                    stamp_file.read_text(encoding="utf-8").strip(),
                    scanners.TRIVY_DB_DIGEST,
                )

                calls1 = [line for line in log_file.read_text(encoding="utf-8").splitlines() if line]
                self.assertGreaterEqual(len(calls1), 1)

                res2 = scanners.fetch_db(cache_dir, str(trivy_bin))
                self.assertEqual(res2, 0)
                calls2 = [line for line in log_file.read_text(encoding="utf-8").splitlines() if line]
                self.assertEqual(len(calls1), len(calls2))

    def test_fetch_refetches_outdated_stamp(self) -> None:
        """Case d: cache with other digest stamp -> refetch, stamp now pinned."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            trivy_bin = make_fake_trivy(temp_dir)
            cache_dir = temp_dir / "cache" / "db"
            cache_dir.mkdir(parents=True, exist_ok=True)
            (cache_dir / "db.stamp").write_text("sha256:outdateddigest\n", encoding="utf-8")
            (cache_dir / "old_data.bin").write_text("stale data\n", encoding="utf-8")

            res = scanners.fetch_db(cache_dir, str(trivy_bin))
            self.assertEqual(res, 0)
            self.assertEqual(scanners.stamp_of(cache_dir), scanners.TRIVY_DB_DIGEST)
            self.assertFalse((cache_dir / "old_data.bin").exists())

    def test_fetch_failure_cleans_up(self) -> None:
        """Case e: failing download -> CheckError, no cache dir, no .fetch-* left."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            trivy_bin = make_fake_trivy(temp_dir)
            cache_dir = temp_dir / "cache" / "db"

            with (
                patch.dict(os.environ, {"FAKETRIVY_FAIL": "1"}),
                self.assertRaises(scanners.CheckError),
            ):
                scanners.fetch_db(cache_dir, str(trivy_bin))

            self.assertFalse(cache_dir.exists())
            leftovers = list(cache_dir.parent.glob(".fetch-*"))
            self.assertEqual(leftovers, [])

    def test_fetch_rename_race_lost(self) -> None:
        """Case f: rename race: fake trivy creates final cache during download."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            trivy_bin = make_fake_trivy(temp_dir)
            cache_dir = temp_dir / "cache" / "db"

            env_vars = {
                "FAKETRIVY_RACE_CACHE": str(cache_dir),
                "FAKETRIVY_RACE_STAMP": scanners.TRIVY_DB_DIGEST,
            }
            with patch.dict(os.environ, env_vars):
                res = scanners.fetch_db(cache_dir, str(trivy_bin))

            self.assertEqual(res, 0)
            self.assertEqual(scanners.stamp_of(cache_dir), scanners.TRIVY_DB_DIGEST)
            self.assertTrue((cache_dir / "data.bin").exists())
            leftovers = list(cache_dir.parent.glob(".fetch-*"))
            self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
