#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Unit tests for tools/scanners.py vulnerability database cache handling."""

from __future__ import annotations

import datetime
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
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

    def test_run_cmd_reads_utf8(self) -> None:
        """Scanner output is read as UTF-8, not the host code page (Trivy tables on Windows)."""
        with patch.object(scanners.subprocess, "run") as run:
            scanners.run_cmd(["fake_tool"])
        self.assertEqual(run.call_args.kwargs.get("encoding"), "utf-8")
        self.assertEqual(run.call_args.kwargs.get("errors"), "replace")

    def scan_with_exceptions(self, entries: list[dict]) -> tuple[str, str]:
        """Capture the ignore file while the scanner subprocess would read it."""
        with tempfile.TemporaryDirectory() as temp_dir_str:
            root = Path(temp_dir_str)
            cache = root / "cache"
            cache.mkdir()
            (cache / "db.stamp").write_text(scanners.TRIVY_DB_DIGEST, encoding="utf-8")
            (root / "requirements.txt").write_text("", encoding="utf-8")
            tables = [
                "[[exception]]\n" + "\n".join(f"{key} = {json.dumps(value)}" for key, value in entry.items())
                for entry in entries
            ]
            (root / "exceptions.toml").write_text("\n".join(tables), encoding="utf-8")
            captured = []

            def capture(argv: list[str], **kwargs: object) -> SimpleNamespace:
                if "--version" not in argv:
                    self.assertIn("--ignorefile", argv)
                    name = argv[argv.index("--ignorefile") + 1]
                    captured.append((name, Path(name).read_text(encoding="utf-8") if name else ""))
                return SimpleNamespace(returncode=0, stdout="fake trivy", stderr="")

            with (
                patch.object(Path, "cwd", return_value=root),
                patch.object(scanners, "run_cmd", side_effect=capture),
                patch.object(scanners, "make_trivy_env", return_value={}),
            ):
                self.assertEqual(scanners.check_trivy(cache, "fake_trivy"), 0)
            self.assertEqual(len(captured), 1)
            name, text = captured[0]
            if name:
                self.assertFalse(Path(name).exists())
            return name, text

    def vulnerability_entry(self, days: int) -> dict:
        """One exception relative to today's UTC date."""
        today = datetime.datetime.now(datetime.UTC).date()
        return {
            "rule": "vulnerability", "path": "requirements.txt",
            "advisories": ["CVE-2026-116684", "GHSA-ab12-cd34-ef56"],
            "reason": 'Pinned CLI dependency; "offline" only.',
            "expires": str(today + datetime.timedelta(days=days)),
        }

    def test_trivy_live_exception(self) -> None:
        """Live entries emit scoped advisories, quoted statements and expiry dates."""
        entry = self.vulnerability_entry(1)
        name, text = self.scan_with_exceptions([entry])
        self.assertTrue(name.endswith(".yaml"))
        self.assertTrue(text.startswith("vulnerabilities:\n"))
        self.assertIn('id: "CVE-2026-116684"', text)
        self.assertIn('id: "GHSA-ab12-cd34-ef56"', text)
        self.assertIn('paths: ["requirements.txt"]', text)
        self.assertIn(f'expired_at: {entry["expires"]}\n', text)
        self.assertIn(f'statement: {json.dumps(entry["reason"])}', text)

    def test_trivy_expired_exception(self) -> None:
        """Expired advisories cannot suppress a scan finding."""
        self.assertEqual(self.scan_with_exceptions([self.vulnerability_entry(-1)]), ("", ""))

    def test_trivy_mixed_expiry(self) -> None:
        """An expired entry stays excluded when another path has a live entry."""
        expired = self.vulnerability_entry(-1)
        expired["advisories"] = ["CVE-2020-14040"]
        live = self.vulnerability_entry(1)
        live["path"] = "cache/db.stamp"
        _, text = self.scan_with_exceptions([expired, live])
        self.assertNotIn("CVE-2020-14040", text)
        self.assertIn('paths: ["cache/db.stamp"]', text)

    def test_trivy_no_exceptions(self) -> None:
        """An explicit empty ignorefile disables implicit .trivyignore loading."""
        self.assertEqual(self.scan_with_exceptions([]), ("", ""))

    def test_trivy_exception_last_day(self) -> None:
        """An exception remains live on its last UTC date."""
        name, text = self.scan_with_exceptions([self.vulnerability_entry(0)])
        self.assertTrue(name)
        self.assertIn('id: "CVE-2026-116684"', text)

    def test_trivy_invalid_exception(self) -> None:
        """The standalone scanner refuses invalid entries before invoking a scan."""
        entry = self.vulnerability_entry(1)
        entry["advisories"] = ["CVE-2026-*"]
        with self.assertRaisesRegex(scanners.CheckError, "advisory ID"):
            self.scan_with_exceptions([entry])

    def test_trivy_glob_path_refused(self) -> None:
        """An exception path cannot widen suppression with a glob pattern."""
        entry = self.vulnerability_entry(1)
        entry["path"] = "*.txt"
        with self.assertRaisesRegex(scanners.CheckError, "vulnerability path"):
            self.scan_with_exceptions([entry])


if __name__ == "__main__":
    unittest.main()
