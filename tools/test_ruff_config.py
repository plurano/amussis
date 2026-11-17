#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Verify Ruff's rule source and dated exceptions."""

import datetime
import tempfile
import tomllib
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import exceptions_check
import scanners
import toolkit

ROOT = Path(__file__).resolve().parent.parent


def config_problems(config: dict, codes: list[str], tracked: set[str]) -> list[str]:
    """Return rule selection, target and tracked-ignore discrepancies."""
    lint = config.get("lint", {})
    selected = lint.get("select", [])
    problems = []
    if len(selected) != len(set(selected)) or set(selected) != set(codes) | {"I001"}:
        problems.append("select must contain exactly the unique pattern codes and I001")
    if config.get("target-version") != "py314":
        problems.append("target-version must be py314")
    if set(lint.get("per-file-ignores", {})) - tracked:
        problems.append("per-file ignores must name tracked files")
    return problems


class RuffConfigTests(unittest.TestCase):
    def setUp(self):
        """Load the Ruff configuration, expected codes and tracked Python files."""
        self.config = tomllib.loads((ROOT / "ruff.toml").read_text(encoding="utf-8"))
        self.codes = [line for line in (ROOT / "tools/ruff/codacy-patterns.txt").read_text(encoding="utf-8").splitlines()
                      if line and not line.startswith("#")]
        result = toolkit.run_command(["git", "ls-files", "-z", "*.py"], ROOT, 60).stdout
        self.tracked = set(result.split("\0"))

    def test_committed_config(self):
        """The committed Ruff configuration has no problems."""
        self.assertEqual(config_problems(self.config, self.codes, self.tracked), [])

    def test_missing_duplicate_and_extra_codes(self):
        """Missing, duplicate and extra selected codes are rejected."""
        for selected in (self.config["lint"]["select"][:-1], self.config["lint"]["select"] + ["I001"],
                         self.config["lint"]["select"] + ["S999"]):
            self.assertTrue(config_problems({"target-version": "py314", "lint": {"select": selected}},
                                            self.codes, self.tracked))

    def test_wrong_target_and_untracked_ignore(self):
        """A wrong target and an ignore for an untracked file are reported."""
        self.config["target-version"] = "py313"
        self.config["lint"]["per-file-ignores"]["missing.py"] = ["S603"]
        self.assertEqual(len(config_problems(self.config, self.codes, self.tracked)), 2)

    def test_entry_validation_and_expiry(self):
        """Ruff exception entries are validated and expire after their deadline."""
        today = datetime.date(2026, 11, 17)
        entry = {"rule": "ruff", "path": ".config/lefthook/scripts/common.py", "codes": ["S603", "S607"],
                 "reason": "test", "expires": "2026-11-27"}
        self.assertEqual(exceptions_check.entry_problem(ROOT, entry, today), "")
        for codes in ([], ["S*"], ["S603", "S603"]):
            self.assertTrue(exceptions_check.entry_problem(ROOT, entry | {"codes": codes}, today))
        self.assertTrue(exceptions_check.entry_problem(ROOT, entry | {"unknown": True}, today))
        self.assertTrue(exceptions_check.entry_problem(ROOT, entry | {"rule": "unsafe_code"}, today))
        by_key = {("ruff", entry["path"]): entry}
        self.assertEqual(exceptions_check.ruff_findings(ROOT, by_key, datetime.date(2026, 11, 27)), [])
        self.assertEqual(len(exceptions_check.ruff_findings(ROOT, by_key, datetime.date(2026, 11, 28))), 2)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "ruff.toml").write_text('[lint.per-file-ignores]\n"other.py" = ["S603"]\n', encoding="utf-8")
            self.assertEqual(len(exceptions_check.ruff_findings(root, by_key, today)), 3)

    def test_scanner_requires_exact_plants(self):
        """The Ruff self-test requires the expected planted findings."""
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            scanners.write_ruff_plants(path)
            self.assertIn("import tomllib", (path / "imports.py").read_text(encoding="utf-8"))
        with patch.object(scanners, "print_tool_version"), patch.object(scanners, "run_cmd") as run:
            run.return_value = types.SimpleNamespace(returncode=1, stdout='[{"filename":"imports.py","code":"I001"},'
                                                     '{"filename":"security.py","code":"S101"}]', stderr='')
            self.assertEqual(scanners.selftest_ruff(ROOT / "ruff.toml", "ruff"), 0)
            run.return_value.stdout = '[]'
            self.assertEqual(scanners.selftest_ruff(ROOT / "ruff.toml", "ruff"), 1)
            run.return_value.returncode = 2
            self.assertEqual(scanners.selftest_ruff(ROOT / "ruff.toml", "ruff"), 1)

    def test_scanner_main_ruff_dispatch(self):
        """Ruff actions dispatch correctly and reject an invalid target."""
        with patch.object(scanners, "check_ruff", return_value=11) as check, \
             patch.object(scanners, "selftest_ruff", return_value=12) as selftest:
            with patch("sys.argv", ["scanners.py", "check", "ruff"]):
                self.assertEqual(scanners.main(), 11)
            check.assert_called_once()
            selftest.assert_not_called()
            with patch("sys.argv", ["scanners.py", "selftest", "ruff"]):
                self.assertEqual(scanners.main(), 12)
            selftest.assert_called_once()
            with patch("sys.argv", ["scanners.py", "fetch-db", "ruff"]):
                with self.assertRaises(SystemExit) as error:
                    scanners.main()
            self.assertEqual(error.exception.code, 2)

    def test_scanner_check_propagates_findings(self):
        """Ruff scanner findings propagate to the check result."""
        with patch.object(scanners, "print_tool_version"), patch.object(scanners, "run_cmd") as run:
            run.side_effect = [types.SimpleNamespace(returncode=0, stdout="a.py\0", stderr=""),
                               types.SimpleNamespace(returncode=1, stdout="finding", stderr="")]
            self.assertEqual(scanners.check_ruff(ROOT / "ruff.toml", "ruff"), 1)
            self.assertIn("a.py", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
