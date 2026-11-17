# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Unit tests for private plan ID detection and command handling."""

import contextlib
import datetime
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import message_ids as subject
from toolkit import CheckError


class PatternTests(unittest.TestCase):
    """Check positive, negative and boundary cases for all patterns."""

    def test_patterns(self):
        """Only complete identifiers and line-leading order labels match."""
        cases = {
            "dated": ("example-planted-check-20260101", "/x-y-z-20260101", "x-y-z-20260101-1234"),
            "hex": ("example-planted-unit-0123456789ab", "engine a60326a18b15", "a-b-c-0123456789ab"),
            "order": ("Order: x", "quoted Order: x", "\tORDER: "),
        }
        for kind, (positive, negative, boundary) in cases.items():
            with self.subTest(kind=kind):
                self.assertEqual(subject.findings("f", positive), [f"f:1: {kind}"])
                self.assertEqual(subject.findings("f", negative), [])
                self.assertEqual(subject.findings("f", boundary), [f"f:1: {kind}"])

    def test_matches_never_printed(self):
        """Findings contain location and kind, never the matched text."""
        plant = "example-planted-check-20260101"
        self.assertEqual(subject.findings("file", f"clean\n{plant}"), ["file:2: dated"])
        self.assertNotIn(plant, str(subject.findings("file", plant)))


class CommandTests(unittest.TestCase):
    """Exercise commands through their entry point using stubs."""

    def invoke(self, args):
        """Capture a command result and both output streams."""
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["message_ids.py", *args]), contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(errors):
            code = subject.main()
        return code, output.getvalue() + errors.getvalue()

    def test_text_command(self):
        """Text returns success, findings or operational error."""
        plant = "example-planted-check-20260101"
        with mock.patch.object(subject, "read_lines", return_value=[plant]):
            code, output = self.invoke(["check-text", "fixture"])
        self.assertEqual(code, 1)
        self.assertNotIn(plant, output)
        with mock.patch.object(subject, "read_lines", return_value=["clean"]):
            self.assertEqual(self.invoke(["check-text", "fixture"])[0], 0)
        with mock.patch.object(subject, "read_lines", side_effect=CheckError("missing")):
            self.assertEqual(self.invoke(["check-text", "fixture"])[0], 2)

    def test_range_command(self):
        """Range handles a finding, an empty range and a Git failure."""
        with mock.patch.object(subject, "commits", return_value=[("a" * 40, "Order: x")]):
            self.assertEqual(self.invoke(["check-range", "--base", "a", "--head", "b"])[0], 1)
        with mock.patch.object(subject, "commits", return_value=[]):
            self.assertEqual(self.invoke(["check-range", "--base", "a", "--head", "a"])[0], 0)
        with mock.patch.object(subject, "commits", side_effect=CheckError("bad revision")):
            self.assertEqual(self.invoke(["check-range", "--base", "a", "--head", "b"])[0], 2)

    def test_history_exceptions(self):
        """Live exceptions need reachable hits; expired entries excuse nothing."""
        sha = "a" * 40
        today = datetime.date(2026, 11, 18)
        entry = {"commits": [sha], "expires": str(today)}
        with mock.patch.object(subject, "load_entries", return_value=({("private-id", "tools/message_ids.py"): entry}, [])), \
                mock.patch.object(subject, "commits", return_value=[(sha, "Order: x")]) as records:
            self.assertEqual(subject.check_history(Path(), "HEAD", today), [])
            records.return_value = [(sha, "clean")]
            self.assertIn("excuses nothing", subject.check_history(Path(), "HEAD", today)[0])
            records.return_value = []
            self.assertIn("not reachable", subject.check_history(Path(), "HEAD", today)[0])
            entry["expires"] = "2026-11-17"
            records.return_value = [(sha, "Order: x")]
            self.assertTrue(subject.check_history(Path(), "HEAD", today))

    def test_history_command(self):
        """History passes through findings and errors from its checker."""
        for value, expected in (([], 0), (["commit hash:1: hex"], 1), (CheckError("bad"), 2)):
            with self.subTest(expected=expected), mock.patch.object(subject, "check_history") as check:
                if isinstance(value, Exception):
                    check.side_effect = value
                else:
                    check.return_value = value
                self.assertEqual(self.invoke(["check-history", "--ref", "HEAD"])[0], expected)

    def test_commit_bounds(self):
        """Each configured limit permits exactly its bound and refuses one extra."""
        for limit in (subject.MAX_COMMITS, subject.MAX_HISTORY_COMMITS):
            with self.subTest(limit=limit), mock.patch.object(subject, "revision", return_value="a" * 40), \
                    mock.patch.object(subject, "git") as git:
                git.return_value = ("a" * 40 + "\0clean\0") * limit
                self.assertEqual(len(subject.commits(Path(), "HEAD", limit)), limit)
                git.return_value += "a" * 40 + "\0clean\0"
                with self.assertRaises(CheckError):
                    subject.commits(Path(), "HEAD", limit)

    def test_selftest_command(self):
        """Selftest returns the status of its plants."""
        with mock.patch.object(subject, "selftest", return_value=[]):
            self.assertEqual(self.invoke(["selftest"])[0], 0)
        with mock.patch.object(subject, "selftest", return_value=["plant passed"]):
            self.assertEqual(self.invoke(["selftest"])[0], 1)


if __name__ == "__main__":
    unittest.main()
