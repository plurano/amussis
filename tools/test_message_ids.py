# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Unit tests for private plan ID detection and command handling."""

import contextlib
import datetime
import io
import json
import re
import subprocess
import sys
import tempfile
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


class GitTests(unittest.TestCase):
    """Exercise Git reading against a scratch repository and stubs."""

    def scratch_repo(self, message):
        """Create an isolated scratch repository holding one commit."""
        scratch = tempfile.TemporaryDirectory(prefix="message-ids-test-")
        self.addCleanup(scratch.cleanup)
        repo = Path(scratch.name)
        subject.git(repo, "init", "--quiet", env=subject.fixture_env())
        subject.fixture_commit(repo, message)
        return repo

    def test_git_decodes_utf8(self):
        """A non-cp1252 character in a commit message is read as UTF-8 without error."""
        repo = self.scratch_repo("quote \u201d end")
        with mock.patch.object(subject.subprocess, "run", wraps=subprocess.run) as run:
            output = subject.git(repo, "log", "-1", "--format=%B", env=subject.fixture_env())
        self.assertIn("\u201d", output)
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
        self.assertEqual(run.call_args.kwargs["errors"], "replace")

    def test_commits_ignores_show_signature(self):
        """Log is run with --no-show-signature, and hashes stay 40 hex under log.showSignature."""
        with mock.patch.object(subject, "revision", return_value="a" * 40), mock.patch.object(subject, "git") as git:
            git.return_value = "a" * 40 + "\0clean\0"
            subject.commits(Path(), "HEAD", 1)
        self.assertIn("--no-show-signature", git.call_args.args)
        repo = self.scratch_repo("clean")
        subject.git(repo, "config", "log.showSignature", "true", env=subject.fixture_env())
        records = subject.commits(repo, "HEAD", 10, env=subject.fixture_env())
        self.assertEqual(len(records), 1)
        self.assertRegex(records[0][0], re.compile(r"[0-9a-f]{40}"))


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

    def event(self, pull_request):
        """Write an event file and return the command result and the planted-file output."""
        with tempfile.TemporaryDirectory(prefix="event-") as scratch:
            path = Path(scratch) / "event.json"
            path.write_text(json.dumps({"pull_request": pull_request}), encoding="utf-8")
            return self.invoke(["check-event", str(path)])

    def test_event_command(self):
        """Event passes clean text and null body; refuses ids in title or body without printing them."""
        plant = "example-planted-check-20260101"
        self.assertEqual(self.event({"title": "clean", "body": "clean"})[0], 0)
        self.assertEqual(self.event({"title": "clean", "body": None})[0], 0)
        for field, pull_request, expected in (
                ("title", {"title": plant, "body": "clean"}, "title:1: dated"),
                ("body", {"title": "clean", "body": f"clean\n{plant}"}, "body:2: dated")):
            with self.subTest(field=field):
                code, output = self.event(pull_request)
                self.assertEqual(code, 1)
                self.assertIn(expected, output)
                self.assertNotIn(plant, output)

    def test_event_operational_errors(self):
        """Missing file, bad JSON, missing pull_request and non-string title exit 2."""
        plant = "example-planted-check-20260101"
        for pull_request in (None, [], {"title": 7, "body": ""}, {"body": plant}, {"title": "clean", "body": 7}):
            with self.subTest(pull_request=pull_request):
                code, output = self.event(pull_request)
                self.assertEqual(code, 2)
                self.assertNotIn(plant, output)
        with tempfile.TemporaryDirectory(prefix="event-") as scratch:
            missing, broken, bare = (Path(scratch) / name for name in ("missing.json", "broken.json", "bare.json"))
            broken.write_text("{" + plant, encoding="utf-8")
            bare.write_text(json.dumps({"action": plant}), encoding="utf-8")
            for path in (missing, broken, bare):
                with self.subTest(path=path.name):
                    code, output = self.invoke(["check-event", str(path)])
                    self.assertEqual(code, 2)
                    self.assertNotIn(plant, output)

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
