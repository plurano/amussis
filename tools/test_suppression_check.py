# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Unit tests for suppression marker detection and command handling."""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import suppression_check as subject
from message_ids import fixture_env, git
from toolkit import CheckError

SEC = "no" + "sec"
SEMGREP = "no" + "semgrep"
REASON = "fixed executable, no shell"


def line(word, tail):
    """Build a source line holding one marker without writing the marker in this file."""
    return f"x = 1  # {word}{tail}"


class MarkerTests(unittest.TestCase):
    """Check positive, negative and boundary cases of the marker rule."""

    def found(self, text):
        """Return the findings for one line."""
        return subject.findings("f", [text])

    def test_refused_markers(self):
        """Markers without a rule id or without a reason are refused."""
        cases = {
            line(SEC, ""): f"f:1: {SEC} without rule id",
            line(SEC, " -- " + REASON): f"f:1: {SEC} without rule id",
            line(SEC, " B404"): f"f:1: {SEC} without reason",
            line(SEC, " B404 B603"): f"f:1: {SEC} without reason",
            line(SEMGREP, ""): f"f:1: {SEMGREP} without rule id",
            line(SEMGREP, " -- " + REASON): f"f:1: {SEMGREP} without rule id",
            line(SEMGREP, ": a.b-c"): f"f:1: {SEMGREP} without reason",
        }
        for text, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(self.found(text), [expected])

    def test_held_markers(self):
        """Complete markers pass, including other languages, several ids and a trailing comment."""
        cases = (
            line(SEC, " B404 -- " + REASON),
            line(SEC, " B404, B603 -- " + REASON),
            line(SEC, f" B404 -- {REASON}  # noqa: S603"),
            f"\tx() // {SEC} G204 -- {REASON}",
            f"x(); /* {SEC} G204 -- {REASON} */",
            line(SEMGREP, ": python.lang.example.rule-id -- " + REASON),
            f"  // {SEMGREP}: js_rule-id -- {REASON}",
            line(SEC, " B603 -- " + REASON) + f"  # {SEMGREP}: a.b -- {REASON}",
            "plain code with the words nosec and nosemgrep outside any comment",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(self.found(text), [])

    def test_reason_word_boundary(self):
        """A reason of 2 words is refused and a reason of 3 words held."""
        for word in (SEC, SEMGREP):
            tail = " B404" if word == SEC else ": a.b"
            with self.subTest(word=word):
                self.assertEqual(self.found(line(word, tail + " -- two words")), [f"f:1: {word} reason under 3 words"])
                self.assertEqual(self.found(line(word, tail + " -- three plain words")), [])

    def test_marker_later_in_comment(self):
        """A Semgrep marker after comment prose still needs an ID and reason."""
        self.assertEqual(self.found(f"x = 1  # explanation: {SEMGREP}"), [f"f:1: {SEMGREP} without rule id"])
        self.assertEqual(self.found(f"x = 1  # explanation: {SEMGREP}: a.b -- {REASON}"), [])

    def test_semgrep_id_separators(self):
        """ID separators can include spaces; a dangling comma is not a reason."""
        for ids in ("a.b,c.d", "a.b, c.d", "a.b c.d", "a.b,\tc.d"):
            with self.subTest(ids=ids):
                self.assertEqual(self.found(line(SEMGREP, f": {ids} -- {REASON}")), [])
        self.assertEqual(self.found(line(SEMGREP, f": a.b, -- {REASON}")), [f"f:1: {SEMGREP} without reason"])

    def test_one_finding_per_marker_with_line_number(self):
        """Each refused marker gives one finding at its own line, and the text is never printed."""
        found = subject.findings("f", ["clean", line(SEC, ""), line(SEMGREP, ": a.b")])
        self.assertEqual(found, [f"f:2: {SEC} without rule id", f"f:3: {SEMGREP} without reason"])
        self.assertNotIn("a.b", str(found))


class RepoTests(unittest.TestCase):
    """Exercise the tracked-file walk and exit codes against scratch repositories."""

    def scratch_repo(self, files):
        """Create an isolated scratch repository tracking the given files."""
        scratch = tempfile.TemporaryDirectory(prefix="suppression-test-")
        self.addCleanup(scratch.cleanup)
        repo = Path(scratch.name)
        git(repo, "init", "--quiet", env=fixture_env())
        for name, text in files.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(text, encoding="utf-8")
        git(repo, "add", "--all", env=fixture_env())
        return repo

    def run_main(self, *argv):
        """Run main with fixture Git isolation and return the exit code and stderr."""
        stderr = io.StringIO()
        with (mock.patch.dict(os.environ, fixture_env(), clear=True), mock.patch.object(sys, "argv", ["suppression_check", *argv]),
              contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO())):
            return subject.main(), stderr.getvalue()

    def test_walk_takes_supported_formats(self):
        """Every supported suffix and Makefile is scanned; other files and untracked files are not."""
        bad = line(SEC, "") + "\n"
        names = ("a.py", "b.sh", "c.yml", "d.yaml", "e.toml", "f.go", "g.rs", "h.mjs", "i.js", "sub/Makefile")
        repo = self.scratch_repo({**dict.fromkeys(names, bad), "notes.md": bad, "data.txt": bad})
        (repo / "untracked.py").write_text(bad, encoding="utf-8")
        self.assertEqual(sorted(subject.tracked_files(repo, fixture_env())), sorted(names))
        self.assertEqual(len(subject.scan(repo, fixture_env())), len(names))

    def test_check_exit_codes(self):
        """Findings exit 1, a clean repository exits 0, and the finding names the path and line."""
        dirty = self.scratch_repo({"a.py": "x = 1\n" + line(SEC, " B404") + "\n"})
        code, stderr = self.run_main("check", "--repo", str(dirty))
        self.assertEqual(code, 1)
        self.assertIn(f"a.py:2: {SEC} without reason", stderr)
        clean = self.scratch_repo({"a.py": line(SEC, " B404 -- " + REASON) + "\n"})
        self.assertEqual(self.run_main("check", "--repo", str(clean)), (0, ""))

    def test_not_a_git_repository(self):
        """A directory outside any repository is an operational error, exit 2."""
        with tempfile.TemporaryDirectory(prefix="suppression-none-") as scratch:
            with mock.patch.dict(os.environ, fixture_env(), clear=True):
                with self.assertRaises(CheckError):
                    subject.scan(Path(scratch))
            code, stderr = self.run_main("check", "--repo", scratch)
        self.assertEqual(code, 2)
        self.assertIn("ERROR:", stderr)

    def test_undecodable_file_is_an_error(self):
        """A tracked file that is not UTF-8 cannot be checked, which exits 2 rather than 0."""
        repo = self.scratch_repo({"a.py": "x = 1\n"})
        (repo / "a.py").write_bytes(b"x = '\xff'\n")
        self.assertEqual(self.run_main("check", "--repo", str(repo))[0], 2)

    def test_selftest_command(self):
        """The selftest passes and prints its plant counts."""
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["suppression_check", "selftest"]), contextlib.redirect_stdout(stdout):
            self.assertEqual(subject.main(), 0)
        self.assertEqual(stdout.getvalue().strip(), "PASS: suppression selftest (6 plants refused, 5 clean cases held)")

    def test_selftest_fails_when_a_plant_passes(self):
        """The selftest reports a plant the rule no longer refuses."""
        with mock.patch.object(subject, "marker_problem", return_value=None):
            self.assertEqual(len(subject.selftest()), 6)


if __name__ == "__main__":
    unittest.main()
