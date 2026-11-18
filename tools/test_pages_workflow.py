#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Verify that Pages deploys only the current main commit."""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exceptions_check import scalar
from toolkit import CheckError

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/pages.yml"


def deploy_job(text: str) -> list[str]:
    """Find the deploy job beneath the top-level jobs mapping."""
    in_jobs, in_deploy, found = False, False, False
    lines = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")):
            if in_deploy:
                break
            in_jobs = line.split("#", 1)[0].rstrip() == "jobs:"
        elif in_jobs and re.match(r"^  [^ #][^:]*:\s*(?:#.*)?$", line):
            if in_deploy:
                break
            in_deploy = line.split(":", 1)[0].strip() == "deploy"
            found = found or in_deploy
        elif in_deploy:
            lines.append(line)
    if not found:
        raise CheckError("workflow has no deploy job")
    return lines


def step_values(lines: list[str]) -> list[dict[str, str]]:
    """Collect step keys and literal run blocks at their expected indentation."""
    steps = []
    in_run = False
    for line in lines:
        if in_run and (not line.strip() or line.startswith("          ")):
            steps[-1]["run"] += "\n" + line
            continue
        in_run = False
        if line.startswith("      - "):
            steps.append({})
            line = "        " + line[8:]
        match = re.match(r"^        ([\w-]+):(?:\s+(.*))?$", line)
        if match and steps:
            key, value = match.groups()
            steps[-1][key] = scalar(value) if value else ""
            in_run = key == "run" and value == "|"
            if in_run:
                steps[-1]["run"] = ""
    return steps


def deploy_steps(text: str) -> list[dict[str, str]]:
    """Read the deploy job's ordered steps from workflow text."""
    lines = deploy_job(text)
    for index, line in enumerate(lines):
        if re.match(r"^    steps:\s*(?:#.*)?$", line):
            following = lines[index + 1:]
            for end, item in enumerate(following):
                if re.match(r"^    [^ #][^:]*:", item):
                    return step_values(following[:end])
            return step_values(following)
    raise CheckError("deploy job has no steps")


def deploy_problems(text: str) -> list[str]:
    """Report deviations from the required deploy guard."""
    steps = deploy_steps(text)
    deploys = [i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/deploy-pages@")]
    heads = [i for i, step in enumerate(steps) if step.get("id") == "head"]
    problems = []
    if len(deploys) != 1:
        problems.append("expected exactly one Pages deploy step")
    if len(heads) != 1:
        problems.append("expected exactly one head step")
    if len(deploys) == 1 and steps[deploys[0]].get("if") != "steps.head.outputs.current == 'true'":
        problems.append("deploy condition must require the current head")
    if len(heads) == 1:
        if len(deploys) == 1 and heads[0] >= deploys[0]:
            problems.append("head step must precede deployment")
        run = steps[heads[0]].get("run", "")
        if any(part not in run for part in ("timeout 60 git ls-remote", "current=true", "current=false")):
            problems.append("head step must check the remote with a timeout and write both outcomes")
    return problems


class PagesWorkflowTests(unittest.TestCase):
    """Check the Pages deployment workflow and its guards."""

    def setUp(self):
        """Load the workflow and locate its head and deploy steps."""
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.head = self.text.index("      - name: Stop when main has moved on")
        self.deploy = self.text.index("      - name: Deploy\n", self.head)

    def test_committed_workflow(self):
        """The committed workflow has no deployment guard problems."""
        self.assertEqual(deploy_problems(self.text), [])

    def test_missing_if(self):
        """A deploy step without its condition is rejected."""
        self.assertTrue(deploy_problems(self.text.replace("        if: steps.head.outputs.current == 'true'\n", "")))

    def test_widened_if(self):
        """A deploy condition widened with always is rejected."""
        self.assertTrue(deploy_problems(self.text.replace("steps.head.outputs.current == 'true'\n",
                                                          "steps.head.outputs.current == 'true' || always()\n")))

    def test_head_after_deploy(self):
        """A head check after deployment is rejected."""
        changed = self.text[:self.head] + self.text[self.deploy:] + "\n" + self.text[self.head:self.deploy]
        self.assertTrue(deploy_problems(changed))

    def test_head_missing(self):
        """A missing head check is rejected."""
        self.assertTrue(deploy_problems(self.text[:self.head] + self.text[self.deploy:]))

    def test_timeout_missing(self):
        """A head check without a remote query timeout is rejected."""
        self.assertTrue(deploy_problems(self.text.replace("timeout 60 git ls-remote", "git ls-remote")))

    def test_duplicate_steps(self):
        """Duplicate head or deploy steps are rejected."""
        head = self.text[self.head:self.deploy]
        deploy = self.text[self.deploy:]
        self.assertTrue(deploy_problems(self.text[:self.deploy] + head + deploy))
        self.assertTrue(deploy_problems(self.text + "\n" + deploy))

    def test_steps_missing(self):
        """A deploy job without steps raises an error."""
        with self.assertRaises(CheckError):
            deploy_steps("jobs:\n  deploy:\n    runs-on: ubuntu\n")

    def test_deploy_job_missing(self):
        """A workflow without a deploy job raises an error."""
        with self.assertRaises(CheckError):
            deploy_steps("jobs:\n  build:\n    steps:\n")


if __name__ == "__main__":
    unittest.main()
