#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Verify the current main commit deploys and no run replaces another pending deploy."""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exceptions_check import scalar
from toolkit import CheckError

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/pages.yml"
SHARED_GROUP = "workflow concurrency must give every run outside a pull request a group of its own"
NO_QUEUE = "deploy job must queue its runs with queue: max"
CANCELS = "deploy job must not cancel a run in progress"


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


def mapping(lines: list[str], header: str) -> dict[str, str]:
    """Read the first flat mapping at the given exact header."""
    result = {}
    found = False
    indent = len(header) - len(header.lstrip()) + 2
    for line in lines:
        if not found:
            found = line.rstrip() == header
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(r"^ {" + str(indent) + r"}([\w-]+):(?:\s+(.*))?$", line)
        if not match:
            break
        key, value = match.groups()
        result[key] = scalar(value) if value else ""
    return result


def concurrency_problems(text: str) -> list[str]:
    """Report concurrency that lets one run replace the pending deploy of another."""
    workflow = mapping(text.splitlines(), "concurrency:")
    deploy = mapping(deploy_job(text), "    concurrency:")
    problems = []
    if workflow and "github.run_id" not in workflow.get("group", ""):
        problems.append(SHARED_GROUP)
    if deploy.get("queue") != "max":
        problems.append(NO_QUEUE)
    if "cancel-in-progress" in deploy and deploy["cancel-in-progress"] != "false":
        problems.append(CANCELS)
    return problems


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


def push_trigger(text: str) -> list[str]:
    """Return the stripped lines of the push trigger inside the on block."""
    in_on, in_push, found = False, False, False
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            if in_on:
                break
            in_on = line == "on:"
        elif in_on and indent <= 2:
            if in_push:
                break
            in_push = line == "  push:"
            found = found or in_push
        elif in_push:
            lines.append(stripped)
    if not found:
        raise CheckError("workflow has no push trigger in on block")
    return lines


def push_problems(text: str) -> list[str]:
    """Report deviations from the required push trigger."""
    lines = push_trigger(text)
    problems = []
    if any(line.startswith(("paths:", "paths-ignore:")) for line in lines):
        problems.append("push trigger must not filter paths")
    if "branches: [main]" not in lines:
        problems.append("push trigger must name the main branch")
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
        self.assertEqual(push_problems(self.text), [])
        self.assertEqual(concurrency_problems(self.text), [])

    def test_shared_workflow_group(self):
        """A shared workflow concurrency group is rejected."""
        changed = self.text.replace(
            "  group: pages-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}\n",
            "  group: pages-${{ github.ref }}\n",
        )
        self.assertNotEqual(changed, self.text)
        self.assertEqual(concurrency_problems(changed), [SHARED_GROUP])

    def test_deploy_queue_missing(self):
        """A deploy concurrency group without a queue is rejected."""
        changed = self.text.replace("      queue: max\n", "")
        self.assertNotEqual(changed, self.text)
        self.assertEqual(concurrency_problems(changed), [NO_QUEUE])

    def test_deploy_queue_single(self):
        """A deploy queue that replaces pending runs is rejected."""
        changed = self.text.replace("      queue: max\n", "      queue: single\n")
        self.assertNotEqual(changed, self.text)
        self.assertEqual(concurrency_problems(changed), [NO_QUEUE])

    def test_deploy_concurrency_missing(self):
        """A deploy job without concurrency is rejected."""
        changed = self.text.replace("    concurrency:\n      group: pages-deploy\n      queue: max\n", "")
        self.assertNotEqual(changed, self.text)
        self.assertEqual(concurrency_problems(changed), [NO_QUEUE])

    def test_deploy_cancels(self):
        """A deploy job that cancels runs in progress is rejected."""
        changed = self.text.replace("      queue: max\n", "      queue: max\n      cancel-in-progress: true\n")
        self.assertNotEqual(changed, self.text)
        self.assertEqual(concurrency_problems(changed), [CANCELS])

    def test_push_paths(self):
        """A push path filter is rejected."""
        changed = self.text.replace("    branches: [main]\n", "    branches: [main]\n    paths:\n      - \"docs/**\"\n")
        self.assertTrue(push_problems(changed))

    def test_push_paths_ignore(self):
        """A push paths-ignore filter is rejected."""
        changed = self.text.replace("    branches: [main]\n", "    branches: [main]\n    paths-ignore:\n      - \"src/**\"\n")
        self.assertTrue(push_problems(changed))

    def test_push_branch_missing(self):
        """A push trigger without the main branch is rejected."""
        self.assertTrue(push_problems(self.text.replace("    branches: [main]\n", "")))

    def test_push_missing(self):
        """A workflow without a push trigger raises an error."""
        with self.assertRaises(CheckError):
            push_problems("on:\n  workflow_dispatch:\njobs:\n")

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
