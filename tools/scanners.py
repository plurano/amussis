#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Run repository security and invariant scanners (semgrep and trivy).

    fetch-db            download the pinned trivy vulnerability database into the
                        cache directory unless a stamp file names the pinned digest
    selftest semgrep    require planted findings in a scratch directory to trigger
                        every rule defined in the semgrep configuration
    selftest trivy      require planted vulnerable manifests in a scratch directory
                        to trigger both expected Go and Rust CVE advisories
    check semgrep       scan repository source files with semgrep against pinned rules
    check trivy         scan repository dependencies offline with trivy against the
                        cached vulnerability database

Pins live in one place: TRIVY_DB_DIGEST as a constant in this file so that
standalone invocations, Makefile targets, and Renovate custom managers reference
the single source of truth.

Exit status: 0 clean or selftest passed, 1 findings detected or selftest failed,
2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_RULES = 100
MAX_LINES = 1000
DEADLINE_SECONDS = 60
SCAN_DEADLINE_SECONDS = 600
FETCH_DEADLINE_SECONDS = 600

TRIVY_DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db"
TRIVY_DB_TAG = "2"
TRIVY_DB_DIGEST = "sha256:44b3f4dfbfe98b280b725f6e4ec7ada9b13774aefbad553a19afc4b919c6a281"

EXPECTED_TRIVY_CVES = {
    "CVE-2020-14040",
    "CVE-2021-25900",
}

PLANTED_SEMGREP_RULES = {
    "hiss-02-go-exec-without-context",
    "hiss-02-go-dial-without-context",
    "hiss-02-go-http-without-context",
    "hiss-02-go-context-todo",
    "hiss-08-go-shell-command",
    "hiss-08-bash-eval",
    "hiss-08-python-eval",
    "hiss-08-python-shell",
    "hiss-02-python-subprocess-without-timeout",
    "hiss-02-python-urlopen-without-timeout",
    "hiss-07-rust-unwrap",
}


class CheckError(Exception):
    """The scanner check could not run; distinct from a finding or selftest failure."""


def run_cmd(
    argv: list[str],
    timeout: int = DEADLINE_SECONDS,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess command with bounded execution time."""
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"{' '.join(argv)}: {error}") from error


def print_tool_version(tool_bin: str) -> None:
    """Print the version string of the selected scanner binary."""
    done = run_cmd([tool_bin, "--version"])
    if done.returncode != 0:
        raise CheckError(f"{tool_bin} --version exited {done.returncode}: {done.stderr.strip()}")
    first_line = (done.stdout or done.stderr).strip().splitlines()[0]
    print(f"{tool_bin} version: {first_line}")


def make_trivy_env(cache_dir: Path) -> dict[str, str]:
    """Provide isolated environment preventing host config conflicts."""
    env = os.environ.copy()
    env.setdefault("DOCKER_CONFIG", str(cache_dir))
    return env


def fetch_db(cache_dir: Path, trivy_bin: str) -> int:
    """Download the pinned Trivy DB unless stamp file names the pinned digest."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    stamp_file = cache_dir / "db.stamp"
    if stamp_file.is_file() and stamp_file.read_text(encoding="utf-8").strip() == TRIVY_DB_DIGEST:
        print(f"trivy database already at pinned digest {TRIVY_DB_DIGEST}")
        return 0
    print_tool_version(trivy_bin)
    target_ref = f"{TRIVY_DB_REPOSITORY}@{TRIVY_DB_DIGEST}"
    argv = [
        trivy_bin, "fs",
        "--cache-dir", str(cache_dir),
        "--db-repository", target_ref,
        "--download-db-only",
    ]
    done = run_cmd(argv, timeout=FETCH_DEADLINE_SECONDS, env=make_trivy_env(cache_dir))
    if done.returncode != 0:
        raise CheckError(f"{' '.join(argv)} exited {done.returncode}: {done.stderr.strip()}")
    stamp_file.write_text(f"{TRIVY_DB_DIGEST}\n", encoding="utf-8")
    print(f"PASS: trivy database updated to {TRIVY_DB_DIGEST}")
    return 0


def read_hiss_rule_ids(config_path: Path) -> set[str]:
    """Parse rule IDs from the semgrep HISS rule configuration."""
    if not config_path.is_file():
        raise CheckError(f"semgrep rule configuration not found: {config_path}")
    pattern = re.compile(r"^\s*-\s+id:\s*(\S+)")
    rule_ids: set[str] = set()
    lines = config_path.read_text(encoding="utf-8").splitlines()
    for idx, line in enumerate(lines):
        if idx >= MAX_LINES:
            break
        match = pattern.match(line)
        if match:
            rule_ids.add(match.group(1))
            if len(rule_ids) >= MAX_RULES:
                break
    if not rule_ids:
        raise CheckError(f"no rules found in semgrep configuration: {config_path}")
    return rule_ids


def write_semgrep_plants(scratch: Path) -> None:
    """Write synthetic plant files covering each semgrep rule."""
    (scratch / "planted.go").write_text(
        "package planted\n\n"
        "import (\n\t\"context\"\n\t\"net\"\n\t\"net/http\"\n\t\"os/exec\"\n)\n\n"
        "func planted(ctx context.Context) {\n"
        "\t_ = exec.Command(\"true\").Run()\n"
        "\t_, _ = net.Dial(\"tcp\", \"127.0.0.1:1\")\n"
        "\t_, _ = http.Get(\"http://127.0.0.1:1\")\n"
        "\t_ = context.TODO()\n"
        "\t_ = exec.CommandContext(ctx, \"sh\", \"-c\", \"true\").Run()\n"
        "}\n",
        encoding="utf-8",
    )
    (scratch / "planted.sh").write_text(
        "#!/usr/bin/env bash\ncmd=\"ls\"\neval \"$cmd\"\n",
        encoding="utf-8",
    )
    (scratch / "planted.py").write_text(
        "import subprocess\nimport urllib.request\n\n"
        "def planted():\n"
        "    eval(\"1 + 1\")\n"
        "    subprocess.run(\"ls\", shell=True, timeout=10)\n"
        "    subprocess.run([\"ls\"])\n"
        "    urllib.request.urlopen(\"http://127.0.0.1:1\")\n",
        encoding="utf-8",
    )
    (scratch / "planted.rs").write_text(
        "pub fn planted() {\n    let _ = Some(1).unwrap();\n}\n",
        encoding="utf-8",
    )


def selftest_semgrep(config_path: Path, semgrep_bin: str) -> int:
    """Run semgrep on planted findings and verify exit code and detected rules."""
    config_rules = read_hiss_rule_ids(config_path)
    print_tool_version(semgrep_bin)
    with tempfile.TemporaryDirectory(prefix="semgrep-selftest-") as scratch_str:
        scratch = Path(scratch_str)
        write_semgrep_plants(scratch)
        argv = [
            semgrep_bin, "scan",
            "--config", str(config_path),
            "--error", "--metrics=off", "--disable-version-check",
            "--json", str(scratch),
        ]
        done = run_cmd(argv, timeout=SCAN_DEADLINE_SECONDS)
        if done.returncode != 1:
            raise CheckError(
                f"semgrep selftest: planted findings gave exit {done.returncode}, want 1\n{done.stderr}"
            )
        try:
            data = json.loads(done.stdout)
        except json.JSONDecodeError as error:
            raise CheckError(f"semgrep output is not valid JSON: {error}") from error

        reported = {r["check_id"].split(".")[-1] for r in data.get("results", [])}
        missing_from_config = config_rules - reported
        unreported_plants = PLANTED_SEMGREP_RULES - reported
        if missing_from_config or unreported_plants:
            failures = sorted(missing_from_config | unreported_plants)
            print(f"FAIL: semgrep selftest missing rule(s): {', '.join(failures)}", file=sys.stderr)
            return 1
        print(f"PASS: semgrep selftest ({len(reported)} planted findings reported, exit 1 as required)")
        return 0


def write_trivy_plants(scratch: Path) -> None:
    """Write synthetic manifest files containing known vulnerable dependencies."""
    (scratch / "go.mod").write_text(
        "module planted\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n",
        encoding="utf-8",
    )
    (scratch / "go.sum").write_text(
        "golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=\n"
        "golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=\n",
        encoding="utf-8",
    )
    (scratch / "Cargo.lock").write_text(
        "version = 4\n\n"
        "[[package]]\nname = \"planted\"\nversion = \"0.0.0\"\n"
        "dependencies = [\n \"smallvec\",\n]\n\n"
        "[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\n"
        "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        encoding="utf-8",
    )


def selftest_trivy(cache_dir: Path, trivy_bin: str) -> int:
    """Run trivy offline against planted manifests and assert exit 3 and CVEs."""
    print_tool_version(trivy_bin)
    with tempfile.TemporaryDirectory(prefix="trivy-selftest-") as scratch_str:
        scratch = Path(scratch_str)
        write_trivy_plants(scratch)
        argv = [
            trivy_bin, "fs",
            "--cache-dir", str(cache_dir),
            "--skip-db-update", "--skip-java-db-update",
            "--offline-scan", "--scanners", "vuln",
            "--exit-code", "3", "--format", "json",
            "--quiet", str(scratch),
        ]
        done = run_cmd(argv, timeout=SCAN_DEADLINE_SECONDS, env=make_trivy_env(cache_dir))
        if done.returncode != 3:
            raise CheckError(
                f"trivy selftest: planted vulnerabilities gave exit {done.returncode}, want 3\n{done.stderr}"
            )
        try:
            data = json.loads(done.stdout)
        except json.JSONDecodeError as error:
            raise CheckError(f"trivy output is not valid JSON: {error}") from error

        reported_cves = {
            v["VulnerabilityID"]
            for r in data.get("Results", [])
            for v in r.get("Vulnerabilities", [])
            if "VulnerabilityID" in v
        }
        missing = EXPECTED_TRIVY_CVES - reported_cves
        if missing:
            print(f"FAIL: trivy selftest missing expected CVE(s): {', '.join(sorted(missing))}", file=sys.stderr)
            return 1
        reported_str = ", ".join(sorted(EXPECTED_TRIVY_CVES))
        print(f"PASS: trivy selftest ({len(EXPECTED_TRIVY_CVES)} planted advisories reported: {reported_str}, exit 3 as required)")
        return 0


def check_semgrep(config_path: Path, semgrep_bin: str) -> int:
    """Perform semgrep tree scan against repository code excluding scratch dirs."""
    print_tool_version(semgrep_bin)
    argv = [
        semgrep_bin, "scan",
        "--config", str(config_path),
        "--error", "--metrics=off", "--disable-version-check",
        "--exclude", ".workingdir",
        "--exclude", "target",
        ".",
    ]
    done = run_cmd(argv, timeout=SCAN_DEADLINE_SECONDS)
    if done.returncode == 0:
        print("PASS: semgrep scan (0 findings)")
        return 0
    if done.returncode == 1:
        if done.stdout:
            print(done.stdout.strip(), file=sys.stderr)
        print("FAIL: semgrep scan found violations", file=sys.stderr)
        return 1
    raise CheckError(f"semgrep scan failed with exit {done.returncode}: {done.stderr.strip()}")


def check_trivy(cache_dir: Path, trivy_bin: str) -> int:
    """Verify Trivy cache stamp and perform offline tree vulnerability scan."""
    stamp_file = cache_dir / "db.stamp"
    if not stamp_file.is_file() or stamp_file.read_text(encoding="utf-8").strip() != TRIVY_DB_DIGEST:
        raise CheckError(
            f"trivy cache stamp invalid or missing; run make fetch to update database to {TRIVY_DB_DIGEST}"
        )
    print_tool_version(trivy_bin)
    argv = [
        trivy_bin, "fs",
        "--cache-dir", str(cache_dir),
        "--skip-db-update", "--skip-java-db-update",
        "--offline-scan", "--scanners", "vuln",
        "--exit-code", "3",
        "--skip-dirs", ".workingdir,target",
        "--quiet",
        ".",
    ]
    done = run_cmd(argv, timeout=SCAN_DEADLINE_SECONDS, env=make_trivy_env(cache_dir))
    if done.returncode == 0:
        if done.stdout:
            print(done.stdout.strip())
        print("PASS: trivy scan (0 vulnerabilities)")
        return 0
    if done.returncode == 3:
        if done.stdout:
            print(done.stdout.strip(), file=sys.stderr)
        print("FAIL: trivy scan found vulnerabilities", file=sys.stderr)
        return 1
    raise CheckError(f"trivy scan failed with exit {done.returncode}: {done.stderr.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("fetch-db", "selftest", "check"))
    parser.add_argument("target", nargs="?", choices=("semgrep", "trivy"))
    parser.add_argument("--cache-dir", type=Path, default=Path("target/trivy-cache"))
    parser.add_argument("--config", type=Path, default=Path(".config/semgrep/hiss.yml"))
    args = parser.parse_args()

    if args.action in ("selftest", "check") and not args.target:
        parser.error(f"{args.action} requires a target (semgrep or trivy)")
    if args.action == "fetch-db" and args.target:
        parser.error("fetch-db takes no target")

    semgrep_bin = os.environ.get("SEMGREP", "semgrep")
    trivy_bin = os.environ.get("TRIVY", "trivy")

    try:
        if args.action == "fetch-db":
            return fetch_db(args.cache_dir, trivy_bin)
        if args.action == "selftest" and args.target == "semgrep":
            return selftest_semgrep(args.config, semgrep_bin)
        if args.action == "selftest" and args.target == "trivy":
            return selftest_trivy(args.cache_dir, trivy_bin)
        if args.action == "check" and args.target == "semgrep":
            return check_semgrep(args.config, semgrep_bin)
        if args.action == "check" and args.target == "trivy":
            return check_trivy(args.cache_dir, trivy_bin)
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
