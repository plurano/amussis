#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Hold the third-party notices of the WebAssembly module to what it is built from.

The module the Go binding embeds is a compiled file. It carries code of every
registry crate it links and of the Rust standard library, and their licences
ask that the copyright and permission notices travel with every copy. The
notices are a file beside the module, and this tool holds that file to the
lock file.

Registry crates come from `cargo metadata`: every crate the module crate
reaches through normal dependencies on the module's target. A procedural macro
runs at build time and is not followed. Each crate has to offer MIT as one of
a plain choice of licences and to ship the text as `LICENSE-MIT`; anything
else is refused, so a new kind of licence is a decision and not a side effect
of a dependency update.

The standard library part is a file per toolchain, tools/notices/, written
from the notice documents that toolchain ships. A toolchain without its file
is refused.

    check       generate, then compare with the committed notices and with the
                licence REUSE.toml names for the module; no network
    update      generate, then replace the committed notices
    selftest    plant one defect per rule and require each to be refused

Exit status: 0 equal, 1 the notices differ, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path

from toolkit import CheckError, run_command

TARGET = "wasm32-unknown-unknown"
PACKAGE = "amussis-decision-wasm"
MODULE = "bindings/go/decision/amussis_decision.wasm"
NOTICES = "bindings/go/decision/THIRD-PARTY-NOTICES.txt"
STANDARD_LIBRARY = "tools/notices/standard-library-{channel}.txt"
STANDARD_LIBRARY_LICENCES = ("MIT", "Unicode-3.0")
OWN_LICENCE = "EUPL-1.2"
TAKEN = "MIT"
TEXT_NAME = "LICENSE-MIT"
QUERY_DEADLINE_SECONDS = 120
MAX_CRATES = 2048
RULE = "=" * 80
THIN_RULE = "-" * 80

HEAD = """Third-party notices for amussis_decision.wasm

The WebAssembly module beside this file is built from the crates of this
repository, which are under {own}. It also holds code of the crates named
below and of the Rust standard library. Where a crate offers a choice of
licences, {taken} is the one taken.

Licence of the module as a whole: {expression}

tools/third_party_notices.py writes this file from Cargo.lock and from the
standard library part of the pinned toolchain; do not edit it by hand.
"""


def run(args: list[str], root: Path, deadline: int) -> str:
    return run_command(args, root, deadline).stdout


def read_text(path: Path) -> str | None:
    """The file as text with Unix line ends, or None when there is no such file."""
    try:
        return path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as error:
        raise CheckError(f"cannot read {path}: {error}") from error


def metadata(root: Path) -> dict:
    """The locked dependency graph for the module's target; no network."""
    args = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"]
    try:
        return json.loads(run([*args, "--filter-platform", TARGET], root, QUERY_DEADLINE_SECONDS))
    except json.JSONDecodeError as error:
        raise CheckError(f"cargo metadata printed no JSON: {error}") from error


def is_macro(package: dict) -> bool:
    return any("proc-macro" in target["kind"] for target in package["targets"])


def linked_crates(meta: dict) -> list[dict]:
    """Every registry crate the module links, ordered by name and version."""
    packages = {package["id"]: package for package in meta["packages"]}
    nodes = {node["id"]: node for node in meta["resolve"]["nodes"]}
    roots = [
        key
        for key, package in packages.items()
        if package["name"] == PACKAGE and package["source"] is None
    ]
    if len(roots) != 1:
        raise CheckError(f"the workspace holds {len(roots)} crates named {PACKAGE}, not one")
    seen = {roots[0]}
    queue = [roots[0]]
    for _ in range(MAX_CRATES):
        if not queue:
            break
        for dep in nodes[queue.pop()]["deps"]:
            normal = any(kind["kind"] is None for kind in dep["dep_kinds"])
            if normal and dep["pkg"] not in seen and not is_macro(packages[dep["pkg"]]):
                seen.add(dep["pkg"])
                queue.append(dep["pkg"])
    if queue:
        raise CheckError(f"the module links more than {MAX_CRATES} crates")
    linked = [packages[key] for key in seen if packages[key]["source"] is not None]
    return sorted(linked, key=lambda package: (package["name"], package["version"]))


def offered(expression: str | None) -> list[str] | None:
    """The licences a plain choice offers; None when the expression is no plain choice."""
    words = (expression or "").replace("/", " OR ").split()
    names = words[0::2]
    if not names or len(words) % 2 == 0 or any(word != "OR" for word in words[1::2]):
        return None
    if any("(" in name or ")" in name or name in ("AND", "OR", "WITH") for name in names):
        return None
    return names


def crate_part(package: dict, text: str | None) -> tuple[str, list[str]]:
    """The notice of one crate, and every reason it cannot be written."""
    name = f"{package['name']} {package['version']}"
    choice = offered(package.get("license"))
    found = []
    if choice is None:
        found.append(f"{name}: the licence `{package.get('license')}` is no plain choice of licences")
    elif TAKEN not in choice:
        found.append(f"{name}: the licence `{package['license']}` offers no {TAKEN}")
    if text is None or not text.strip():
        found.append(f"{name}: the crate ships no {TEXT_NAME}")
    body = "\n".join(line.rstrip() for line in (text or "").strip("\n").split("\n"))
    head = (
        f"{RULE}\n{name}\nhttps://crates.io/crates/{package['name']}/{package['version']}\n"
        f"Licence offered: {package.get('license')}; taken: {TAKEN}\n{THIN_RULE}\n"
    )
    return f"{head}{body}\n", found


def compose(
    crates: list[dict], texts: dict[str, str | None], channel: str, library: str | None
) -> tuple[str, str, list[str]]:
    """The notices, the licence of the module, and every reason they cannot be written."""
    licences = [OWN_LICENCE]
    for name in (TAKEN, *STANDARD_LIBRARY_LICENCES):
        if name not in licences:
            licences.append(name)
    expression = " AND ".join(licences)
    parts = [HEAD.format(own=OWN_LICENCE, taken=TAKEN, expression=expression)]
    found = []
    for package in crates:
        part, reasons = crate_part(package, texts.get(package["id"]))
        parts.append(part)
        found.extend(reasons)
    if library is None:
        found.append(
            f"{STANDARD_LIBRARY.format(channel=channel)} is missing: the standard library part "
            f"was not written for toolchain {channel}; write it from the notice documents that "
            "toolchain ships (share/doc/rust/COPYRIGHT-library.html)"
        )
    parts.append(library or "")
    return "\n".join(parts), expression, found


def annotated(reuse: dict, path: str) -> list[str]:
    """Every licence expression REUSE.toml names for one path."""
    return [
        str(table.get("SPDX-License-Identifier"))
        for table in reuse.get("annotations", [])
        if path in ([table["path"]] if isinstance(table.get("path"), str) else table.get("path", []))
    ]


def differences(generated: str, committed: str | None, expression: str, reuse: dict) -> list[str]:
    """Every reason the committed notices are not the notices of this tree."""
    found = []
    if committed is None:
        found.append(f"{NOTICES} is missing; write it with `tools/third_party_notices.py update`")
    elif committed != generated:
        found.append(
            f"{NOTICES} (sha256 {digest(committed)}) differs from the notices of this tree "
            f"(sha256 {digest(generated)}); write it with `tools/third_party_notices.py update` "
            "and commit the result"
        )
    for path in (MODULE, NOTICES):
        names = annotated(reuse, path)
        if names != [expression]:
            found.append(f"REUSE.toml names {names or 'no licence'} for {path}, not `{expression}`")
    return found


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def channel_of(root: Path) -> str:
    try:
        pinned = tomllib.loads(read_text(root / "rust-toolchain.toml") or "")
        return str(pinned["toolchain"]["channel"])
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise CheckError(f"rust-toolchain.toml names no toolchain channel: {error}") from error


def reuse_of(root: Path) -> dict:
    try:
        return tomllib.loads(read_text(root / "REUSE.toml") or "")
    except tomllib.TOMLDecodeError as error:
        raise CheckError(f"REUSE.toml is no TOML: {error}") from error


def generate(root: Path) -> tuple[str, str, list[str]]:
    """The notices of this tree, the licence of the module, and what stops them."""
    crates = linked_crates(metadata(root))
    texts = {
        package["id"]: read_text(Path(package["manifest_path"]).parent / TEXT_NAME) for package in crates
    }
    channel = channel_of(root)
    library = read_text(root / STANDARD_LIBRARY.format(channel=channel))
    return compose(crates, texts, channel, library)


def planted_graph() -> tuple[dict, dict[str, str]]:
    """A graph with one crate of each kind the walk has to tell apart."""

    def package(name: str, licence: str, source: str | None = "registry", kind: str = "lib") -> dict:
        return {
            "id": name,
            "name": name,
            "version": "1.0.0",
            "license": licence,
            "source": source,
            "targets": [{"kind": [kind]}],
            "manifest_path": f"/planted/{name}/Cargo.toml",
        }

    def node(name: str, deps: list[tuple[str, str | None]]) -> dict:
        return {"id": name, "deps": [{"pkg": pkg, "dep_kinds": [{"kind": kind}]} for pkg, kind in deps]}

    packages = [
        package(PACKAGE, OWN_LICENCE, source=None),
        package("own-library", OWN_LICENCE, source=None),
        package("linked", "MIT OR Apache-2.0"),
        package("linked-deeper", "Unlicense/MIT"),
        package("macro", "MIT", kind="proc-macro"),
        package("macro-only", "GPL-3.0-only"),
        package("build-only", "GPL-3.0-only"),
        package("test-only", "GPL-3.0-only"),
    ]
    nodes = [
        node(PACKAGE, [("own-library", None), ("test-only", "dev")]),
        node("own-library", [("linked", None), ("macro", None), ("build-only", "build")]),
        node("linked", [("linked-deeper", None)]),
        node("linked-deeper", []),
        node("macro", [("macro-only", None)]),
        node("macro-only", []),
        node("build-only", []),
        node("test-only", []),
    ]
    texts = {
        name: f"Copyright (c) the authors of {name}\n\nPermission is hereby granted.\n"
        for name in ("linked", "linked-deeper")
    }
    return {"packages": packages, "resolve": {"nodes": nodes}}, texts


def planted_cases() -> dict[str, tuple[list[str], str]]:
    """Each plant by name: what the checks find on it, and what they have to say."""
    meta, texts = planted_graph()
    crates = linked_crates(meta)
    library = f"{RULE}\nthe standard library\n"
    good, expression, clean = compose(crates, texts, "1.0.0", library)
    reuse = {"annotations": [{"path": [MODULE, NOTICES], "SPDX-License-Identifier": expression}]}
    listed = [package["name"] for package in crates]
    cases = {}
    if listed != ["linked", "linked-deeper"] or clean or differences(good, good, expression, reuse):
        cases["the planted graph without a defect"] = ([f"lists {listed}, finds {clean}"], "must pass")

    def licensed(licence: str | None) -> list[str]:
        changed = [dict(crates[0], license=licence), crates[1]]
        return compose(changed, texts, "1.0.0", library)[2]

    def committed(notices: str | None, annotations: dict) -> list[str]:
        return differences(good, notices, expression, annotations)

    only_own = {"annotations": [{"path": [MODULE, NOTICES], "SPDX-License-Identifier": OWN_LICENCE}]}
    only_module = {"annotations": [{"path": MODULE, "SPDX-License-Identifier": expression}]}
    without_text = compose(crates, {**texts, "linked-deeper": None}, "1.0.0", library)[2]
    empty_text = compose(crates, {**texts, "linked": " \n"}, "1.0.0", library)[2]
    one_crate = compose(crates[:1], texts, "1.0.0", library)[0]
    cases.update(
        {
            "a linked crate offers no MIT": (licensed("Apache-2.0 OR ISC"), "offers no MIT"),
            "a linked crate has a compound licence": (licensed("MIT AND Unicode-3.0"), "no plain choice"),
            "a linked crate has a licence with an exception": (
                licensed("Apache-2.0 WITH LLVM-exception OR MIT"),
                "no plain choice",
            ),
            "a linked crate has a licence in brackets": (licensed("(MIT OR Apache-2.0)"), "no plain choice"),
            "a linked crate names no licence": (licensed(None), "no plain choice"),
            "a linked crate ships no licence text": (without_text, f"ships no {TEXT_NAME}"),
            "a linked crate ships an empty licence text": (empty_text, f"ships no {TEXT_NAME}"),
            "no standard library part for the toolchain": (
                compose(crates, texts, "9.99.9", None)[2],
                "standard-library-9.99.9.txt is missing",
            ),
            "the committed notices lack one crate": (committed(one_crate, reuse), "differs from the notices"),
            "one word of the committed notices changed": (
                committed(good.replace("authors", "author", 1), reuse),
                "differs from the notices",
            ),
            "the committed notices are missing": (committed(None, reuse), "is missing"),
            "the committed notices are empty": (committed("", reuse), "differs from the notices"),
            "REUSE.toml gives the module the licence of the repository alone": (
                committed(good, only_own),
                f"for {MODULE}",
            ),
            "REUSE.toml does not name the notices": (committed(good, only_module), f"for {NOTICES}"),
        }
    )
    return cases


def selftest(root: Path) -> tuple[list[str], int]:
    """Each plant must be refused, and for the reason it was planted for."""
    generated, expression, found = generate(root)
    found.extend(differences(generated, read_text(root / NOTICES), expression, reuse_of(root)))
    failures = [f"the unplanted tree is refused: {line}" for line in found]
    cases = planted_cases()
    for name, (reasons, expected) in cases.items():
        if not reasons:
            failures.append(f"plant passed: {name}")
        elif not any(expected in line for line in reasons):
            failures.append(f"plant refused for another reason: {name}: {reasons}")
    return failures, len(cases)


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("command", choices=("check", "update", "selftest"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.command == "selftest":
            found, count = selftest(root)
            detail = f"{count} plants refused"
        else:
            generated, expression, found = generate(root)
            if args.command == "update" and not found:
                (root / NOTICES).write_text(generated, encoding="utf-8", newline="\n")
            found.extend(differences(generated, read_text(root / NOTICES), expression, reuse_of(root)))
            detail = f"{expression}, sha256 {digest(generated)}"
    except CheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"PASS: notices {args.command} ({detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
