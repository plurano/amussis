<!--
SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
SPDX-License-Identifier: EUPL-1.2
-->

# Exceptions

The workspace forbids `unsafe` code. The export file
`crates/amussis-decision-wasm/src/abi.rs` needs the allowance for linkage alone
(`unsafe extern` for the imports, `#[unsafe(no_mangle)]` for the exports) and
is named in `exceptions.toml` with one file, one rule, a reason and an end date
at most 90 days ahead. `tools/exceptions_check.py` fails on any other file that
lowers the lint, on an entry whose file lowers nothing, and on an entry past its
date: a lapsed exception excuses nothing.

The same check holds `.github/rulesets/main.json` to the workflows. The Praetor
engine writes that file, and for a job that calls another workflow it requires
the calling job's own name. A run reports such a job as
`<calling job> / <called job>`, so the required name is never reported
(cordanaLLM/praetor#1212). The check reads every workflow's job names and the
rule set: a required name that is the bare name of a calling job needs a live
entry for the rule-set file, a required name no job carries is refused with or
without one, and an entry is refused once no such name is left. No job here
calls another workflow today, so the list holds no such entry; the selftest
plants a calling job to keep the rule proven.

Functions come out in another order on Windows and on macOS: the order
follows the `-C metadata` values cargo passes to the compiler, which differ
from host to host and which no stable setting fixes (issue #2).

`tools/module-compare` removes the order from the comparison. It labels every
function by its type, locals and instructions, with call targets replaced by
the labels of the called functions over twelve rounds, and compares the two
sets of labels. Element segments, exports and the start function are compared
through those labels. Every other section is compared byte for byte, and the
data section is reported as its own class. The tool refuses a module it cannot
fully read, such as one with a duplicate data or start section or element
items in expression form, instead of passing it.

On a Windows or macOS host whose build differs from the committed bytes,
`tools/wasm_module.py check` fails on any code or data difference and passes an
order-only difference with a notice. It still refuses a build that is no module
or holds a machine path, and a missing module. Every other host is held to the
bytes. An entry of the retired rule `module-byte-comparison` is refused by
`tools/exceptions_check.py` like any unknown rule.
