// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! Executable checks on the workspace manifests.
//!
//! The SHA-256-only hashing rule excludes MD5, the repository pins the toolchain, and the
//! workspace activates exactly one crate. Each of those is a claim about files
//! rather than about code, so each is asserted here rather than left as prose.

#[path = "../../dependency_closure.rs"]
mod dependency_closure;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cargo_metadata::Metadata;

/// This crate's package name, the start of its dependency closure.
const PACKAGE: &str = "amussis-decision";

/// The MD5 implementations the SHA-256-only rule excludes from this crate's
/// closure. The earlier lock-wide sweep searched for four spellings, `"md5"`, `"md-5"`,
/// `name = "md5` and `name = "md-5`; they name these two packages, and the
/// closure matches names exactly. The last two had no closing quote, so they
/// also refused any package whose name merely starts with `md5` or `md-5`
/// (`md5-asm`, say); the exact-name closure rule gives that prefix coverage up, and
/// `a_prefixed_md5_name_is_not_a_hit` records it.
const FORBIDDEN: [&str; 2] = ["md5", "md-5"];

/// Returns the workspace root, two directories above this crate's manifest.
fn workspace_root() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Some(manifest.parent()?.parent()?.to_path_buf())
}

/// Reads a workspace file, returning `None` when it is missing.
fn read(name: &str) -> Option<String> {
    std::fs::read_to_string(workspace_root()?.join(name)).ok()
}

/// The resolved dependency graph contains no MD5 implementation.
///
/// The graph is this crate's own dependency closure, read from `cargo metadata`,
/// rather than the whole lock; the SHA-256 implementation must still be locked
/// and in the closure.
#[test]
fn the_lock_file_contains_no_md5_implementation() -> Result<(), String> {
    let names = dependency_closure::own_closure(PACKAGE)?;
    let found = dependency_closure::hits(&names, &FORBIDDEN);
    assert!(
        found.is_empty(),
        "the closure of {PACKAGE} must not contain {found:?}: SHA-256-only hashing excludes MD5"
    );
    assert!(
        names.contains("sha2"),
        "the closure must contain the SHA-256 implementation"
    );
    let lock = read("Cargo.lock").unwrap_or_default();
    assert!(!lock.is_empty(), "Cargo.lock must be committed");
    assert!(
        lock.contains("name = \"sha2\""),
        "the resolved lock must contain the SHA-256 implementation"
    );
    Ok(())
}

/// Negative: an MD5 implementation planted in this crate's own closure, as a
/// dev or a normal dependency, fails the sweep.
#[test]
fn a_planted_md5_crate_fails_the_sweep() -> Result<(), String> {
    let mut planted = dependency_closure::metadata()?;
    dependency_closure::plant(&mut planted, PACKAGE, "md5", Some("dev"))?;
    dependency_closure::plant(&mut planted, PACKAGE, "md-5", None)?;
    let names = dependency_closure::closure(&planted, PACKAGE)?;
    assert_eq!(
        dependency_closure::hits(&names, &FORBIDDEN),
        vec!["md5", "md-5"]
    );
    Ok(())
}

/// Boundary: names match exactly, so a package whose name only starts with an
/// MD5 spelling is not a hit. The earlier lock-wide search refused it
/// through its unterminated `name = "md5` token; that coverage is given up.
#[test]
fn a_prefixed_md5_name_is_not_a_hit() -> Result<(), String> {
    let prefixed = dependency_closure::synthetic(PACKAGE, &["md5-asm", "md-5-extra"])?;
    let names = dependency_closure::closure(&prefixed, PACKAGE)?;
    assert_eq!(
        dependency_closure::hits(&names, &FORBIDDEN),
        [] as [&str; 0]
    );
    Ok(())
}

/// Negative: malformed metadata fails closed instead of yielding an empty
/// closure that would pass the sweep: text cut short, a document without
/// `packages`, and a resolve edge without its `pkg`.
#[test]
fn malformed_metadata_is_refused() -> Result<(), String> {
    let valid = serde_json::to_string(&dependency_closure::synthetic(PACKAGE, &["sha2"])?)
        .map_err(|error| error.to_string())?;
    let truncated = valid.get(..valid.len() / 2).unwrap_or_default();
    let without_packages = valid.replacen("\"packages\"", "\"pakages\"", 1);
    let without_pkg = valid.replacen("\"pkg\"", "\"pgk\"", 1);
    for (case, text) in [
        ("truncated", truncated),
        ("without packages", without_packages.as_str()),
        ("without pkg", without_pkg.as_str()),
    ] {
        let error = dependency_closure::parse(text)
            .err()
            .ok_or(format!("{case}: malformed metadata was accepted"))?;
        assert!(error.contains("not valid metadata"), "{case}: {error}");
    }
    let names = dependency_closure::closure(&dependency_closure::parse(&valid)?, PACKAGE)?;
    assert!(
        names.contains("sha2"),
        "the well-formed document must parse"
    );
    Ok(())
}

/// The crate manifest declares no MD5 dependency and no unexpected one.
///
/// `serde` and `serde_json` are reviewed dependencies: the proposal schema
/// and the encoding rules read and write JSON whatever schemas an adapter
/// declares, so both stay after the operating system's schemas left.
#[test]
fn the_crate_manifest_declares_only_the_reviewed_dependencies() {
    let manifest = read("crates/amussis-decision/Cargo.toml").unwrap_or_default();
    assert!(!manifest.is_empty(), "the crate manifest must exist");
    assert!(
        !manifest.contains("md5"),
        "SHA-256-only hashing excludes MD5"
    );
    assert!(
        !manifest.contains("md-5"),
        "SHA-256-only hashing excludes MD5"
    );
    assert!(
        !manifest.contains("[[bin]]"),
        "this crate ships a library only"
    );
    for expected in ["sha2", "base16ct", "thiserror", "serde", "serde_json"] {
        assert!(
            manifest.contains(&format!("\n{expected}.workspace = true")),
            "the manifest must declare {expected}"
        );
    }
    let declared = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .map_or(0, |table| {
            table.lines().filter(|line| line.contains('=')).count()
        });
    assert_eq!(declared, 5, "a sixth dependency needs a review first");
    for deferred in ["tokio", "dbus", "zbus", "tss-esapi", "aya", "libbpf"] {
        assert!(
            !manifest.contains(deferred),
            "{deferred} is not part of this crate"
        );
    }
}

/// The toolchain pin names an exact version, not a moving channel.
#[test]
fn the_toolchain_pin_is_an_exact_version() {
    let toolchain = read("rust-toolchain.toml").unwrap_or_default();
    assert!(
        !toolchain.is_empty(),
        "rust-toolchain.toml must be committed"
    );
    for moving in ["\"stable\"", "\"beta\"", "\"nightly\""] {
        assert!(
            !toolchain.contains(moving),
            "the channel must be an exact version, not {moving}"
        );
    }
    let channel = toolchain
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = "))
        .unwrap_or_default()
        .trim_matches('"')
        .to_owned();
    let parts: Vec<&str> = channel.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "the pinned channel must be a three-component version, found {channel:?}"
    );
    for part in parts {
        assert!(
            part.chars().all(|c| c.is_ascii_digit()) && !part.is_empty(),
            "the pinned channel component {part:?} must be numeric"
        );
    }
    assert!(toolchain.contains("clippy"), "the pin must carry clippy");
    assert!(toolchain.contains("rustfmt"), "the pin must carry rustfmt");
}

/// A `rust-version`: major, minor and patch.
type RustVersion = (u64, u64, u64);

/// Parses `1.87` or `1.98.1` into comparable numbers.
fn rust_version(text: &str) -> Option<RustVersion> {
    let mut parts = text.split('.').map(str::parse::<u64>);
    let major = parts.next()?.ok()?;
    let minor = parts.next()?.ok()?;
    let patch = parts.next().unwrap_or(Ok(0)).ok()?;
    Some((major, minor, patch))
}

/// The value of the first line of `text` that reads `key = "..."`.
fn quoted_value(text: &str, key: &str) -> Option<RustVersion> {
    let prefix = format!("{key} = \"");
    let line = text.lines().find(|line| line.starts_with(&prefix))?;
    rust_version(line.strip_prefix(&prefix)?.strip_suffix('"')?)
}

/// The highest `rust_version` any package outside the workspace declares,
/// with the packages that declare it.
fn highest_declared(metadata: &Metadata) -> Result<(RustVersion, Vec<String>), String> {
    let members: BTreeSet<&str> = metadata
        .workspace_members
        .iter()
        .map(|id| id.repr.as_str())
        .collect();
    let declared: Vec<(RustVersion, String)> = metadata
        .packages
        .iter()
        .filter(|package| !members.contains(package.id.repr.as_str()))
        .filter_map(|package| {
            let version = package.rust_version.as_ref()?;
            let tuple = (version.major, version.minor, version.patch);
            Some((tuple, package.name.to_string()))
        })
        .collect();
    let highest = declared
        .iter()
        .map(|(version, _)| *version)
        .max()
        .ok_or("none declared")?;
    let names = declared
        .into_iter()
        .filter(|(version, _)| *version == highest)
        .map(|(_, name)| name)
        .collect();
    Ok((highest, names))
}

/// The workspace `rust-version` is the pinned toolchain, the only Rust any
/// job builds with, and no resolved package declares more than that pin.
/// The settings source requires the same equality.
fn judge_rust_version(
    declared: RustVersion,
    pin: RustVersion,
    highest: RustVersion,
) -> Result<(), String> {
    if declared != pin {
        return Err(format!("rust-version {declared:?} is not the pin {pin:?}"));
    }
    if highest > pin {
        return Err(format!(
            "the graph declares {highest:?}, above the pin {pin:?}"
        ));
    }
    Ok(())
}

/// Positive: the workspace `rust-version` equals the `rust-toolchain.toml`
/// pin, and the highest `rust-version` any resolved package declares, read
/// from `cargo metadata`, is not above it. A declared minimum below the pin
/// would claim a Rust that no job builds with.
#[test]
fn the_workspace_rust_version_is_the_pinned_toolchain() -> Result<(), String> {
    let (highest, names) = highest_declared(&dependency_closure::metadata()?)?;
    let manifest = read("Cargo.toml").unwrap_or_default();
    let declared = quoted_value(&manifest, "rust-version").ok_or("no rust-version")?;
    let toolchain = read("rust-toolchain.toml").unwrap_or_default();
    let pin = quoted_value(&toolchain, "channel").ok_or("no channel")?;
    judge_rust_version(declared, pin, highest).map_err(|error| format!("{error}; {names:?}"))
}

/// Negative: a `rust-version` one release below the pin is refused, and so
/// is a resolved package that declares one release above it.
#[test]
fn a_rust_version_off_the_pin_is_refused() -> Result<(), String> {
    let toolchain = read("rust-toolchain.toml").unwrap_or_default();
    let pin = quoted_value(&toolchain, "channel").ok_or("no channel")?;
    let (major, minor, patch) = pin;
    let below = quoted_value(
        &format!("rust-version = \"{major}.{}\"", minor.saturating_sub(1)),
        "rust-version",
    )
    .ok_or("unparsed")?;
    let error = judge_rust_version(below, pin, below)
        .err()
        .ok_or("a rust-version below the pin passed")?;
    assert!(error.contains("is not the pin"), "{error}");
    let above = (major, minor.saturating_add(1), patch);
    let error = judge_rust_version(pin, pin, above)
        .err()
        .ok_or("a dependency above the pin passed")?;
    assert!(error.contains("above the pin"), "{error}");
    Ok(())
}

/// Boundary: a resolved package that declares exactly the pin is admitted,
/// and one patch release above it is not; a version read without a patch
/// release is the `.0` release.
#[test]
fn the_graph_may_reach_the_pin_and_no_further() -> Result<(), String> {
    let toolchain = read("rust-toolchain.toml").unwrap_or_default();
    let pin = quoted_value(&toolchain, "channel").ok_or("no channel")?;
    let (major, minor, patch) = pin;
    judge_rust_version(pin, pin, pin)?;
    let error = judge_rust_version(pin, pin, (major, minor, patch.saturating_add(1)))
        .err()
        .ok_or("one patch release above the pin passed")?;
    assert!(error.contains("above the pin"), "{error}");
    assert_eq!(
        quoted_value(&format!("channel = \"{major}.{minor}\""), "channel"),
        Some((major, minor, 0))
    );
    Ok(())
}

/// The workspace activates exactly the crate directories that have a manifest.
///
/// The member list is written out: a glob would activate any reserved crate
/// directory the moment it gained a manifest, with no review.
///
/// The count is derived rather than written down. A literal had to be edited
/// in three crates at once each time the workspace added members, which is
/// duplicated mutable state of exactly the kind the repository has a gate
/// against. The invariant behind it -- a directory with a manifest is a member,
/// and nothing else is -- is what is held here.
#[test]
fn the_workspace_activates_only_the_promoted_crates() {
    let root = read("Cargo.toml").unwrap_or_default();
    assert!(!root.is_empty(), "the workspace root manifest must exist");
    let members: Vec<String> = root
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("\"crates/"))
        .map(|line| line.trim_matches(|c| c == '"' || c == ',').to_owned())
        .collect();
    let directories = crate_directories_with_a_manifest();
    assert!(!directories.is_empty(), "crates/ must hold manifests");
    assert_eq!(
        members.len(),
        directories.len(),
        "the member list must name only the activated crates, found {members:?}"
    );
    for promoted in &directories {
        assert!(
            members
                .iter()
                .any(|member| member == &format!("crates/{promoted}")),
            "the member list must name {promoted}"
        );
    }
    assert!(
        !root.contains("crates/*"),
        "the member list must be written out, never globbed"
    );
}

/// Returns every directory under `crates/` that carries a manifest, sorted.
fn crate_directories_with_a_manifest() -> Vec<String> {
    let Some(root) = workspace_root() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(root.join("crates")) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .flatten()
        .take(64)
        .filter(|entry| entry.path().join("Cargo.toml").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort_unstable();
    found
}

/// The workspace's own package metadata is pinned.
///
/// These three assertions used to sit at the end of
/// `the_workspace_activates_only_the_promoted_crates`. Deriving the member
/// count from the tree had nothing to do with them, so they are their own test
/// rather than collateral of that refactor: the resolver version changes how
/// features are unified across the whole workspace, and the licence and
/// repository fields are inherited by every crate through
/// `license.workspace = true` and `repository.workspace = true`, so a change
/// to either silently restamps every manifest in the tree.
///
/// Nothing else in the repository reads these fields:
/// `tools/verify_preparation.py` opens the root manifest for
/// `workspace.members` only.
#[test]
fn the_workspace_package_metadata_is_pinned() {
    let root = read("Cargo.toml").unwrap_or_default();
    assert!(!root.is_empty(), "the workspace root manifest must exist");
    assert!(
        root.contains("resolver = \"3\""),
        "the resolver version must stay pinned at 3"
    );
    assert!(
        root.contains("license = \"EUPL-1.2\""),
        "the workspace licence every crate inherits must stay EUPL-1.2"
    );
    assert!(
        root.contains("https://github.com/plurano/amussis"),
        "the repository every crate inherits must stay the canonical remote"
    );
}

/// HISS-04 is mechanised: without clippy.toml the thresholds stay at the
/// clippy defaults of 100 lines and a cognitive complexity of 25.
#[test]
fn the_complexity_thresholds_are_configured() {
    let config = read("clippy.toml").unwrap_or_default();
    assert!(!config.is_empty(), "clippy.toml must be committed");
    assert!(config.contains("too-many-lines-threshold = 60"));
    assert!(config.contains("cognitive-complexity-threshold = 10"));
}

/// MD5 appears nowhere in the crate's own code.
///
/// The API-level exclusion is asserted in `audit_ledger.rs`; this is the
/// file-level half, and unlike a local array literal it is a property of the
/// crate: adding an `Md5` variant, an md5 backend or an `md5` serialisation
/// alias anywhere under `src/` fails here. Comment lines are excluded, because
/// the documentation has to be able to say that MD5 is excluded.
#[test]
fn the_crate_source_names_no_md5_implementation() {
    let mut offenders: Vec<String> = Vec::new();
    for (path, body) in crate_sources() {
        let lowered = code_only(&body).to_lowercase();
        for token in ["md5", "md-5"] {
            if lowered.contains(token) {
                offenders.push(format!("{path}: {token}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "SHA-256-only hashing excludes MD5 from the crate itself, found: {offenders:?}"
    );
}

/// The library uses `unwrap_or` in exactly the six places the crate
/// documentation inventories.
///
/// HISS-07 bans `unwrap` and `expect` outright, which clippy enforces. This
/// catches the looser failure: an inventory in the documentation that has
/// drifted from the code it claims to describe.
#[test]
fn the_unwrap_or_inventory_is_exact() {
    let expected = [
        ("identity.rs", 2usize),
        ("ledger/hash.rs", 1),
        ("ledger/signer.rs", 1),
        ("engine.rs", 1),
        ("ledger/mod.rs", 1),
    ];
    let mut found: Vec<(String, usize)> = Vec::new();
    let mut total = 0usize;
    for (path, body) in crate_sources() {
        let count = code_only(&body).matches("unwrap_or").count();
        if count > 0 {
            found.push((path, count));
            total = total.saturating_add(count);
        }
    }
    assert_eq!(total, 6, "the inventory claims six sites, found {found:?}");
    for (suffix, count) in expected {
        let hit = found
            .iter()
            .find(|(path, _)| path.ends_with(suffix))
            .map(|(_, count)| *count);
        assert_eq!(
            hit,
            Some(count),
            "the inventory claims {count} site(s) in {suffix}, found {hit:?}"
        );
    }
    assert_eq!(
        found.len(),
        expected.len(),
        "an undocumented file uses unwrap_or: {found:?}"
    );
}

/// Returns `body` with every whole-line comment removed, so a scan sees code.
///
/// The crate documents its own exclusions, so a naive token scan would be
/// satisfied by the prose that promises the token is absent.
fn code_only(body: &str) -> String {
    body.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<&str>>()
        .join("\n")
}

/// Spells `path` with `/` between its parts on every platform, so one
/// expected path matches a checkout on Windows as well.
fn slash_separated(path: &Path) -> String {
    let parts: Vec<String> = path
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    parts.join("/")
}

/// The spelling is the same whichever separator the platform reads.
#[test]
fn a_relative_path_is_spelt_with_slashes_on_every_platform() {
    let native: PathBuf = ["ledger", "hash.rs"].iter().collect();
    assert_eq!(slash_separated(&native), "ledger/hash.rs");
    assert_eq!(slash_separated(Path::new("identity.rs")), "identity.rs");
    assert_eq!(slash_separated(Path::new("")), "");
}

/// Reads every `.rs` file under the crate's `src/`, relative path and body,
/// the path spelt with `/` on every platform.
///
/// The walk is iterative and doubly bounded: at most 64 directories and at most
/// 64 entries per directory.
fn crate_sources() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![src.clone()];
    for _ in 0..64 {
        let Some(directory) = stack.pop() else { break };
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten().take(64) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let relative = slash_separated(path.strip_prefix(&src).unwrap_or(&path));
            out.push((relative, std::fs::read_to_string(&path).unwrap_or_default()));
        }
    }
    out
}

/// The library names the host environment in exactly one module.
#[test]
fn host_effects_are_confined_to_the_effects_module() {
    let root = workspace_root().unwrap_or_default();
    let src = root.join("crates/amussis-decision/src");
    let mut offenders: Vec<String> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![src.clone()];
    // Bounded walk: the crate has fewer than 64 source entries.
    for _ in 0..64 {
        let Some(directory) = stack.pop() else { break };
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten().take(64) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            if path.starts_with(src.join("effects")) {
                continue;
            }
            let body = std::fs::read_to_string(&path).unwrap_or_default();
            if body.contains("SystemTime") || body.contains("std::fs") {
                offenders.push(path.display().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "only src/effects/ may touch the host environment, found: {offenders:?}"
    );
}
