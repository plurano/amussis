// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Executable checks on the workspace manifests.
//!
//! Decision D02 excludes MD5, the milestone pins the toolchain, and the
//! workspace activates exactly one crate. Each of those is a claim about files
//! rather than about code, so each is asserted here rather than left as prose.

use std::path::{Path, PathBuf};

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
#[test]
fn the_lock_file_contains_no_md5_implementation() {
    let lock = read("Cargo.lock").unwrap_or_default();
    assert!(!lock.is_empty(), "Cargo.lock must be committed");
    for token in ["\"md5\"", "\"md-5\"", "name = \"md5", "name = \"md-5"] {
        assert!(
            !lock.contains(token),
            "the resolved lock must not contain {token}: D02 excludes MD5"
        );
    }
    assert!(
        lock.contains("name = \"sha2\""),
        "the resolved lock must contain the SHA-256 implementation"
    );
}

/// The crate manifest declares no MD5 dependency and no unexpected one.
#[test]
fn the_crate_manifest_declares_only_the_reviewed_dependencies() {
    let manifest = read("crates/aegis-justitia/Cargo.toml").unwrap_or_default();
    assert!(!manifest.is_empty(), "the crate manifest must exist");
    assert!(!manifest.contains("md5"), "D02 excludes MD5");
    assert!(!manifest.contains("md-5"), "D02 excludes MD5");
    assert!(
        !manifest.contains("[[bin]]"),
        "milestone M02 ships a library only"
    );
    for expected in ["sha2", "base16ct", "thiserror"] {
        assert!(
            manifest.contains(expected),
            "the manifest must declare {expected}"
        );
    }
    for deferred in ["tokio", "dbus", "zbus", "tss-esapi", "aya", "libbpf"] {
        assert!(
            !manifest.contains(deferred),
            "{deferred} is deferred past milestone M02"
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

/// The workspace activates exactly the crates the milestones promote.
///
/// M02 promoted `aegis-justitia` and M03 promoted `aegis-fabrica-defs`, so the
/// list grows by a named entry per milestone. What must not change is that it
/// is written out: a glob would activate the reserved crate directories the
/// moment one of them gained a manifest, with no review.
#[test]
fn the_workspace_activates_only_the_promoted_crates() {
    let root = read("Cargo.toml").unwrap_or_default();
    assert!(!root.is_empty(), "the workspace root manifest must exist");
    assert!(
        root.contains("members = [\"crates/aegis-fabrica-defs\", \"crates/aegis-justitia\"]"),
        "the member list must be explicit and name only the activated crates"
    );
    assert!(
        !root.contains("crates/*"),
        "a glob would activate the reserved crate directories"
    );
    assert!(root.contains("resolver = \"3\""));
    assert!(root.contains("license = \"EUPL-1.2\""));
    assert!(root.contains("https://github.com/cordanaLLM/Aegis-OS"));
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
        "D02 excludes MD5 from the crate itself, found: {offenders:?}"
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

/// Reads every `.rs` file under the crate's `src/`, relative path and body.
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
            let relative = path
                .strip_prefix(&src)
                .unwrap_or(&path)
                .display()
                .to_string();
            out.push((relative, std::fs::read_to_string(&path).unwrap_or_default()));
        }
    }
    out
}

/// The library names the host environment in exactly one module.
#[test]
fn host_effects_are_confined_to_the_effects_module() {
    let root = workspace_root().unwrap_or_default();
    let src = root.join("crates/aegis-justitia/src");
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
