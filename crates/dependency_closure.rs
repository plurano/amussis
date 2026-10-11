// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! D78: a crate's own dependency closure, read from `cargo metadata`.
//!
//! One file, included by path into the manifest-hygiene test of every crate
//! whose negative sweep reads its closure (`#[path = "../../dependency_closure.rs"]`),
//! so the rule D78 records has one definition rather than one per crate. It is
//! not a crate and has no manifest: a test helper that were a workspace member
//! would enter every closure it is meant to read.
//!
//! The closure is read the way D78 records it: from
//! `cargo metadata --format-version 1 --locked --offline --all-features`
//! without `--filter-platform`, starting at the one workspace member with the
//! crate's name, following every `resolve.nodes[].deps[].pkg` edge whatever its
//! `dep_kinds` (normal, dev and build alike), marking a node visited when it is
//! pushed so the walk is bounded by the node count, and matching package names
//! exactly. It fails closed on a spawn error, a non-zero exit, a missed
//! deadline (HISS-02), unparsable output, a null resolve, and zero or several
//! start nodes; an offline failure names `cargo fetch --locked` as the cure.
//!
//! What D78 gives up is recorded with it: no test forbids a crate
//! workspace-wide any more, so each sweep's guarantee holds for its own crate.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

/// How long `cargo metadata` may run.
pub const METADATA_DEADLINE: Duration = Duration::from_secs(120);

/// How often the deadline loop polls the child.
const POLL: Duration = Duration::from_millis(25);

/// The most polls one wait makes: 120 s / 25 ms.
const MAX_POLLS: u32 = 4_800;

/// Numbers each run within one test binary, so concurrent runs never share
/// an output file.
static RUNS: AtomicU32 = AtomicU32::new(0);

/// The arguments D78 records, in order.
pub const METADATA_ARGS: [&str; 6] = [
    "metadata",
    "--format-version",
    "1",
    "--locked",
    "--offline",
    "--all-features",
];

/// The workspace root, two directories above the including crate's manifest.
#[must_use]
pub fn workspace_root() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Some(manifest.parent()?.parent()?.to_path_buf())
}

/// Waits for `child` under `deadline`, killing it past the deadline.
fn wait(child: &mut Child, deadline: Duration) -> Result<ExitStatus, String> {
    let started = Instant::now();
    for _ in 0..=MAX_POLLS {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < deadline => std::thread::sleep(POLL),
            Ok(None) => break,
            Err(error) => return Err(format!("waiting for cargo metadata failed: {error}")),
        }
    }
    let killed = child.kill().and_then(|()| child.wait());
    Err(format!(
        "cargo metadata missed its {deadline:?} deadline; killed: {killed:?}"
    ))
}

/// One `cargo metadata` invocation: which program, which arguments, where.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// The program to run; `$CARGO` in a test run.
    pub program: OsString,
    /// The arguments, `METADATA_ARGS` for the real closure.
    pub args: Vec<String>,
    /// The directory it runs in.
    pub root: PathBuf,
    /// How long it may run.
    pub deadline: Duration,
}

impl Invocation {
    /// The invocation D78 records, in this workspace, under its deadline.
    ///
    /// # Errors
    ///
    /// Returns the reason when the workspace root cannot be derived.
    pub fn recorded() -> Result<Self, String> {
        Ok(Self {
            program: std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()),
            args: METADATA_ARGS.iter().map(|arg| (*arg).to_owned()).collect(),
            root: workspace_root().ok_or("no workspace root")?,
            deadline: METADATA_DEADLINE,
        })
    }

    /// Runs the invocation, output to files so no pipe can fill and stall
    /// the child, and returns the parsed document.
    ///
    /// # Errors
    ///
    /// Fails closed on a spawn error, a non-zero exit (naming
    /// `cargo fetch --locked`), a missed deadline and unparsable output.
    pub fn run(&self) -> Result<Value, String> {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let run = RUNS.fetch_add(1, Ordering::Relaxed);
        let stem = format!("{}-{}-{run}", env!("CARGO_PKG_NAME"), std::process::id());
        let (out, err) = (
            dir.join(format!("{stem}-metadata.json")),
            dir.join(format!("{stem}-metadata.err")),
        );
        let files = (std::fs::File::create(&out), std::fs::File::create(&err));
        let (Ok(stdout), Ok(stderr)) = files else {
            return Err("cannot create the metadata output files".to_owned());
        };
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|error| format!("cargo metadata could not be spawned: {error}"))?;
        let status = wait(&mut child, self.deadline)?;
        if !status.success() {
            let text = std::fs::read_to_string(&err).unwrap_or_default();
            return Err(format!(
                "cargo metadata exited {status}; if offline, run `cargo fetch --locked`: {text}"
            ));
        }
        let text = std::fs::read_to_string(&out).map_err(|error| error.to_string())?;
        serde_json::from_str(&text)
            .map_err(|error| format!("cargo metadata output is not JSON: {error}"))
    }
}

/// The workspace's metadata, read once per test binary.
///
/// # Errors
///
/// Returns why [`Invocation::run`] failed.
pub fn metadata() -> Result<Value, String> {
    static METADATA: OnceLock<Result<Value, String>> = OnceLock::new();
    METADATA
        .get_or_init(|| Invocation::recorded()?.run())
        .clone()
}

/// Maps every package id to its name.
fn names_by_id(metadata: &Value) -> Result<BTreeMap<&str, &str>, String> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("the metadata lists no packages")?;
    Ok(packages
        .iter()
        .filter_map(|entry| Some((entry.get("id")?.as_str()?, entry.get("name")?.as_str()?)))
        .collect())
}

/// The id of the one workspace member named `package`.
fn start_node<'a>(
    metadata: &'a Value,
    names: &BTreeMap<&str, &str>,
    package: &str,
) -> Result<&'a str, String> {
    let members = metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or("the metadata lists no workspace members")?;
    let starts: Vec<&str> = members
        .iter()
        .filter_map(Value::as_str)
        .filter(|id| names.get(id) == Some(&package))
        .collect();
    let [start] = starts.as_slice() else {
        return Err(format!(
            "{} workspace members are named {package}",
            starts.len()
        ));
    };
    Ok(start)
}

/// Every resolve node's outgoing `pkg` edges, whatever their `dep_kinds`.
fn edges(metadata: &Value) -> Result<(usize, BTreeMap<&str, Vec<&str>>), String> {
    let nodes = metadata
        .get("resolve")
        .and_then(|resolve| resolve.get("nodes"))
        .and_then(Value::as_array)
        .ok_or("the resolve is null")?;
    let edges = nodes
        .iter()
        .filter_map(|node| {
            let id = node.get("id")?.as_str()?;
            let deps = node.get("deps")?.as_array()?;
            Some((
                id,
                deps.iter()
                    .filter_map(|dep| dep.get("pkg")?.as_str())
                    .collect(),
            ))
        })
        .collect();
    Ok((nodes.len(), edges))
}

/// The package names in the closure of the one workspace member named
/// `package`, the member included.
///
/// # Errors
///
/// Fails closed on a document with no packages or members, a null resolve,
/// and zero or several start nodes.
pub fn closure(metadata: &Value, package: &str) -> Result<BTreeSet<String>, String> {
    let names = names_by_id(metadata)?;
    let start = start_node(metadata, &names, package)?;
    let (node_count, edges) = edges(metadata)?;
    let mut visited: BTreeSet<&str> = BTreeSet::from([start]);
    let mut stack = vec![start];
    for _ in 0..=node_count {
        let Some(id) = stack.pop() else { break };
        for dep in edges.get(id).map(Vec::as_slice).unwrap_or_default() {
            if visited.insert(dep) {
                stack.push(dep);
            }
        }
    }
    Ok(visited
        .iter()
        .filter_map(|id| names.get(id))
        .map(|name| (*name).to_owned())
        .collect())
}

/// The closure of `package` in this workspace's own metadata.
///
/// # Errors
///
/// Returns why the metadata could not be read or the closure not computed.
pub fn own_closure(package: &str) -> Result<BTreeSet<String>, String> {
    closure(&metadata()?, package)
}

/// The names of `forbidden` found in `names`, matched exactly and in the
/// order `forbidden` lists them.
#[must_use]
pub fn hits(names: &BTreeSet<String>, forbidden: &[&'static str]) -> Vec<&'static str> {
    forbidden
        .iter()
        .copied()
        .filter(|name| names.contains(*name))
        .collect()
}

/// Sets `key` on a JSON object; anything else is left as it is.
pub fn set(value: &mut Value, key: &str, new: Value) {
    if let Some(object) = value.as_object_mut() {
        object.insert(key.to_owned(), new);
    }
}

/// A small synthetic metadata document: `package`, a workspace member,
/// depending directly on each of `deps`.
#[must_use]
pub fn synthetic(package: &str, deps: &[&str]) -> Value {
    let mut packages = vec![serde_json::json!({ "id": "member", "name": package })];
    packages.extend(
        deps.iter()
            .map(|name| serde_json::json!({ "id": name, "name": name })),
    );
    let mut nodes = vec![serde_json::json!({
        "id": "member",
        "deps": deps.iter().map(|name| serde_json::json!({ "pkg": name })).collect::<Vec<_>>(),
    })];
    nodes.extend(
        deps.iter()
            .map(|name| serde_json::json!({ "id": name, "deps": [] })),
    );
    serde_json::json!({
        "packages": packages,
        "workspace_members": ["member"],
        "resolve": { "nodes": nodes },
    })
}

/// Plants `name` as a direct dependency of the workspace member `package`,
/// with the given `kind` (`Some("dev")`, `Some("build")` or `None` for a
/// normal dependency), the way
/// `cargo metadata` would report it after a manifest edit.
///
/// # Errors
///
/// Returns why the member could not be found.
pub fn plant(
    metadata: &mut Value,
    package: &str,
    name: &str,
    kind: Option<&str>,
) -> Result<(), String> {
    let names = names_by_id(metadata)?;
    let start = start_node(metadata, &names, package)?.to_owned();
    let id = format!("planted+{name}");
    if let Some(packages) = metadata.get_mut("packages").and_then(Value::as_array_mut) {
        packages.push(serde_json::json!({ "id": id, "name": name }));
    }
    let nodes = metadata
        .pointer_mut("/resolve/nodes")
        .and_then(Value::as_array_mut)
        .ok_or("the resolve is null")?;
    for node in nodes.iter_mut() {
        if node.get("id").and_then(Value::as_str) == Some(start.as_str()) {
            if let Some(deps) = node.get_mut("deps").and_then(Value::as_array_mut) {
                deps.push(serde_json::json!({
                    "name": name,
                    "pkg": id,
                    "dep_kinds": [{ "kind": kind, "target": null }],
                }));
            }
        }
    }
    nodes.push(serde_json::json!({ "id": id, "deps": [] }));
    Ok(())
}
