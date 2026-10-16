// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! A crate's own dependency closure, read from `cargo metadata`.
//!
//! One file, included by path into the manifest-hygiene test of every crate
//! whose negative sweep reads its closure (`#[path = "../../dependency_closure.rs"]`),
//! so the closure rule has one definition rather than one per crate. It is
//! not a crate and has no manifest: a test helper that were a workspace member
//! would enter every closure it is meant to read.
//!
//! The closure is read from
//! `cargo metadata --format-version 1 --locked --offline --all-features`
//! without `--filter-platform`, starting at the one workspace member with the
//! crate's name, following every `resolve.nodes[].deps[].pkg` edge whatever its
//! `dep_kinds` (normal, dev and build alike), marking a node visited when it is
//! pushed so the walk is bounded by the node count, and matching package names
//! exactly. The walk reads `cargo_metadata`'s typed `Metadata`. It fails closed
//! on a spawn error, a non-zero exit, a missed deadline (HISS-02), unparsable
//! output, a null resolve, and zero or several start nodes; an offline failure
//! names `cargo fetch --locked` as the cure.
//!
//! This own-closure rule does not forbid a crate workspace-wide, so each
//! sweep's guarantee holds for its own crate.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use cargo_metadata::{Metadata, MetadataCommand, Node, NodeDep, Package, PackageId};

/// How long `cargo metadata` may run.
pub const METADATA_DEADLINE: Duration = Duration::from_secs(120);

/// How often the deadline loop polls the child.
const POLL: Duration = Duration::from_millis(25);

/// The most polls one wait makes: 120 s / 25 ms.
const MAX_POLLS: u32 = 4_800;

/// Numbers each run within one test binary, so concurrent runs never share
/// an output file.
static RUNS: AtomicU32 = AtomicU32::new(0);

/// The `cargo metadata` arguments for the closure query, in order.
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
    /// The workspace's closure-query invocation under its deadline.
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
    pub fn run(&self) -> Result<Metadata, String> {
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
        parse(&text)
    }
}

/// Parses `cargo metadata` output into the typed document.
///
/// # Errors
///
/// Fails closed on text that is not JSON or lacks a field the format
/// requires, such as `packages` or a resolve edge's `pkg`.
pub fn parse(text: &str) -> Result<Metadata, String> {
    MetadataCommand::parse(text)
        .map_err(|error| format!("cargo metadata output is not valid metadata: {error}"))
}

/// The workspace's metadata, read once per test binary.
///
/// # Errors
///
/// Returns why [`Invocation::run`] failed.
pub fn metadata() -> Result<Metadata, String> {
    static METADATA: OnceLock<Result<Metadata, String>> = OnceLock::new();
    METADATA
        .get_or_init(|| Invocation::recorded()?.run())
        .clone()
}

/// Maps every package id to its name.
fn names_by_id(metadata: &Metadata) -> BTreeMap<&PackageId, &str> {
    metadata
        .packages
        .iter()
        .map(|package| (&package.id, package.name.as_str()))
        .collect()
}

/// The id of the one workspace member named `package`.
fn start_node<'a>(
    metadata: &'a Metadata,
    names: &BTreeMap<&PackageId, &str>,
    package: &str,
) -> Result<&'a PackageId, String> {
    let starts: Vec<&PackageId> = metadata
        .workspace_members
        .iter()
        .filter(|id| names.get(id).copied() == Some(package))
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
fn edges(metadata: &Metadata) -> Result<(usize, BTreeMap<&PackageId, Vec<&PackageId>>), String> {
    let resolve = metadata.resolve.as_ref().ok_or("the resolve is null")?;
    let edges = resolve
        .nodes
        .iter()
        .map(|node| (&node.id, node.deps.iter().map(|dep| &dep.pkg).collect()))
        .collect();
    Ok((resolve.nodes.len(), edges))
}

/// The package names in the closure of the one workspace member named
/// `package`, the member included.
///
/// # Errors
///
/// Fails closed on a document with no packages or members, a null resolve,
/// and zero or several start nodes.
pub fn closure(metadata: &Metadata, package: &str) -> Result<BTreeSet<String>, String> {
    let names = names_by_id(metadata);
    let start = start_node(metadata, &names, package)?;
    let (node_count, edges) = edges(metadata)?;
    let mut visited: BTreeSet<&PackageId> = BTreeSet::from([start]);
    let mut stack = vec![start];
    for _ in 0..=node_count {
        let Some(id) = stack.pop() else { break };
        for &dep in edges.get(id).map(Vec::as_slice).unwrap_or_default() {
            if visited.insert(dep) {
                stack.push(dep);
            }
        }
    }
    Ok(visited
        .iter()
        .filter_map(|&id| names.get(id).copied())
        .map(str::to_owned)
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

/// A minimal package JSON object for synthetic and planted packages.
fn package_json(name: &str, id: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name, "version": "0.1.0", "id": id,
        "dependencies": [], "targets": [], "features": {},
        "manifest_path": "/synthetic/Cargo.toml",
    })
}

/// A small synthetic metadata document: `package`, a workspace member,
/// depending directly on each of `deps`.
///
/// # Errors
///
/// Returns the reason when the synthetic metadata cannot be parsed.
pub fn synthetic(package: &str, deps: &[&str]) -> Result<Metadata, String> {
    let mut packages = vec![package_json(package, "member")];
    packages.extend(deps.iter().map(|name| package_json(name, name)));
    let member_deps: Vec<_> = deps
        .iter()
        .map(|name| serde_json::json!({ "name": name, "pkg": name }))
        .collect();
    let mut nodes = vec![serde_json::json!({
        "id": "member", "dependencies": deps, "deps": member_deps,
    })];
    nodes.extend(
        deps.iter()
            .map(|name| serde_json::json!({ "id": name, "dependencies": [], "deps": [] })),
    );
    let json = serde_json::json!({
        "packages": packages,
        "workspace_members": ["member"],
        "resolve": { "nodes": nodes },
        "workspace_root": "/synthetic",
        "target_directory": "/synthetic/target",
        "version": 1,
    });
    parse(&json.to_string())
}

/// Plants `name` as a direct dependency of the workspace member `package`,
/// with the given `kind` (`Some("dev")`, `Some("build")` or `None` for a
/// normal dependency), the way
/// `cargo metadata` would report it after a manifest edit.
///
/// # Errors
///
/// Returns why the member could not be found or the resolve is null.
pub fn plant(
    metadata: &mut Metadata,
    package: &str,
    name: &str,
    kind: Option<&str>,
) -> Result<(), String> {
    let names = names_by_id(metadata);
    let start = start_node(metadata, &names, package)?.clone();
    let id = format!("planted+{name}");
    let pkg: Package =
        serde_json::from_value(package_json(name, &id)).map_err(|error| error.to_string())?;
    metadata.packages.push(pkg);
    let resolve = metadata.resolve.as_mut().ok_or("the resolve is null")?;
    let dep: NodeDep = serde_json::from_value(serde_json::json!({
        "name": name, "pkg": id, "dep_kinds": [{ "kind": kind, "target": null }],
    }))
    .map_err(|error| error.to_string())?;
    for node in &mut resolve.nodes {
        if node.id == start {
            node.deps.push(dep.clone());
        }
    }
    let node: Node = serde_json::from_value(serde_json::json!({
        "id": id, "dependencies": [], "deps": [],
    }))
    .map_err(|error| error.to_string())?;
    resolve.nodes.push(node);
    Ok(())
}
