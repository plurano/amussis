// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The generalised public-surface sweep.
//!
//! HISS-15 asks for positive, negative and boundary coverage of every public
//! interface. Reviewing that by hand caught individual holes and then let new
//! ones in, so the sweep is mechanised here instead of repeated by eye.
//!
//! The rule is deliberately crude and therefore checkable: every name the
//! crate's `src/` declares as public API -- a type, an enum variant, a method,
//! a trait item, an associated or free constant -- must appear as a whole
//! identifier in at least one integration test. A public item with no test
//! reference is either untested surface or surface that should not exist; both
//! are findings, and this file turns either into a failed gate.
//!
//! What the rule does not claim: a name that appears is not thereby proved
//! correct. The triples that exercise these items live in the other test files,
//! `public_surface_triples.rs` included. This sweep only guarantees that none
//! of them is forgotten.
//!
//! This file excludes itself from the scanned test sources. A sweep that could
//! read its own expectation list would pass by naming the names it checks.

use std::path::{Path, PathBuf};

/// This file's name, excluded from the scanned test sources.
const SWEEP_FILE: &str = "public_surface.rs";

/// Scalar bound on directories visited and entries read per directory.
const WALK_BOUND: usize = 64;

/// Scalar bound on the lines read from any one source file.
const LINE_BOUND: usize = 4096;

/// The smallest public surface the scanner may report before it is assumed to
/// be reading nothing rather than finding nothing.
const MINIMUM_SURFACE: usize = 200;

/// Which enclosing block makes an unmarked item public API.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    /// Not inside a public enum or trait.
    Outside,
    /// Inside a `pub enum`: its direct children are variants.
    Enum,
    /// Inside a `pub trait`: its direct children are trait items.
    Trait,
}

/// Returns the identifier that starts `text`, if it starts with one.
fn leading_identifier(text: &str) -> Option<String> {
    let name: String = text
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let first = name.chars().next()?;
    if first.is_ascii_digit() {
        return None;
    }
    Some(name)
}

/// Returns the name a `pub` declaration on `text` introduces.
///
/// `pub use` and `pub mod` are deliberately not names of their own: a
/// re-export names an item declared elsewhere, and a module is a namespace
/// rather than an interface.
fn declared_name(text: &str) -> Option<String> {
    let after_pub = text.strip_prefix("pub ")?;
    let rest = after_pub
        .strip_prefix("const fn ")
        .or_else(|| after_pub.strip_prefix("unsafe fn "))
        .or_else(|| after_pub.strip_prefix("fn "))
        .or_else(|| after_pub.strip_prefix("struct "))
        .or_else(|| after_pub.strip_prefix("enum "))
        .or_else(|| after_pub.strip_prefix("trait "))
        .or_else(|| after_pub.strip_prefix("type "))
        .or_else(|| after_pub.strip_prefix("const "))?;
    leading_identifier(rest.trim_start())
}

/// Returns the variant `text` declares, when it declares one.
fn variant_name(text: &str) -> Option<String> {
    let name = leading_identifier(text)?;
    if !name.chars().next()?.is_ascii_uppercase() {
        return None;
    }
    let tail = text.get(name.len()..)?.trim_start();
    let opens_payload = tail.starts_with('{') || tail.starts_with('(');
    if tail.is_empty() || tail.starts_with(',') || opens_payload {
        return Some(name);
    }
    None
}

/// Returns the trait item `text` declares, when it declares one.
fn trait_item_name(text: &str) -> Option<String> {
    if let Some(rest) = text.strip_prefix("fn ") {
        return leading_identifier(rest);
    }
    leading_identifier(text.strip_prefix("const ")?)
}

/// Returns the name of a direct child of a public enum or trait.
fn member_name(block: Block, text: &str) -> Option<String> {
    match block {
        Block::Outside => None,
        Block::Enum => variant_name(text),
        Block::Trait => trait_item_name(text),
    }
}

/// Returns the kind of block `text` opens, if it opens one.
fn block_opener(text: &str) -> Option<Block> {
    if text.starts_with("pub enum ") {
        return Some(Block::Enum);
    }
    if text.starts_with("pub trait ") {
        return Some(Block::Trait);
    }
    None
}

/// Returns the net brace nesting `line` introduces.
fn brace_delta(line: &str) -> i32 {
    let opens = i32::try_from(line.matches('{').count()).unwrap_or(0);
    let closes = i32::try_from(line.matches('}').count()).unwrap_or(0);
    opens.saturating_sub(closes)
}

/// Collects public names from one source file, line by line.
struct Scanner {
    depth: i32,
    block: Block,
    block_depth: i32,
    names: Vec<String>,
}

impl Scanner {
    /// Builds an empty scanner.
    fn new() -> Self {
        Self {
            depth: 0,
            block: Block::Outside,
            block_depth: 0,
            names: Vec::new(),
        }
    }

    /// Scans one file, resetting the nesting state first.
    fn file(&mut self, body: &str) {
        self.depth = 0;
        self.block = Block::Outside;
        self.block_depth = 0;
        for line in body.lines().take(LINE_BOUND) {
            self.line(line);
        }
    }

    /// Records what one line declares and tracks the nesting it changes.
    ///
    /// Comment lines are skipped whole, braces included: the crate documents
    /// its own encodings, and a brace inside prose is not nesting.
    fn line(&mut self, line: &str) {
        let text = line.trim();
        if text.starts_with("//") {
            return;
        }
        self.collect(text);
        if let Some(kind) = block_opener(text) {
            self.block = kind;
            self.block_depth = self.depth;
        }
        self.close(brace_delta(line));
    }

    /// Records whatever `text` declares at the current nesting.
    fn collect(&mut self, text: &str) {
        if let Some(name) = declared_name(text) {
            self.names.push(name);
        }
        if self.depth != self.block_depth.saturating_add(1) {
            return;
        }
        if let Some(name) = member_name(self.block, text) {
            self.names.push(name);
        }
    }

    /// Advances the nesting depth and leaves the block when it closes.
    fn close(&mut self, delta: i32) {
        let next = self.depth.saturating_add(delta);
        if next <= self.block_depth {
            self.block = Block::Outside;
        }
        self.depth = next;
    }
}

/// Returns the `.rs` files under `root`, as (file name, body) pairs.
///
/// The walk is iterative and doubly bounded: at most [`WALK_BOUND`]
/// directories and at most [`WALK_BOUND`] entries per directory.
fn rust_sources(root: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    for _ in 0..WALK_BOUND {
        let Some(directory) = stack.pop() else { break };
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten().take(WALK_BOUND) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let name = path
                .file_name()
                .map(|raw| raw.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push((name, std::fs::read_to_string(&path).unwrap_or_default()));
        }
    }
    out
}

/// Returns every public name the crate's `src/` declares.
fn public_names() -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanner = Scanner::new();
    for (_, body) in rust_sources(&src) {
        scanner.file(&body);
    }
    scanner.names.sort_unstable();
    scanner.names.dedup();
    scanner.names
}

/// Returns the code of every integration test but this one, comments removed.
///
/// Comments are removed so that naming an item in a doc comment does not count
/// as exercising it.
fn test_sources() -> String {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = String::new();
    for (name, body) in rust_sources(&tests) {
        if name == SWEEP_FILE {
            continue;
        }
        for line in body.lines().take(LINE_BOUND) {
            if line.trim_start().starts_with("//") {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Returns `true` when `c` may appear inside a Rust identifier.
fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Returns `true` when `text` contains `name` as a whole identifier.
fn contains_identifier(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(at, _)| {
        let before = text.get(..at).and_then(|head| head.chars().next_back());
        let after = text
            .get(at.saturating_add(name.len())..)
            .and_then(|tail| tail.chars().next());
        !before.is_some_and(is_identifier_char) && !after.is_some_and(is_identifier_char)
    })
}

// --- Positive -------------------------------------------------------------

/// Positive: every public item the crate declares is named by a test.
///
/// This is the sweep itself. A failure lists the items, so closing it is
/// mechanical: give the item a triple, or delete the item.
#[test]
fn every_public_item_is_named_by_an_integration_test() {
    let names = public_names();
    assert!(
        names.len() >= MINIMUM_SURFACE,
        "the scanner reported only {} public names, fewer than the {MINIMUM_SURFACE} \
         this crate is known to export; it is reading nothing, not finding nothing",
        names.len()
    );
    let sources = test_sources();
    assert!(
        !sources.is_empty(),
        "no integration test source was read at all"
    );
    let missing: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| !contains_identifier(&sources, name))
        .collect();
    assert!(
        missing.is_empty(),
        "public items with no integration-test reference: {missing:?}"
    );
}

// --- Negative -------------------------------------------------------------

/// Negative: the scanner distinguishes public surface from private helpers,
/// so the sweep cannot pass by collecting nothing or by collecting everything.
#[test]
fn the_scanner_reads_public_surface_and_not_private_helpers() {
    let names = public_names();
    for expected in [
        "JustitiaEngine",
        "adjudicate",
        "MAX_LEDGER_RECORDS",
        "RequireApproval",
        "append_record",
        "ALGORITHM",
        "Sha256Ledger",
    ] {
        assert!(
            names.iter().any(|name| name == expected),
            "the scanner missed the public item {expected}"
        );
    }
    for private in [
        "commit",
        "verify_link",
        "draft_for",
        "is_live",
        "write_killswitch",
    ] {
        assert!(
            !names.iter().any(|name| name == private),
            "the scanner collected the private helper {private}"
        );
    }
}

// --- Boundary -------------------------------------------------------------

/// Boundary: identifier matching is exact at both ends, so a name is not
/// counted as referenced because a longer name contains it.
#[test]
fn the_identifier_matcher_is_exact_at_both_ends() {
    assert!(contains_identifier(
        "InterceptorOutcome::Block { reason }",
        "Block"
    ));
    assert!(!contains_identifier("BlockReason::RegistryFull", "Block"));
    assert!(!contains_identifier("InterceptorOutcome", "Outcome"));
    assert!(!contains_identifier("outer_Block", "Block"));
    assert!(!contains_identifier("Block2", "Block"));
    assert!(contains_identifier("Block", "Block"));
    assert!(!contains_identifier("", "Block"));
}
