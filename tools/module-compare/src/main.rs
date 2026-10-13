// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

//! WebAssembly module order-free comparator: verifies code section equivalence
//! under arbitrary function permutation, and data section byte equivalence.

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::process::ExitCode;
use wasmparser::{ElementItems, ExternalKind, FunctionBody, Operator, Parser, Payload, TypeRef};

/// Maximum accepted module size in bytes (4 MiB).
const MAX_MODULE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum number of payload items parsed per module.
const MAX_PAYLOADS: usize = 65_536;

/// Maximum number of operators allowed per defined function body.
const MAX_OPERATORS_PER_FUNC: usize = 100_000;

/// Maximum locals declarations allowed per defined function body.
const MAX_LOCALS: usize = 10_000;

/// Maximum element segments or element items allowed.
const MAX_ELEMENTS: usize = 65_536;

/// Maximum export entries allowed.
const MAX_EXPORTS: usize = 65_536;

/// Fixed rounds for Weisfeiler-Lehman graph labeling iteration.
const LABEL_ROUNDS: usize = 12;

/// WebAssembly magic bytes.
const MAGIC_BYTES: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];

/// An error encountered while reading or comparing modules.
#[derive(Debug)]
enum CompareError {
    Usage,
    Io(String),
    Malformed(String),
}

impl std::fmt::Display for CompareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage => write!(
                f,
                "Usage: amussis-module-compare <committed.wasm> <built.wasm>"
            ),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Malformed(msg) => write!(f, "Malformed WebAssembly: {msg}"),
        }
    }
}

/// A parsed element segment within a WebAssembly module.
struct ElementSegment {
    kind_id: u8,
    metadata: Vec<u8>,
    functions: Vec<u32>,
}

/// A parsed WebAssembly module holding structural code elements and data bytes.
struct ParsedModule {
    imported_funcs: u32,
    func_types: Vec<u32>,
    bodies: Vec<Vec<String>>,
    callees: Vec<Vec<u32>>,
    elements: Vec<ElementSegment>,
    exports: Vec<(String, ExternalKind, u32)>,
    start: Option<u32>,
    has_data: bool,
    data: Vec<u8>,
    other: Vec<(u8, Vec<u8>)>,
}

impl ParsedModule {
    fn new() -> Self {
        Self {
            imported_funcs: 0,
            func_types: Vec::new(),
            bodies: Vec::new(),
            callees: Vec::new(),
            elements: Vec::new(),
            exports: Vec::new(),
            start: None,
            has_data: false,
            data: Vec::new(),
            other: Vec::new(),
        }
    }
}

/// A finding of difference between two modules.
enum Finding {
    Code(String),
    Data(String),
}

/// Hashes any hashable item with a deterministic `DefaultHasher`.
fn hash_item<T: Hash>(item: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    item.hash(&mut hasher);
    hasher.finish()
}

/// Extracts a slice from a byte slice using a 64-bit range.
fn slice_range<'a>(
    bytes: &'a [u8],
    range: &std::ops::Range<u64>,
) -> Result<&'a [u8], CompareError> {
    let start = usize::try_from(range.start)
        .map_err(|_| CompareError::Malformed("section offset out of range".to_string()))?;
    let end = usize::try_from(range.end)
        .map_err(|_| CompareError::Malformed("section offset out of range".to_string()))?;
    bytes
        .get(start..end)
        .ok_or_else(|| CompareError::Malformed("section range out of bounds".to_string()))
}

/// Parses function locals and instruction sequence into abstracted operator names and call targets.
fn parse_code_entry(body: &FunctionBody) -> Result<(Vec<String>, Vec<u32>), CompareError> {
    let mut ops = Vec::new();
    let mut calls = Vec::new();

    let locals_reader = body
        .get_locals_reader()
        .map_err(|e| CompareError::Malformed(format!("locals reader error: {e}")))?;
    let mut locals_fmt = Vec::new();
    for (idx, local) in locals_reader.into_iter().enumerate() {
        if idx >= MAX_LOCALS {
            return Err(CompareError::Malformed(
                "too many locals declarations".to_string(),
            ));
        }
        let (count, ty) =
            local.map_err(|e| CompareError::Malformed(format!("locals read error: {e}")))?;
        locals_fmt.push(format!("({count},{ty:?})"));
    }
    ops.push(locals_fmt.join(","));

    let mut r = body
        .get_operators_reader()
        .map_err(|e| CompareError::Malformed(format!("operators reader error: {e}")))?;
    let mut op_count = 0usize;
    while !r.eof() {
        if op_count >= MAX_OPERATORS_PER_FUNC {
            return Err(CompareError::Malformed(
                "operators exceed limit in function".to_string(),
            ));
        }
        op_count = op_count.saturating_add(1);
        let op = r
            .read()
            .map_err(|e| CompareError::Malformed(format!("operator read error: {e}")))?;
        match op {
            Operator::Call { function_index } => {
                calls.push(function_index);
                ops.push("Call".to_string());
            }
            Operator::ReturnCall { function_index } => {
                calls.push(function_index);
                ops.push("ReturnCall".to_string());
            }
            Operator::RefFunc { function_index } => {
                calls.push(function_index);
                ops.push("RefFunc".to_string());
            }
            other_op => {
                ops.push(format!("{other_op:?}"));
            }
        }
    }
    Ok((ops, calls))
}

/// Reads function indices from element section items.
fn read_element_functions(
    funcs_reader: wasmparser::SectionLimited<'_, u32>,
) -> Result<Vec<u32>, CompareError> {
    let mut funcs = Vec::new();
    for (f_idx, func) in funcs_reader.into_iter().enumerate() {
        if f_idx >= MAX_ELEMENTS {
            return Err(CompareError::Malformed(
                "element functions exceed limit".to_string(),
            ));
        }
        let f = func.map_err(|e| CompareError::Malformed(format!("element func error: {e}")))?;
        funcs.push(f);
    }
    Ok(funcs)
}

/// Parses an element section reader into element segments.
fn parse_element_section(
    r: wasmparser::ElementSectionReader,
    bytes: &[u8],
    m: &mut ParsedModule,
) -> Result<(), CompareError> {
    for (elem_idx, elem) in r.into_iter().enumerate() {
        if elem_idx >= MAX_ELEMENTS {
            return Err(CompareError::Malformed(
                "element segments exceed limit".to_string(),
            ));
        }
        let elem = elem.map_err(|e| CompareError::Malformed(format!("element read error: {e}")))?;
        let funcs = match elem.items {
            ElementItems::Functions(funcs_reader) => read_element_functions(funcs_reader)?,
            ElementItems::Expressions(_, _) => {
                return Err(CompareError::Malformed(
                    "element segment with expression items is not supported".to_string(),
                ));
            }
        };
        let (kind_id, metadata) = match elem.kind {
            wasmparser::ElementKind::Passive => (0u8, Vec::new()),
            wasmparser::ElementKind::Active {
                table_index,
                offset_expr,
            } => {
                let range = offset_expr.get_binary_reader().range();
                let offset_bytes = slice_range(bytes, &range)?.to_vec();
                let mut meta = Vec::new();
                if let Some(t) = table_index {
                    meta.extend_from_slice(&t.to_le_bytes());
                }
                meta.extend_from_slice(&offset_bytes);
                (1u8, meta)
            }
            wasmparser::ElementKind::Declared => (2u8, Vec::new()),
        };
        m.elements.push(ElementSegment {
            kind_id,
            metadata,
            functions: funcs,
        });
    }
    Ok(())
}

/// Parses import section reader, records raw bytes into `other`, and counts imported functions.
fn parse_import_section(
    r: wasmparser::ImportSectionReader,
    bytes: &[u8],
    m: &mut ParsedModule,
) -> Result<(), CompareError> {
    let section_bytes = slice_range(bytes, &r.range())?.to_vec();
    m.other.push((2, section_bytes));
    for imp in r.into_imports() {
        let imp = imp.map_err(|e| CompareError::Malformed(format!("import error: {e}")))?;
        if matches!(imp.ty, TypeRef::Func(_)) {
            m.imported_funcs = m.imported_funcs.saturating_add(1);
        }
    }
    Ok(())
}

/// Parses export section reader, enforcing `MAX_EXPORTS`.
fn parse_export_section(
    r: wasmparser::ExportSectionReader,
    m: &mut ParsedModule,
) -> Result<(), CompareError> {
    for (idx, e) in r.into_iter().enumerate() {
        if idx >= MAX_EXPORTS {
            return Err(CompareError::Malformed("exports exceed limit".to_string()));
        }
        let e = e.map_err(|e| CompareError::Malformed(format!("export error: {e}")))?;
        m.exports.push((e.name.to_string(), e.kind, e.index));
    }
    Ok(())
}

/// Parses data section reader, storing the full section bytes and validating every segment.
fn parse_data_section(
    r: wasmparser::DataSectionReader,
    bytes: &[u8],
    m: &mut ParsedModule,
) -> Result<(), CompareError> {
    if m.has_data {
        return Err(CompareError::Malformed(
            "duplicate data section".to_string(),
        ));
    }
    m.has_data = true;
    m.data = slice_range(bytes, &r.range())?.to_vec();
    for d in r {
        let _ = d.map_err(|e| CompareError::Malformed(format!("data error: {e}")))?;
    }
    Ok(())
}

/// Dispatches an individual wasmparser payload and populates the module.
fn handle_payload(
    payload: Payload,
    bytes: &[u8],
    m: &mut ParsedModule,
) -> Result<(), CompareError> {
    match payload {
        Payload::ImportSection(r) => parse_import_section(r, bytes, m)?,
        Payload::FunctionSection(r) => {
            for t in r {
                let t = t.map_err(|e| CompareError::Malformed(format!("func type error: {e}")))?;
                m.func_types.push(t);
            }
        }
        Payload::ElementSection(r) => parse_element_section(r, bytes, m)?,
        Payload::ExportSection(r) => parse_export_section(r, m)?,
        Payload::StartSection { func, range: _ } => {
            if m.start.is_some() {
                return Err(CompareError::Malformed(
                    "duplicate start section".to_string(),
                ));
            }
            m.start = Some(func);
        }
        Payload::CodeSectionStart { .. } | Payload::Version { .. } | Payload::End(_) => {}
        Payload::CodeSectionEntry(body) => {
            let (ops, calls) = parse_code_entry(&body)?;
            m.bodies.push(ops);
            m.callees.push(calls);
        }
        Payload::DataSection(r) => parse_data_section(r, bytes, m)?,
        Payload::TypeSection(r) => m.other.push((1, slice_range(bytes, &r.range())?.to_vec())),
        Payload::TableSection(r) => m.other.push((4, slice_range(bytes, &r.range())?.to_vec())),
        Payload::MemorySection(r) => m.other.push((5, slice_range(bytes, &r.range())?.to_vec())),
        Payload::GlobalSection(r) => m.other.push((6, slice_range(bytes, &r.range())?.to_vec())),
        Payload::DataCountSection { range, .. } => {
            m.other.push((12, slice_range(bytes, &range)?.to_vec()));
        }
        Payload::CustomSection(r) => m.other.push((0, slice_range(bytes, &r.range())?.to_vec())),
        other => {
            if let Some((id, range)) = other.as_section() {
                m.other.push((id, slice_range(bytes, &range)?.to_vec()));
            } else {
                return Err(CompareError::Malformed(format!(
                    "unhandled payload {other:?}"
                )));
            }
        }
    }
    Ok(())
}

/// Parses a WebAssembly module from byte slice into structured form.
fn parse_module(bytes: &[u8]) -> Result<ParsedModule, CompareError> {
    if bytes.len() > MAX_MODULE_BYTES {
        return Err(CompareError::Malformed(format!(
            "module size {} exceeds bound {}",
            bytes.len(),
            MAX_MODULE_BYTES
        )));
    }
    if bytes.len() < 8 || bytes.get(..4) != Some(&MAGIC_BYTES) {
        return Err(CompareError::Malformed("invalid wasm header".to_string()));
    }
    let mut m = ParsedModule::new();
    for (count, payload) in Parser::new(0).parse_all(bytes).enumerate() {
        if count >= MAX_PAYLOADS {
            return Err(CompareError::Malformed(
                "payload count exceeds limit".to_string(),
            ));
        }
        let payload =
            payload.map_err(|e| CompareError::Malformed(format!("wasm parse error: {e}")))?;
        handle_payload(payload, bytes, &mut m)?;
    }
    if m.func_types.len() != m.bodies.len() {
        return Err(CompareError::Malformed(format!(
            "function section declared {} types but code section has {} bodies",
            m.func_types.len(),
            m.bodies.len()
        )));
    }
    Ok(m)
}

/// Resolves the label of a function index (imported or defined) from the label array.
fn label_of(m: &ParsedModule, lab: &[u64], idx: u32) -> Result<u64, CompareError> {
    if idx < m.imported_funcs {
        Ok(hash_item(&("import", idx)))
    } else {
        let local_idx = idx
            .checked_sub(m.imported_funcs)
            .ok_or_else(|| CompareError::Malformed(format!("invalid function index {idx}")))?;
        let val = lab.get(local_idx as usize).copied().ok_or_else(|| {
            CompareError::Malformed(format!("function index {idx} out of bounds"))
        })?;
        Ok(val)
    }
}

/// Collects callee labels in order for a defined function.
fn get_callee_labels(m: &ParsedModule, lab: &[u64], idx: usize) -> Result<Vec<u64>, CompareError> {
    let mut callee_labels = Vec::new();
    let Some(calls) = m.callees.get(idx) else {
        return Ok(callee_labels);
    };
    for &c in calls {
        let clab = label_of(m, lab, c)?;
        callee_labels.push(clab);
    }
    Ok(callee_labels)
}

/// Computes Weisfeiler-Lehman graph labels for all defined functions over 12 fixed rounds.
fn compute_labels(m: &ParsedModule) -> Result<Vec<u64>, CompareError> {
    let n = m.bodies.len();
    let mut lab = Vec::with_capacity(n);
    for i in 0..n {
        let ty = m.func_types.get(i).copied().unwrap_or(0);
        let body = m.bodies.get(i);
        lab.push(hash_item(&(ty, body)));
    }
    for _ in 0..LABEL_ROUNDS {
        let mut next = Vec::with_capacity(n);
        for i in 0..n {
            let callee_labels = get_callee_labels(m, &lab, i)?;
            let current = lab.get(i).copied().unwrap_or(0);
            next.push(hash_item(&(current, callee_labels)));
        }
        lab = next;
    }
    Ok(lab)
}

/// Compares defined functions by count and multiset of Weisfeiler-Lehman labels.
fn compare_functions(a: &ParsedModule, b: &ParsedModule, la: &[u64], lb: &[u64]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if a.bodies.len() != b.bodies.len() {
        findings.push(Finding::Code(format!(
            "defined function count differs ({} vs {})",
            a.bodies.len(),
            b.bodies.len()
        )));
    }
    let mut counts: BTreeMap<u64, i32> = BTreeMap::new();
    for &l in la {
        let entry = counts.entry(l).or_default();
        *entry = entry.saturating_add(1);
    }
    for &l in lb {
        let entry = counts.entry(l).or_default();
        *entry = entry.saturating_sub(1);
    }
    let unmatched: usize = counts
        .values()
        .filter(|&&v| v != 0)
        .map(|v| v.unsigned_abs() as usize)
        .sum();
    if unmatched > 0 {
        findings.push(Finding::Code(format!("{unmatched} functions unmatched")));
    }
    findings
}

/// Compares element segments mapped through function labels in order.
fn compare_elements(
    a: &ParsedModule,
    b: &ParsedModule,
    la: &[u64],
    lb: &[u64],
) -> Result<Vec<Finding>, CompareError> {
    let mut findings = Vec::new();
    if a.elements.len() != b.elements.len() {
        findings.push(Finding::Code(format!(
            "element segment count differs ({} vs {})",
            a.elements.len(),
            b.elements.len()
        )));
        return Ok(findings);
    }
    for (idx, (ea, eb)) in a.elements.iter().zip(&b.elements).enumerate() {
        if ea.kind_id != eb.kind_id || ea.metadata != eb.metadata {
            findings.push(Finding::Code(format!(
                "element segment {idx} kind/metadata differs"
            )));
            continue;
        }
        let mapped_a: Vec<u64> = ea
            .functions
            .iter()
            .map(|&i| label_of(a, la, i))
            .collect::<Result<_, _>>()?;
        let mapped_b: Vec<u64> = eb
            .functions
            .iter()
            .map(|&i| label_of(b, lb, i))
            .collect::<Result<_, _>>()?;
        if mapped_a != mapped_b {
            findings.push(Finding::Code(format!(
                "element segment {idx} functions differ"
            )));
        }
    }
    Ok(findings)
}

/// Compares exports mapped through function labels in order.
fn compare_exports(
    a: &ParsedModule,
    b: &ParsedModule,
    la: &[u64],
    lb: &[u64],
) -> Result<Vec<Finding>, CompareError> {
    let mut findings = Vec::new();
    if a.exports.len() != b.exports.len() {
        findings.push(Finding::Code(format!(
            "export count differs ({} vs {})",
            a.exports.len(),
            b.exports.len()
        )));
        return Ok(findings);
    }
    for (idx, (xa, xb)) in a.exports.iter().zip(&b.exports).enumerate() {
        if xa.0 != xb.0 || xa.1 != xb.1 {
            findings.push(Finding::Code(format!("export {idx} name or kind differs")));
            continue;
        }
        let target_a = if xa.1 == ExternalKind::Func {
            label_of(a, la, xa.2)?
        } else {
            u64::from(xa.2)
        };
        let target_b = if xb.1 == ExternalKind::Func {
            label_of(b, lb, xb.2)?
        } else {
            u64::from(xb.2)
        };
        if target_a != target_b {
            findings.push(Finding::Code(format!("export \"{}\" target differs", xa.0)));
        }
    }
    Ok(findings)
}

/// Compares start function mapped through function labels.
fn compare_start(
    a: &ParsedModule,
    b: &ParsedModule,
    la: &[u64],
    lb: &[u64],
) -> Result<Vec<Finding>, CompareError> {
    let mut findings = Vec::new();
    match (a.start, b.start) {
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            findings.push(Finding::Code("start section presence differs".to_string()));
        }
        (Some(sa), Some(sb)) => {
            let label_start_a = label_of(a, la, sa)?;
            let label_start_b = label_of(b, lb, sb)?;
            if label_start_a != label_start_b {
                findings.push(Finding::Code("start function target differs".to_string()));
            }
        }
    }
    Ok(findings)
}

/// Compares non-data sections (Type, Import, Table, Memory, Global, `DataCount`, Custom) byte for byte.
fn compare_other_sections(a: &ParsedModule, b: &ParsedModule) -> Vec<Finding> {
    let mut findings = Vec::new();
    if a.other != b.other {
        findings.push(Finding::Code(
            "non-data section contents differ".to_string(),
        ));
    }
    findings
}

/// Compares data section concatenated bytes and returns finding and difference count.
fn compare_data_sections(a: &ParsedModule, b: &ParsedModule) -> (Option<Finding>, usize) {
    let diff = a
        .data
        .iter()
        .zip(&b.data)
        .filter(|(x, y)| x != y)
        .count()
        .saturating_add(a.data.len().abs_diff(b.data.len()));
    if diff > 0 {
        (Some(Finding::Data(format!("{diff} bytes differ"))), diff)
    } else {
        (None, 0)
    }
}

/// Compares two modules and returns all code findings, data finding, and data byte difference count.
fn compare_modules(
    a: &ParsedModule,
    b: &ParsedModule,
) -> Result<(Vec<Finding>, Option<Finding>, usize), CompareError> {
    let la = compute_labels(a)?;
    let lb = compute_labels(b)?;
    let mut code_findings = Vec::new();
    code_findings.extend(compare_functions(a, b, &la, &lb));
    code_findings.extend(compare_elements(a, b, &la, &lb)?);
    code_findings.extend(compare_exports(a, b, &la, &lb)?);
    code_findings.extend(compare_start(a, b, &la, &lb)?);
    code_findings.extend(compare_other_sections(a, b));
    let (data_finding, data_diff) = compare_data_sections(a, b);
    Ok((code_findings, data_finding, data_diff))
}

/// Writes a string followed by newline to stdout without clippy `print_stdout` warning.
fn write_stdout(msg: &str) -> Result<(), std::io::Error> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{msg}")
}

/// Writes a string followed by newline to stderr without clippy `print_stderr` warning.
fn write_stderr(msg: &str) -> Result<(), std::io::Error> {
    let mut err = std::io::stderr().lock();
    writeln!(err, "{msg}")
}

/// Compares two wasm byte slices and returns (`code_equal`, `data_equal`, `data_diff_bytes`, findings).
#[cfg(test)]
fn compare_wasm_bytes(
    a_bytes: &[u8],
    b_bytes: &[u8],
) -> Result<(bool, bool, usize, Vec<String>), CompareError> {
    let ma = parse_module(a_bytes)?;
    let mb = parse_module(b_bytes)?;
    let (code_findings, data_finding, data_diff) = compare_modules(&ma, &mb)?;
    let mut list = Vec::new();
    for f in &code_findings {
        match f {
            Finding::Code(msg) => list.push(format!("finding: code: {msg}")),
            Finding::Data(msg) => list.push(format!("finding: data: {msg}")),
        }
    }
    if let Some(Finding::Data(msg)) = &data_finding {
        list.push(format!("finding: data: {msg}"));
    }
    Ok((code_findings.is_empty(), data_diff == 0, data_diff, list))
}

/// Reads a file from disk into a vector of bytes, enforcing `MAX_MODULE_BYTES`.
fn read_module_file(path: &str) -> Result<Vec<u8>, CompareError> {
    let bytes =
        std::fs::read(path).map_err(|e| CompareError::Io(format!("cannot read {path}: {e}")))?;
    if bytes.len() > MAX_MODULE_BYTES {
        return Err(CompareError::Malformed(format!(
            "{path}: module size {} exceeds maximum {MAX_MODULE_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Executes comparison and prints findings and verdict to stdout.
fn run_app(path_committed: &str, path_built: &str) -> Result<ExitCode, CompareError> {
    let bytes_a = read_module_file(path_committed)?;
    let bytes_b = read_module_file(path_built)?;
    let mod_a = parse_module(&bytes_a)?;
    let mod_b = parse_module(&bytes_b)?;
    let (code_findings, data_finding, data_diff) = compare_modules(&mod_a, &mod_b)?;

    for f in &code_findings {
        if let Finding::Code(msg) = f {
            let _ = write_stdout(&format!("finding: code: {msg}"));
        }
    }
    if let Some(Finding::Data(msg)) = &data_finding {
        let _ = write_stdout(&format!("finding: data: {msg}"));
    }

    let verdict = match (code_findings.is_empty(), data_diff) {
        (true, 0) => "verdict: code equal, data equal".to_string(),
        (true, n) => {
            let unit = if n == 1 { "byte" } else { "bytes" };
            format!("verdict: code equal, data differ ({n} {unit})")
        }
        (false, 0) => "verdict: code differ, data equal".to_string(),
        (false, n) => {
            let unit = if n == 1 { "byte" } else { "bytes" };
            format!("verdict: code differ, data differ ({n} {unit})")
        }
    };
    let _ = write_stdout(&verdict);

    if code_findings.is_empty() && data_diff == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        let err = CompareError::Usage;
        let _ = write_stderr(&format!("ERROR: {err}"));
        return ExitCode::from(2);
    }
    let Some(path_committed) = args.get(1) else {
        return ExitCode::from(2);
    };
    let Some(path_built) = args.get(2) else {
        return ExitCode::from(2);
    };
    match run_app(path_committed, path_built) {
        Ok(code) => code,
        Err(err) => {
            let _ = write_stderr(&format!("ERROR: {err}"));
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_u32(mut val: u32, buf: &mut Vec<u8>) {
        for _ in 0..5 {
            let mut byte = (val & 0x7F) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if val == 0 {
                break;
            }
        }
    }

    fn write_len(len: usize, buf: &mut Vec<u8>) {
        let val = u32::try_from(len).unwrap_or(u32::MAX);
        encode_u32(val, buf);
    }

    fn write_section(id: u8, payload: &[u8], buf: &mut Vec<u8>) {
        buf.push(id);
        write_len(payload.len(), buf);
        buf.extend_from_slice(payload);
    }

    fn write_code_section(buf: &mut Vec<u8>, bodies: &[&[u8]]) {
        let mut code_payload = Vec::new();
        write_len(bodies.len(), &mut code_payload);
        for &b in bodies {
            let mut body_bytes = Vec::new();
            encode_u32(0, &mut body_bytes);
            body_bytes.extend_from_slice(b);
            write_len(body_bytes.len(), &mut code_payload);
            code_payload.extend_from_slice(&body_bytes);
        }
        write_section(10, &code_payload, buf);
    }

    fn write_data_section(buf: &mut Vec<u8>, d: &[u8], offset_val: u32) {
        let mut data_payload = Vec::new();
        encode_u32(1, &mut data_payload);
        data_payload.push(0x00);
        data_payload.push(0x41);
        encode_u32(offset_val, &mut data_payload);
        data_payload.push(0x0b);
        write_len(d.len(), &mut data_payload);
        data_payload.extend_from_slice(d);
        write_section(11, &data_payload, buf);
    }

    fn build_test_module_with_offset_and_elem(
        func_types: &[u32],
        exports: &[(&str, u32)],
        elements: Option<&[u8]>,
        bodies: &[&[u8]],
        data: Option<&[u8]>,
        offset_val: u32,
    ) -> Vec<u8> {
        let mut buf = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let mut type_payload = Vec::new();
        encode_u32(1, &mut type_payload);
        type_payload.push(0x60);
        encode_u32(0, &mut type_payload);
        encode_u32(1, &mut type_payload);
        type_payload.push(0x7f);
        write_section(1, &type_payload, &mut buf);

        let mut func_payload = Vec::new();
        write_len(func_types.len(), &mut func_payload);
        for &t in func_types {
            encode_u32(t, &mut func_payload);
        }
        write_section(3, &func_payload, &mut buf);

        if !exports.is_empty() {
            let mut exp_payload = Vec::new();
            write_len(exports.len(), &mut exp_payload);
            for &(name, idx) in exports {
                write_len(name.len(), &mut exp_payload);
                exp_payload.extend_from_slice(name.as_bytes());
                exp_payload.push(0x00);
                encode_u32(idx, &mut exp_payload);
            }
            write_section(7, &exp_payload, &mut buf);
        }

        if let Some(elem) = elements {
            write_section(9, elem, &mut buf);
        }

        write_code_section(&mut buf, bodies);

        if let Some(d) = data {
            write_data_section(&mut buf, d, offset_val);
        }

        buf
    }

    fn build_test_module_with_offset(
        func_types: &[u32],
        exports: &[(&str, u32)],
        bodies: &[&[u8]],
        data: Option<&[u8]>,
        offset_val: u32,
    ) -> Vec<u8> {
        build_test_module_with_offset_and_elem(func_types, exports, None, bodies, data, offset_val)
    }

    fn build_test_module(
        func_types: &[u32],
        exports: &[(&str, u32)],
        bodies: &[&[u8]],
        data: Option<&[u8]>,
    ) -> Vec<u8> {
        build_test_module_with_offset(func_types, exports, bodies, data, 0)
    }

    #[test]
    fn test_identical_module() -> Result<(), CompareError> {
        let m = build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x2a, 0x0b]], Some(b"hello"));
        let (code_eq, data_eq, diff, _) = compare_wasm_bytes(&m, &m)?;
        assert!(code_eq);
        assert!(data_eq);
        assert_eq!(diff, 0);
        Ok(())
    }

    #[test]
    fn test_two_functions_swapped() -> Result<(), CompareError> {
        // Module A: func 0 calls func 1; func 1 returns 42. "main" -> 0.
        let ma = build_test_module(
            &[0, 0],
            &[("main", 0)],
            &[&[0x10, 0x01, 0x0b], &[0x41, 0x2a, 0x0b]],
            Some(b"data"),
        );
        // Module B: func 0 returns 42; func 1 calls func 0. "main" -> 1.
        let mb = build_test_module(
            &[0, 0],
            &[("main", 1)],
            &[&[0x41, 0x2a, 0x0b], &[0x10, 0x00, 0x0b]],
            Some(b"data"),
        );
        let (code_eq, data_eq, diff, _) = compare_wasm_bytes(&ma, &mb)?;
        assert!(code_eq, "swapped functions must be accepted as equal code");
        assert!(data_eq);
        assert_eq!(diff, 0);
        Ok(())
    }

    #[test]
    fn test_i32_const_operand_changed() -> Result<(), CompareError> {
        let ma = build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x2a, 0x0b]], None);
        let mb = build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x2b, 0x0b]], None);
        let (code_eq, _, _, _) = compare_wasm_bytes(&ma, &mb)?;
        assert!(!code_eq);
        Ok(())
    }

    #[test]
    fn test_opcode_add_to_sub() -> Result<(), CompareError> {
        let ma = build_test_module(
            &[0],
            &[("main", 0)],
            &[&[0x41, 0x01, 0x41, 0x02, 0x6a, 0x0b]],
            None,
        );
        let mb = build_test_module(
            &[0],
            &[("main", 0)],
            &[&[0x41, 0x01, 0x41, 0x02, 0x6b, 0x0b]],
            None,
        );
        let (code_eq, _, _, _) = compare_wasm_bytes(&ma, &mb)?;
        assert!(!code_eq);
        Ok(())
    }

    #[test]
    fn test_export_points_at_other_function() -> Result<(), CompareError> {
        // Two distinct functions; ma exports 0, mb exports 1.
        let ma = build_test_module(
            &[0, 0],
            &[("main", 0)],
            &[&[0x41, 0x01, 0x0b], &[0x41, 0x02, 0x0b]],
            None,
        );
        let mb = build_test_module(
            &[0, 0],
            &[("main", 1)],
            &[&[0x41, 0x01, 0x0b], &[0x41, 0x02, 0x0b]],
            None,
        );
        let (code_eq, _, _, _) = compare_wasm_bytes(&ma, &mb)?;
        assert!(!code_eq);
        Ok(())
    }

    #[test]
    fn test_one_data_byte_flipped() -> Result<(), CompareError> {
        let ma = build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x01, 0x0b]], Some(b"abc"));
        let mb = build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x01, 0x0b]], Some(b"abd"));
        let (code_eq, data_eq, diff, _) = compare_wasm_bytes(&ma, &mb)?;
        assert!(code_eq);
        assert!(!data_eq);
        assert_eq!(diff, 1);
        Ok(())
    }

    #[test]
    fn test_truncated_bytes_error() {
        let truncated = b"\0asm\x01\0\0";
        assert!(compare_wasm_bytes(truncated, truncated).is_err());
    }

    #[test]
    fn test_empty_module() -> Result<(), CompareError> {
        let empty = b"\0asm\x01\0\0\0";
        let (code_eq, data_eq, diff, _) = compare_wasm_bytes(empty, empty)?;
        assert!(code_eq);
        assert!(data_eq);
        assert_eq!(diff, 0);
        Ok(())
    }

    #[test]
    fn test_data_segment_offset_changed() -> Result<(), CompareError> {
        let ma = build_test_module_with_offset(
            &[0],
            &[("main", 0)],
            &[&[0x41, 0x2a, 0x0b]],
            Some(b"hello"),
            0,
        );
        let mb = build_test_module_with_offset(
            &[0],
            &[("main", 0)],
            &[&[0x41, 0x2a, 0x0b]],
            Some(b"hello"),
            16,
        );
        let (code_eq, data_eq, diff, _) = compare_wasm_bytes(&ma, &mb)?;
        assert!(code_eq, "code must be equal");
        assert!(!data_eq, "data must differ when segment offset differs");
        assert_eq!(diff, 1);
        Ok(())
    }

    #[test]
    fn test_element_segment_expressions_refused() {
        // Section 9: 1 element segment, flag 5 (passive expressions), funcref (0x70), 1 expr (ref.func 0, end)
        let elem_payload = [0x01, 0x05, 0x70, 0x01, 0xd2, 0x00, 0x0b];
        let m = build_test_module_with_offset_and_elem(
            &[0],
            &[("main", 0)],
            Some(&elem_payload),
            &[&[0x41, 0x2a, 0x0b]],
            None,
            0,
        );
        let res = compare_wasm_bytes(&m, &m);
        assert!(
            matches!(
                res,
                Err(CompareError::Malformed(ref msg))
                    if msg.contains("element segment with expression items is not supported")
            ),
            "expected Malformed error for element segment with expression items, got {res:?}"
        );
    }

    #[test]
    fn test_unknown_or_tag_section_causes_code_differ() -> Result<(), CompareError> {
        let mut ma = build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x2a, 0x0b]], None);
        let mut mb = ma.clone();
        write_section(99, &[0x01], &mut ma);
        write_section(99, &[0x02], &mut mb);
        let (code_eq, data_eq, diff, _) = compare_wasm_bytes(&ma, &mb)?;
        assert!(
            !code_eq,
            "unknown section difference must cause code differ"
        );
        assert!(data_eq);
        assert_eq!(diff, 0);
        Ok(())
    }

    #[test]
    fn test_duplicate_data_section_refused() -> Result<(), CompareError> {
        let mut m = ParsedModule::new();
        let wasm1 = build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x2a, 0x0b]], Some(b"hello"));
        for p in Parser::new(0).parse_all(&wasm1) {
            let payload = p.map_err(|e| CompareError::Malformed(format!("{e}")))?;
            handle_payload(payload, &wasm1, &mut m)?;
        }
        let wasm2 = build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x2a, 0x0b]], Some(b"world"));
        let mut second_data = None;
        for p in Parser::new(0).parse_all(&wasm2) {
            let payload = p.map_err(|e| CompareError::Malformed(format!("{e}")))?;
            if matches!(payload, Payload::DataSection(_)) {
                second_data = Some(payload);
            }
        }
        let Some(second_payload) = second_data else {
            return Err(CompareError::Malformed("missing data section".to_string()));
        };
        let res = handle_payload(second_payload, &wasm2, &mut m);
        assert!(
            matches!(
                res,
                Err(CompareError::Malformed(ref msg)) if msg.contains("duplicate data section")
            ),
            "expected duplicate data section error, got {res:?}"
        );
        let mut two_data_wasm = wasm1.clone();
        write_data_section(&mut two_data_wasm, b"world", 0);
        assert!(compare_wasm_bytes(&two_data_wasm, &two_data_wasm).is_err());
        Ok(())
    }

    #[test]
    fn test_duplicate_start_section_refused() {
        let mut m = ParsedModule::new();
        let p1 = Payload::StartSection {
            func: 0,
            range: 0..1,
        };
        let p2 = Payload::StartSection {
            func: 1,
            range: 0..1,
        };
        assert!(handle_payload(p1, &[], &mut m).is_ok());
        let res = handle_payload(p2, &[], &mut m);
        assert!(
            matches!(
                res,
                Err(CompareError::Malformed(ref msg)) if msg.contains("duplicate start section")
            ),
            "expected duplicate start section error, got {res:?}"
        );
        let mut two_start_wasm =
            build_test_module(&[0], &[("main", 0)], &[&[0x41, 0x2a, 0x0b]], None);
        let mut start_payload = Vec::new();
        encode_u32(0, &mut start_payload);
        write_section(8, &start_payload, &mut two_start_wasm);
        write_section(8, &start_payload, &mut two_start_wasm);
        assert!(compare_wasm_bytes(&two_start_wasm, &two_start_wasm).is_err());
    }
}
