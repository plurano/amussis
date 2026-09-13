// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The two decisions milestone M14 settles or records about the P06 edges.
//!
//! D03's direction half is closed: the action gate is propose/intercept, and
//! the opposite direction is unrepresentable rather than merely discouraged.
//! D03's transport half is not closed, and the split record is asserted here so
//! that the code cannot read as broader than the roadmap. D04 is recorded and
//! still open, with both readings of the Vesta admission path kept
//! representable and neither treated as authoritative.
//!
//! What this file is not: a contract test of either admission path. The D04
//! tests below sweep the decision register -- a static table of hops and
//! citations -- and no payload crosses a path, nothing is admitted and nothing
//! is refused. The behavioural contract for both paths is milestone M06's work.

use aegis_justitia::{
    ActionProposal, D03_ACTION_GATE, D03_ACTION_GATE_DIRECTION, D03_ACTION_GATE_TRANSPORT,
    D04_SANDBOX_GATE, DecisionRecord, DecisionRequest, DecisionState, EdgeId, GateDirection,
    MAX_ADMISSION_HOPS, SandboxAdmissionPath, SchemaId, SignedAuditRecord, contract_edges,
};

// --- D03: the direction half is closed, the transport half is not ---------

/// Positive: D03's direction half is recorded as settled, and the settled
/// direction is the one the proposal type carries.
#[test]
fn d03s_direction_is_closed_and_the_proposal_carries_the_settled_direction() {
    assert_eq!(D03_ACTION_GATE_DIRECTION.id(), "D03");
    assert_eq!(D03_ACTION_GATE_DIRECTION.state(), DecisionState::Closed);
    assert!(D03_ACTION_GATE_DIRECTION.is_settled());
    assert!(!D03_ACTION_GATE_DIRECTION.question().is_empty());
    assert_eq!(
        ActionProposal::DIRECTION,
        GateDirection::MinervaProposesJustitiaIntercepts
    );
    assert_eq!(GateDirection::SETTLED, ActionProposal::DIRECTION);
    assert_eq!(
        GateDirection::SETTLED.proposer(),
        "P09_Minerva",
        "D03: Minerva proposes"
    );
    assert_eq!(
        GateDirection::SETTLED.interceptor(),
        "P06_Justitia",
        "D03: Justitia intercepts and decides"
    );
    assert_eq!(GateDirection::SETTLED.tag(), "p09-proposes-p06-intercepts");
}

/// Negative: closing the direction did not close D03. The transport half is
/// recorded as unresolved, and D03 as a whole has no settled answer, so a
/// reader of the code sees the same open question the roadmap carries as
/// dispute DSP-03 against decision D26.
#[test]
fn d03s_transport_is_still_open_and_the_record_says_so() {
    assert_eq!(D03_ACTION_GATE_TRANSPORT.id(), "D03");
    assert_eq!(D03_ACTION_GATE_TRANSPORT.state(), DecisionState::Unresolved);
    assert!(!D03_ACTION_GATE_TRANSPORT.is_settled());
    assert!(
        D03_ACTION_GATE_TRANSPORT.question().contains("transport"),
        "the open half must still ask its own question"
    );
    assert_eq!(
        D03_ACTION_GATE,
        [D03_ACTION_GATE_DIRECTION, D03_ACTION_GATE_TRANSPORT],
        "D03 is the pair, not either half on its own"
    );
    let settled = D03_ACTION_GATE
        .iter()
        .filter(|half| half.is_settled())
        .count();
    assert_eq!(settled, 1, "exactly one half of D03 is settled");
    assert_ne!(
        D03_ACTION_GATE_DIRECTION, D03_ACTION_GATE_TRANSPORT,
        "the two halves are distinct records of one decision"
    );
}

/// Negative: the graph's edge identifier is kept even though the direction was
/// reinterpreted, so the contract stays traceable to its source.
#[test]
fn closing_d03_did_not_rename_the_graph_edge() {
    assert_eq!(ActionProposal::EDGE, EdgeId::ActionGateIntercept);
    assert_eq!(ActionProposal::EDGE.name(), "ACTION_GATE_INTERCEPT");
    assert!(ActionProposal::EDGE.in_graph_of_record());
    assert_eq!(ActionProposal::EDGE.evidence(), "export-062");
}

/// Boundary: the settled direction is the only one that exists, so a payload
/// naming any other direction has no variant to decode into.
#[test]
fn the_gate_direction_admits_exactly_one_variant() -> Result<(), serde_json::Error> {
    let encoded = serde_json::to_string(&GateDirection::SETTLED)?;
    assert_eq!(encoded, "\"p09-proposes-p06-intercepts\"");
    let decoded: GateDirection = serde_json::from_str(&encoded)?;
    assert_eq!(decoded, GateDirection::SETTLED);
    assert!(serde_json::from_str::<GateDirection>("\"p06-proposes-p09-intercepts\"").is_err());
    Ok(())
}

// --- D04: recorded, unresolved -------------------------------------------

/// Positive: D04 is recorded as unresolved, with both readings kept.
#[test]
fn d04_is_recorded_as_unresolved_with_both_paths_kept() {
    assert_eq!(D04_SANDBOX_GATE.id(), "D04");
    assert_eq!(D04_SANDBOX_GATE.state(), DecisionState::Unresolved);
    assert!(!D04_SANDBOX_GATE.is_settled());
    assert!(!D04_SANDBOX_GATE.question().is_empty());
    assert_eq!(
        SandboxAdmissionPath::BOTH,
        [
            SandboxAdmissionPath::DirectSyscallIntercept,
            SandboxAdmissionPath::TransitiveThroughMinerva
        ]
    );
}

/// Positive: the decision register records the direct P06 to P10 path, and
/// records it as absent from the graph of record.
///
/// A register sweep, not a contract test: it round-trips the value and reads
/// the static table behind it. Nothing is admitted or refused on this path
/// here, and the behavioural contract for it is milestone M06's work.
#[test]
fn the_register_records_the_direct_p06_to_p10_path_as_absent_from_the_graph()
-> Result<(), serde_json::Error> {
    let path = SandboxAdmissionPath::DirectSyscallIntercept;
    let encoded = serde_json::to_string(&path)?;
    assert_eq!(encoded, "\"direct-syscall-intercept\"");
    assert_eq!(
        serde_json::from_str::<SandboxAdmissionPath>(&encoded)?,
        path
    );
    assert_eq!(path.hops(), [EdgeId::SyscallIntercept]);
    assert!(!path.in_graph_of_record());
    assert_eq!(EdgeId::SyscallIntercept.evidence(), "export-002");
    Ok(())
}

/// Positive: the decision register records the transitive path through P09,
/// and records every hop of it as present in the graph of record.
///
/// A register sweep, not a contract test, for the same reason as the direct
/// path above: no capsule execution is admitted or refused here.
#[test]
fn the_register_records_the_transitive_path_through_p09_as_in_the_graph()
-> Result<(), serde_json::Error> {
    let path = SandboxAdmissionPath::TransitiveThroughMinerva;
    let encoded = serde_json::to_string(&path)?;
    assert_eq!(encoded, "\"transitive-through-minerva\"");
    assert_eq!(
        serde_json::from_str::<SandboxAdmissionPath>(&encoded)?,
        path
    );
    assert_eq!(
        path.hops(),
        [EdgeId::ActionGateIntercept, EdgeId::ExecuteWasmedCapsule]
    );
    assert!(path.in_graph_of_record());
    assert_eq!(EdgeId::ExecuteWasmedCapsule.evidence(), "export-062");
    Ok(())
}

/// Negative: recording D04 did not silently settle it. Exactly one of the two
/// paths is in the graph of record, which is what keeps the question open; a
/// change that made both agree would have to update this test deliberately.
#[test]
fn neither_sandbox_path_is_treated_as_settled() {
    let in_graph = SandboxAdmissionPath::BOTH
        .iter()
        .filter(|path| path.in_graph_of_record())
        .count();
    assert_eq!(
        in_graph, 1,
        "D04 stays open precisely because the two readings disagree"
    );
    assert!(!D04_SANDBOX_GATE.is_settled());
    let settled = DecisionRecord::new("D04", DecisionState::Closed, D04_SANDBOX_GATE.question());
    assert_ne!(
        D04_SANDBOX_GATE, settled,
        "the recorded decision is not the settled one"
    );
}

/// Boundary: no admission path names more than the scalar hop bound, and the
/// two readings sit at either end of it.
#[test]
fn every_admission_path_stays_inside_the_hop_bound() {
    let mut seen = 0usize;
    for path in SandboxAdmissionPath::BOTH {
        assert!(!path.hops().is_empty());
        assert!(path.hops().len() <= MAX_ADMISSION_HOPS);
        seen = seen.saturating_add(1);
    }
    assert_eq!(seen, 2);
    assert_eq!(
        SandboxAdmissionPath::DirectSyscallIntercept.hops().len(),
        1,
        "the direct reading is one hop"
    );
    assert_eq!(
        SandboxAdmissionPath::TransitiveThroughMinerva.hops().len(),
        MAX_ADMISSION_HOPS,
        "the transitive reading sits exactly at the bound"
    );
}

// --- The schema-to-edge map ----------------------------------------------

/// Positive: each schema names the edge it carries, in both directions.
#[test]
fn every_schema_names_its_graph_edge() {
    assert_eq!(
        contract_edges(),
        [
            (SchemaId::ActionProposal, EdgeId::ActionGateIntercept),
            (SchemaId::DecisionRequest, EdgeId::DispatchDecisionRequest),
            (
                SchemaId::SignedAuditRecord,
                EdgeId::AuditReconstructiveCandidate
            ),
        ]
    );
    for (schema, edge) in contract_edges() {
        assert_eq!(schema.edge(), edge);
        assert!(edge.in_graph_of_record());
    }
    assert_eq!(ActionProposal::SCHEMA, SchemaId::ActionProposal);
    assert_eq!(DecisionRequest::SCHEMA, SchemaId::DecisionRequest);
    assert_eq!(SignedAuditRecord::SCHEMA, SchemaId::SignedAuditRecord);
}

/// Negative: exactly one edge is absent from the graph of record, and it is the
/// one decision D04 is about.
///
/// The sweep iterates [`EdgeId::ALL`], which the crate declares beside the
/// exhaustive `name` match, rather than a copy of the list kept here. `EdgeId`
/// is `#[non_exhaustive]` and this is a separate crate, so a list kept here
/// could not be forced to grow with a new variant and this test would keep
/// passing while no longer testing what its name claims.
#[test]
fn only_the_disputed_edge_is_absent_from_the_graph_of_record() {
    let absent: Vec<EdgeId> = EdgeId::ALL
        .into_iter()
        .filter(|edge| !edge.in_graph_of_record())
        .collect();
    assert_eq!(absent, [EdgeId::SyscallIntercept]);
    assert_eq!(EdgeId::SyscallIntercept.name(), "SYSCALL_INTERCEPT");
}

/// Boundary: every edge in the exported set names itself and cites its
/// evidence, with no empty or duplicated identifier anywhere in the set.
#[test]
fn every_edge_name_is_distinct_and_cited() {
    let mut names: Vec<&'static str> = EdgeId::ALL.iter().map(|edge| edge.name()).collect();
    names.sort_unstable();
    let distinct = names.len();
    names.dedup();
    assert_eq!(names.len(), distinct, "edge names must be distinct");
    for edge in EdgeId::ALL {
        assert!(!edge.name().is_empty());
        assert!(edge.evidence().starts_with("export-"));
    }
    assert_eq!(
        EdgeId::DispatchDecisionRequest.name(),
        "DISPATCH_DECISION_REQUEST"
    );
    assert_eq!(
        EdgeId::AuditReconstructiveCandidate.name(),
        "AUDIT_RECONSTRUCTIVE_CANDIDATE"
    );
}
