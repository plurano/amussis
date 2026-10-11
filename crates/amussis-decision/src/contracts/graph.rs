// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The subsystem-graph edges these contracts carry, and the two decisions
//! about them that milestone M14 settles or records.
//!
//! The graph of record is the imported subsystem graph (export-062
//! `1ce919ed54bb`). Two of its edges were disputed by the architecture document
//! (export-002 `7e0c95f4ea05`), and this module is where the code states what
//! was decided about each:
//!
//! * **D03's direction is closed here; its transport is not.** The action gate
//!   keeps the graph's edge identifier `ACTION_GATE_INTERCEPT`, and the call
//!   semantics are propose/intercept: P09 Minerva proposes an action and P06
//!   Justitia intercepts and decides. [`GateDirection`] has exactly one
//!   variant, so the settled direction is the only one a payload can name and
//!   the opposite reading is unrepresentable rather than merely discouraged.
//!   The roadmap poses D03 as one question about direction *and* transport, and
//!   only the first half is answered. The record is split to say so:
//!   [`D03_ACTION_GATE_DIRECTION`] is closed, [`D03_ACTION_GATE_TRANSPORT`] is
//!   not, and [`D03_ACTION_GATE`] is the pair rather than a single settled
//!   decision, so nothing in this crate can be read as closing D03 as a whole.
//! * **D04 is recorded here, not settled.** Whether P06 also gates P10 Vesta
//!   directly is supported by one source and absent from the graph of record,
//!   so [`SandboxAdmissionPath`] keeps *both* readings representable and
//!   neither authoritative.
//!
//! # What this module does not do
//!
//! Nothing here admits or refuses anything. [`SandboxAdmissionPath`] is a
//! register of the two readings D04 leaves open: it names the hops of each and
//! whether the graph of record contains them, and the tests that sweep it are a
//! decision-register sweep over that static table, not contract tests. No
//! payload crosses either path and no sandbox execution is gated. The
//! behavioural contract for both admission paths -- what is admitted, what is
//! refused, and the evidence on which D04 is finally settled -- is milestone
//! M06's work, not this milestone's.

use crate::contracts::SchemaId;

/// Scalar upper bound on the hops any admission path may name.
pub const MAX_ADMISSION_HOPS: usize = 2;

/// The subsystem-graph edges this crate's contracts touch.
///
/// The identifiers are the graph's own (export-062 `1ce919ed54bb`), kept
/// verbatim under decision D03 so an edge stays traceable to its source even
/// where a direction was reinterpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum EdgeId {
    /// P06 and P09: the pre-execution risk-tier gate and approval routing.
    #[serde(rename = "ACTION_GATE_INTERCEPT")]
    ActionGateIntercept,
    /// P06 to P05: the Article 14 human-overseer decision-request payload.
    #[serde(rename = "DISPATCH_DECISION_REQUEST")]
    DispatchDecisionRequest,
    /// P06 to P16: signed audit records for proposed candidate modifications.
    #[serde(rename = "AUDIT_RECONSTRUCTIVE_CANDIDATE")]
    AuditReconstructiveCandidate,
    /// P09 to P10: capsule execution inside a Vesta sandbox.
    #[serde(rename = "EXECUTE_WASMED_CAPSULE")]
    ExecuteWasmedCapsule,
    /// P06 to P10: the direct syscall intercept drawn by export-002 only.
    #[serde(rename = "SYSCALL_INTERCEPT")]
    SyscallIntercept,
}

impl EdgeId {
    /// Every edge this enum names, in declaration order.
    ///
    /// Declared immediately above [`Self::name`] on purpose. That match is
    /// exhaustive over the enum, as is [`Self::evidence`] below it, so adding a
    /// variant is a compile error inside this block and the array is updated in
    /// the same edit. The set is exported rather than re-declared by each sweep
    /// that needs one because `#[non_exhaustive]` stops a consumer crate from
    /// matching the enum exhaustively: a test holding its own copy of the list
    /// cannot be broken by a new variant at all, and would quietly stop testing
    /// what its name claims.
    pub const ALL: [Self; 5] = [
        Self::ActionGateIntercept,
        Self::DispatchDecisionRequest,
        Self::AuditReconstructiveCandidate,
        Self::ExecuteWasmedCapsule,
        Self::SyscallIntercept,
    ];

    /// Returns the edge identifier as it is written in the graph of record.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ActionGateIntercept => "ACTION_GATE_INTERCEPT",
            Self::DispatchDecisionRequest => "DISPATCH_DECISION_REQUEST",
            Self::AuditReconstructiveCandidate => "AUDIT_RECONSTRUCTIVE_CANDIDATE",
            Self::ExecuteWasmedCapsule => "EXECUTE_WASMED_CAPSULE",
            Self::SyscallIntercept => "SYSCALL_INTERCEPT",
        }
    }

    /// Returns `true` when the graph of record contains this edge.
    ///
    /// [`Self::SyscallIntercept`] is the single exception: it is drawn by the
    /// architecture document and absent from the graph, which is exactly what
    /// makes decision D04 unresolved.
    #[must_use]
    pub const fn in_graph_of_record(self) -> bool {
        !matches!(self, Self::SyscallIntercept)
    }

    /// Returns the export identifier that is this edge's primary evidence.
    #[must_use]
    pub const fn evidence(self) -> &'static str {
        match self {
            Self::SyscallIntercept => "export-002",
            Self::ActionGateIntercept
            | Self::DispatchDecisionRequest
            | Self::AuditReconstructiveCandidate
            | Self::ExecuteWasmedCapsule => "export-062",
        }
    }
}

/// The settled call direction of the P06/P09 action gate (decision D03).
///
/// One variant, on purpose. The graph of record draws the edge from P06 to P09
/// and the architecture document draws it from P09 to P06; D03 resolves the
/// disagreement in favour of propose/intercept semantics while keeping the
/// graph's edge identifier. Encoding the outcome as a single-variant enum makes
/// a payload that claims the opposite direction fail to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum GateDirection {
    /// P09 Minerva proposes; P06 Justitia intercepts and decides.
    #[serde(rename = "p09-proposes-p06-intercepts")]
    MinervaProposesJustitiaIntercepts,
}

impl GateDirection {
    /// The direction decision D03 settled, and the only one this build admits.
    pub const SETTLED: Self = Self::MinervaProposesJustitiaIntercepts;

    /// Returns the stable tag the wire form carries.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::MinervaProposesJustitiaIntercepts => "p09-proposes-p06-intercepts",
        }
    }

    /// Returns the subsystem that proposes an action.
    #[must_use]
    pub const fn proposer(self) -> &'static str {
        match self {
            Self::MinervaProposesJustitiaIntercepts => "P09_Minerva",
        }
    }

    /// Returns the subsystem that intercepts and decides.
    #[must_use]
    pub const fn interceptor(self) -> &'static str {
        match self {
            Self::MinervaProposesJustitiaIntercepts => "P06_Justitia",
        }
    }
}

/// How a P10 Vesta sandbox execution could reach the P06 gate (decision D04).
///
/// Both variants are admissible because D04 is unresolved. Neither is the
/// graph of record on its own: [`Self::DirectSyscallIntercept`] rests on a
/// single source, and [`Self::TransitiveThroughMinerva`] is composed of two
/// edges that the graph does contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SandboxAdmissionPath {
    /// P06 gates P10 directly over the action-gate program (export-002 only).
    DirectSyscallIntercept,
    /// P06 gates P09, and P09 executes the capsule in P10 (graph of record).
    TransitiveThroughMinerva,
}

impl SandboxAdmissionPath {
    /// The two readings D04 leaves open, in a fixed order.
    pub const BOTH: [Self; 2] = [Self::DirectSyscallIntercept, Self::TransitiveThroughMinerva];

    /// Returns the edges this path traverses, at most [`MAX_ADMISSION_HOPS`].
    #[must_use]
    pub const fn hops(self) -> &'static [EdgeId] {
        match self {
            Self::DirectSyscallIntercept => &[EdgeId::SyscallIntercept],
            Self::TransitiveThroughMinerva => {
                &[EdgeId::ActionGateIntercept, EdgeId::ExecuteWasmedCapsule]
            }
        }
    }

    /// Returns `true` when every hop of this path is in the graph of record.
    #[must_use]
    pub fn in_graph_of_record(self) -> bool {
        self.hops().iter().all(|edge| edge.in_graph_of_record())
    }
}

/// Whether a recorded decision is settled or still open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionState {
    /// Settled; the types in this crate encode the outcome.
    Closed,
    /// Recorded and still open; every reading stays representable.
    Unresolved,
}

/// One roadmap decision, as the code that depends on it records it.
///
/// Keeping the record in code rather than only in prose means a later change
/// of mind has to touch the module that relies on the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionRecord {
    id: &'static str,
    state: DecisionState,
    question: &'static str,
}

impl DecisionRecord {
    /// Records one decision.
    #[must_use]
    pub const fn new(id: &'static str, state: DecisionState, question: &'static str) -> Self {
        Self {
            id,
            state,
            question,
        }
    }

    /// Returns the decision identifier, as the roadmap writes it.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Returns whether the decision is settled.
    #[must_use]
    pub const fn state(&self) -> DecisionState {
        self.state
    }

    /// Returns the question the decision answers, or leaves open.
    #[must_use]
    pub const fn question(&self) -> &'static str {
        self.question
    }

    /// Returns `true` only for a settled decision.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        matches!(self.state, DecisionState::Closed)
    }
}

/// D03's direction half: which way the P06/P09 action gate calls. Closed.
pub const D03_ACTION_GATE_DIRECTION: DecisionRecord = DecisionRecord::new(
    "D03",
    DecisionState::Closed,
    "Which direction does the Justitia/Minerva action gate call in?",
);

/// D03's transport half: what carries the P06/P09 action gate. Still open.
///
/// The roadmap poses D03 as one question about direction *and* transport, and
/// milestone M14 answered only the direction. Three transports are still named
/// for this single edge -- an eBPF `action_gate` program combined with D-Bus,
/// and a Unix domain socket with a sub-500 microsecond budget -- and the choice
/// is carried as dispute DSP-03 against open decision D26. "No transport is
/// implemented" and "no transport is decided" are different statements; the
/// module documentation makes the first, and this record makes the second.
pub const D03_ACTION_GATE_TRANSPORT: DecisionRecord = DecisionRecord::new(
    "D03",
    DecisionState::Unresolved,
    "Which transport does the Justitia/Minerva action gate use?",
);

/// D03 as a whole: both halves, direction first and transport second.
///
/// There is deliberately no single [`DecisionRecord`] for D03 and no settled
/// answer for it, because one half is settled and the other is not. A reader
/// who wants D03's state has to look at both, which is what keeps the code
/// record from reading as broader than the roadmap record.
pub const D03_ACTION_GATE: [DecisionRecord; 2] =
    [D03_ACTION_GATE_DIRECTION, D03_ACTION_GATE_TRANSPORT];

/// D04: whether P06 also gates P10 sandbox execution directly. Unresolved.
pub const D04_SANDBOX_GATE: DecisionRecord = DecisionRecord::new(
    "D04",
    DecisionState::Unresolved,
    "Does Justitia gate Vesta sandbox execution directly, or through Minerva?",
);

/// Returns the edge each schema carries, in schema order.
#[must_use]
pub const fn contract_edges() -> [(SchemaId, EdgeId); 3] {
    [
        (SchemaId::ActionProposal, EdgeId::ActionGateIntercept),
        (SchemaId::DecisionRequest, EdgeId::DispatchDecisionRequest),
        (
            SchemaId::SignedAuditRecord,
            EdgeId::AuditReconstructiveCandidate,
        ),
    ]
}
