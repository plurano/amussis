// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import "fmt"

// Class is what the engine decided about one proposal, or what came of the
// checkers' decision of a held action.
//
// The zero value is Blocked, so an Outcome that was never filled in permits
// nothing.
type Class uint8

const (
	// Blocked: the action must not run. Outcome.Detail says why.
	Blocked Class = iota
	// Refused: the input was not decided at all. Outcome.Detail says why.
	Refused
	// RequireApproval: the action is held until a checker approves it.
	RequireApproval
	// Warned: the action may run and is monitored.
	Warned
	// Allowed: the action may run. Decide gives it for an action that needs
	// no approval, Adjudicate for a held action the checkers approved.
	Allowed
	// Rejected: the checkers rejected the held action. It must not run.
	Rejected
	// NotAdjudicated: the engine took no decision of a held action and
	// recorded no vote. Outcome.Detail says why.
	NotAdjudicated
)

// Details of a Blocked outcome: the engine's block reasons.
const (
	// BlockHalted: the engine was halted earlier; Outcome.Halt says why.
	BlockHalted uint8 = 1
	// BlockAuditUnavailable: the record could not be signed or stored.
	BlockAuditUnavailable uint8 = 2
	// BlockClockUnavailable: the clock could not be read or stepped back.
	BlockClockUnavailable uint8 = 3
	// BlockLoaderFault: the loader could not run the module or read its
	// answer. The module never gives this detail; only this package does.
	BlockLoaderFault uint8 = 0xff
)

// Reasons for a halt, carried by Outcome.Halt beside BlockHalted.
const (
	HaltOperatorStop      uint8 = 1
	HaltAuditUnavailable  uint8 = 2
	HaltLedgerCompromised uint8 = 3
	HaltClockUnavailable  uint8 = 4
)

// Details of a Refused outcome.
const (
	RefusedNotInitialised uint8 = 1
	RefusedTooLong        uint8 = 2
	RefusedNotUTF8        uint8 = 3
	RefusedUnknownVersion uint8 = 4
	RefusedMalformed      uint8 = 5
	RefusedIntent         uint8 = 6
	RefusedBusy           uint8 = 7
	// RefusedAdjudication: the Adjudication cannot be read: a vote that is
	// neither Approve nor Reject, no checker or more than MaxCheckers, or an
	// intent id or a checker that is no identity of the engine.
	RefusedAdjudication uint8 = 8
)

// Details of a NotAdjudicated outcome. The action stays held, but for the
// one detail that says otherwise.
const (
	// UnadjudicatedHalted: the engine is halted and takes no decision of a
	// held action; Outcome.Halt says why.
	UnadjudicatedHalted uint8 = 1
	// UnadjudicatedUnknownRequest: no action is held under the intent id. It
	// was never held, or an earlier engine held it.
	UnadjudicatedUnknownRequest uint8 = 2
	// UnadjudicatedAlreadyDecided: the action was approved or rejected
	// before.
	UnadjudicatedAlreadyDecided uint8 = 3
	// UnadjudicatedExpired: the approval window of the action closed.
	UnadjudicatedExpired uint8 = 4
	// UnadjudicatedApproval: the checkers do not satisfy the approval rule of
	// the action: too few, one person named twice, or the maker among them.
	UnadjudicatedApproval uint8 = 5
	// UnadjudicatedClockUnavailable: the clock could not be read. The engine
	// is halted.
	UnadjudicatedClockUnavailable uint8 = 6
	// UnadjudicatedUnrecorded: the vote could not be signed or stored. The
	// action is no longer held, nothing was decided, and the engine is
	// halted.
	UnadjudicatedUnrecorded uint8 = 7
	// UnadjudicatedEngine: the engine refused for a reason that has no detail
	// of its own.
	UnadjudicatedEngine uint8 = 8
)

// Outcome is the engine's answer to one proposal or to one adjudication.
type Outcome struct {
	Class Class
	// Detail says why, for the classes that name one.
	Detail uint8
	// Halt is the reason the engine is halted for: beside BlockHalted, and
	// beside a NotAdjudicated outcome that found or left the engine halted.
	Halt uint8
}

// Permits reports whether the action may run now. Only Allowed and Warned
// permit; a held, blocked, refused or rejected action does not, and neither
// does one whose adjudication the engine did not take.
func (o Outcome) Permits() bool {
	return o.Class == Allowed || o.Class == Warned
}

// The class byte of the module's outcome code.
const (
	wireAllow           = 0
	wireWarn            = 1
	wireRequireApproval = 2
	wireBlock           = 3
	wireRefused         = 4
	wireRejected        = 5
	wireNotAdjudicated  = 6
)

// decode reads the module's outcome code for a proposal: class, detail and
// halt in the three low bytes, zero in the fourth. A code it does not know is
// an error, never a permitting outcome: an answer that permits carries
// exactly the bytes the module writes for it. The classes of an adjudication
// are none the module writes for a proposal.
func decode(code uint32) (Outcome, error) {
	class, detail, halt, rest := uint8(code), uint8(code>>8), uint8(code>>16), uint8(code>>24)
	if rest != 0 {
		return Outcome{}, fmt.Errorf("outcome code %#x sets a reserved byte", code)
	}
	var (
		c  Class
		ok bool
	)
	if halt != 0 {
		c, ok = decodeHaltedProposal(class, detail)
	} else {
		c, ok = decodeUnhaltedProposal(class, detail)
	}
	if !ok {
		return Outcome{}, fmt.Errorf("outcome code %#x is not one the module writes", code)
	}
	return Outcome{Class: c, Detail: detail, Halt: halt}, nil
}

func decodeHaltedProposal(class, detail uint8) (Class, bool) {
	if class == wireBlock && detail != 0 && detail != BlockLoaderFault {
		return Blocked, true
	}
	return 0, false
}

func decodeUnhaltedProposal(class, detail uint8) (Class, bool) {
	switch class {
	case wireAllow:
		return Allowed, detail == 0
	case wireWarn:
		return Warned, detail != 0
	case wireRequireApproval:
		return RequireApproval, detail == 0
	case wireBlock:
		return Blocked, detail != 0 && detail != BlockLoaderFault
	case wireRefused:
		return Refused, detail != 0
	default:
		return 0, false
	}
}

// decodeAdjudication reads the module's outcome code for an adjudication, as
// strictly as decode reads the one for a proposal. An approval is the allow
// code and no other; a warning, a hold and a block are none the module
// writes for an adjudication.
func decodeAdjudication(code uint32) (Outcome, error) {
	class, detail, halt, rest := uint8(code), uint8(code>>8), uint8(code>>16), uint8(code>>24)
	if rest != 0 {
		return Outcome{}, fmt.Errorf("outcome code %#x sets a reserved byte", code)
	}
	c, ok := decodeAdjudicationClass(class, detail, halt)
	if !ok {
		return Outcome{}, fmt.Errorf("outcome code %#x is not one the module writes for an adjudication", code)
	}
	return Outcome{Class: c, Detail: detail, Halt: halt}, nil
}

func decodeAdjudicationClass(class, detail, halt uint8) (Class, bool) {
	switch class {
	case wireAllow:
		return Allowed, detail == 0 && halt == 0
	case wireRejected:
		return Rejected, detail == 0 && halt == 0
	case wireNotAdjudicated:
		return NotAdjudicated, validNotAdjudicated(detail, halt)
	case wireRefused:
		return Refused, detail != 0 && halt == 0
	default:
		return 0, false
	}
}

func validNotAdjudicated(detail, halt uint8) bool {
	if detail < UnadjudicatedHalted || detail > UnadjudicatedEngine {
		return false
	}
	return detail != UnadjudicatedHalted || halt != 0
}
