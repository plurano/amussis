// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import "fmt"

// Class is what the engine decided about one proposal.
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
	// Allowed: the action may run.
	Allowed
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
)

// Outcome is the engine's answer to one proposal.
type Outcome struct {
	Class  Class
	Detail uint8
	Halt   uint8
}

// Permits reports whether the action may run now. Only Allowed and Warned
// permit; a held, blocked or refused action does not.
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
)

// decode reads the module's outcome code: class, detail and halt in the three
// low bytes, zero in the fourth. A code it does not know is an error, never a
// permitting outcome: an answer that permits carries exactly the bytes the
// module writes for it.
func decode(code uint32) (Outcome, error) {
	class, detail, halt, rest := uint8(code), uint8(code>>8), uint8(code>>16), uint8(code>>24)
	outcome := Outcome{Detail: detail, Halt: halt}
	switch {
	case rest != 0:
		return Outcome{}, fmt.Errorf("outcome code %#x sets a reserved byte", code)
	case class == wireAllow && detail == 0 && halt == 0:
		outcome.Class = Allowed
	case class == wireWarn && detail != 0 && halt == 0:
		outcome.Class = Warned
	case class == wireRequireApproval && detail == 0 && halt == 0:
		outcome.Class = RequireApproval
	case class == wireBlock && detail != 0 && detail != BlockLoaderFault:
		outcome.Class = Blocked
	case class == wireRefused && detail != 0 && halt == 0:
		outcome.Class = Refused
	default:
		return Outcome{}, fmt.Errorf("outcome code %#x is not one the module writes", code)
	}
	return outcome, nil
}
