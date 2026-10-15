// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

// The intent id the held action of these tests is proposed under.
const heldID = "intent-held-1"

// What the content of a record says at statusAt.
const (
	statusApproved    = 2
	statusRejected    = 3
	statusHaltEngaged = 6
)

// approvalWindow is the time in seconds the engine holds an action for.
const approvalWindow = 300

// The held actions of the two levels that need approval.
var (
	heldConsequential = strings.Replace(consequential, "intent-0001", heldID, 1)
	heldBiometric     = strings.Replace(biometric, "intent-0001", heldID, 1)
)

type recordFault struct {
	name        string
	plant, mend func(w *world)
}

// recordFaults are the signer and the sink, each failing in turn.
var recordFaults = []recordFault{
	{"signer", func(w *world) { w.signErr = errPlanted }, func(w *world) { w.signErr = nil }},
	{"sink", func(w *world) { w.sinkErr = errPlanted }, func(w *world) { w.sinkErr = nil }},
}

// holding is an engine that holds one action: proposal, under heldID.
func holding(t *testing.T, w *world, mode Mode, proposal string) *Engine {
	t.Helper()
	engine := engineFor(t, w, mode)
	want(t, decide(t, engine, proposal), Outcome{Class: RequireApproval})
	return engine
}

func adjudicate(t *testing.T, engine *Engine, adjudication Adjudication) Outcome {
	t.Helper()
	outcome, err := engine.Adjudicate(t.Context(), adjudication)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	return outcome
}

// vote is a decision of the held action by checkers.
func vote(vote Vote, checkers ...string) Adjudication {
	return Adjudication{IntentID: heldID, Vote: vote, Checkers: checkers}
}

func untaken(why, halt uint8) Outcome {
	return Outcome{Class: NotAdjudicated, Detail: why, Halt: halt}
}

// wantUntaken holds an adjudication to not being taken: the outcome names
// why, permits nothing, and nothing was stored for it.
func wantUntaken(t *testing.T, w *world, engine *Engine, adjudication Adjudication, expected Outcome) {
	t.Helper()
	stored := len(w.stored)
	outcome := adjudicate(t, engine, adjudication)
	if outcome != expected || outcome.Permits() || len(w.stored) != stored {
		t.Fatalf("%+v gave %+v with %d records, want %+v with %d", adjudication, outcome, len(w.stored), expected, stored)
	}
}

// raw hands bytes the loader never writes to the module's adjudicate
// function.
func raw(t *testing.T, engine *Engine, input []byte) Outcome {
	t.Helper()
	engine.mu.Lock()
	defer engine.mu.Unlock()
	outcome, err := engine.ask(t.Context(), engine.adjudicate, input, decodeAdjudication)
	if err != nil {
		t.Fatalf("the module did not answer %x: %v", input, err)
	}
	return outcome
}

// Positive: one checker approves a held action. The approval is a record of
// the chain under the intent id of the proposal, the action may run, and it
// is decided once.
func TestAnApprovalIsARecordAndLetsTheHeldActionProceed(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := holding(t, w, mode, heldConsequential)
		outcome := adjudicate(t, engine, vote(Approve, "carol"))
		if outcome != (Outcome{Class: Allowed}) || !outcome.Permits() {
			t.Fatalf("the approval gave %+v", outcome)
		}
		record := head(t, w)
		if record.Preimage[statusAt] != statusApproved || !bytes.Contains(record.Preimage, []byte(heldID)) {
			t.Fatalf("the record of the approval has status %d", record.Preimage[statusAt])
		}
		wantUntaken(t, w, engine, vote(Approve, "carol"), untaken(UnadjudicatedAlreadyDecided, 0))
		wantChain(t, w, 2)
	})
}

// Positive: a rejection is a decision and a record, and permits nothing; an
// approval that follows it is not taken.
func TestARejectionIsARecordAndPermitsNothing(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := holding(t, w, mode, heldConsequential)
		outcome := adjudicate(t, engine, vote(Reject, "carol"))
		if outcome != (Outcome{Class: Rejected}) || outcome.Permits() {
			t.Fatalf("the rejection gave %+v", outcome)
		}
		if status := head(t, w).Preimage[statusAt]; status != statusRejected {
			t.Fatalf("the record of the rejection has status %d", status)
		}
		wantUntaken(t, w, engine, vote(Approve, "carol"), untaken(UnadjudicatedAlreadyDecided, 0))
		wantChain(t, w, 2)
	})
}

// Planted, both ways: the checkers are held to the approval rule of the
// action. A panel that is too small, names one person twice or names the
// maker of the proposal is not taken and records nothing; the action stays
// held, and the panel its level demands is taken.
func TestTheCheckersAreHeldToTheApprovalRuleOfTheAction(t *testing.T) {
	cases := []struct {
		name, proposal string
		full           []string
		short          [][]string
	}{
		{"one checker", heldConsequential, []string{"carol"}, [][]string{
			{"maker-alice"}, {"carol", "carol"}, {"carol", "maker-alice"},
		}},
		{"two checkers", heldBiometric, []string{"carol", "dave"}, [][]string{
			{"carol"}, {"maker-alice"}, {"carol", "carol"}, {"maker-alice", "carol"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := newWorld()
				engine := holding(t, w, mode, c.proposal)
				for _, panel := range c.short {
					wantUntaken(t, w, engine, vote(Approve, panel...), untaken(UnadjudicatedApproval, 0))
				}
				want(t, adjudicate(t, engine, vote(Approve, c.full...)), Outcome{Class: Allowed})
				wantChain(t, w, 2)
			})
		})
	}
}

// Planted: an adjudication for an action that is not held. Nothing was
// proposed, the action was allowed and never held, another action is the
// held one, or an earlier engine held it: the engine takes no vote, records
// nothing and permits nothing.
func TestAnAdjudicationForAnActionThatIsNotHeldIsNotTaken(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		notHeld := untaken(UnadjudicatedUnknownRequest, 0)
		w := newWorld()
		engine := engineFor(t, w, mode)
		for _, decision := range []Vote{Approve, Reject} {
			wantUntaken(t, w, engine, vote(decision, "carol"), notHeld)
		}
		if w.offered != 0 {
			t.Fatalf("an adjudication of nothing offered %d records", w.offered)
		}
		allow(t, engine, 1)
		wantUntaken(t, w, engine, Adjudication{IntentID: "intent-0001", Vote: Approve, Checkers: []string{"carol"}}, notHeld)

		held := newWorld()
		first := holding(t, held, mode, heldConsequential)
		wantUntaken(t, held, first, Adjudication{IntentID: "intent-held-2", Vote: Approve, Checkers: []string{"carol"}}, notHeld)
		if err := first.Close(t.Context()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		second := continued(t, held, mode, Continuation{Head: head(t, held)})
		wantUntaken(t, held, second, vote(Approve, "carol"), notHeld)
	})
}

// Planted: a host that cannot sign the record of a vote, or cannot store it.
// An approval that is not in the chain did not happen: the outcome permits
// nothing, the action is no longer held and the engine is halted, also for
// a host that delivers again.
func TestAVoteThatCannotBeSignedOrStoredIsNoVoteAndHalts(t *testing.T) {
	for _, fault := range recordFaults {
		for _, decision := range []Vote{Approve, Reject} {
			t.Run(fault.name, func(t *testing.T) {
				inBothModes(t, func(t *testing.T, mode Mode) {
					w := newWorld()
					engine := holding(t, w, mode, heldConsequential)
					fault.plant(w)
					wantUntaken(t, w, engine, vote(decision, "carol"), untaken(UnadjudicatedUnrecorded, HaltAuditUnavailable))
					fault.mend(w)
					wantUntaken(t, w, engine, vote(decision, "carol"), untaken(UnadjudicatedHalted, HaltAuditUnavailable))
					want(t, decide(t, engine, routine), halted(HaltAuditUnavailable))
				})
			})
		}
	}
}

// Planted, both ways: a clock that cannot be read when the decision
// arrives. No vote is taken and the engine halts at the level of the held
// action; an adjudication that names no held action halts at the highest.
func TestAnAdjudicationUnderAnUnreadableClockHaltsAtTheLevelInHand(t *testing.T) {
	cases := []struct {
		intent string
		level  byte
	}{{heldID, byte(LevelConsequential)}, {"intent-held-2", levelHighest}}
	for _, c := range cases {
		t.Run(c.intent, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := newWorld()
				engine := holding(t, w, mode, heldConsequential)
				adjudication := Adjudication{IntentID: c.intent, Vote: Approve, Checkers: []string{"carol"}}
				w.clockErr = errPlanted
				outcome := adjudicate(t, engine, adjudication)
				w.clockErr = nil
				want(t, outcome, untaken(UnadjudicatedClockUnavailable, HaltClockUnavailable))
				record := head(t, w)
				if record.Preimage[statusAt] != statusHaltEngaged || record.Preimage[levelAt] != c.level {
					t.Fatalf("the halt record has status %d and level %d, want level %d", record.Preimage[statusAt], record.Preimage[levelAt], c.level)
				}
				wantUntaken(t, w, engine, adjudication, untaken(UnadjudicatedHalted, HaltClockUnavailable))
			})
		})
	}
}

// Boundary: a held action is decided inside its approval window. One second
// before the window closes the approval is taken; at the second it closes it
// is not, and nothing is recorded.
func TestAHeldActionIsDecidedOnlyInsideItsApprovalWindow(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		open := newWorld()
		engine := holding(t, open, mode, heldConsequential)
		open.now = testStart + approvalWindow - 1
		want(t, adjudicate(t, engine, vote(Approve, "carol")), Outcome{Class: Allowed})

		late := newWorld()
		engine = holding(t, late, mode, heldConsequential)
		late.now = testStart + approvalWindow
		wantUntaken(t, late, engine, vote(Approve, "carol"), untaken(UnadjudicatedExpired, 0))
	})
}

// Negative: a halted engine takes no decision of a held action, approval or
// rejection.
func TestAHaltedEngineTakesNoAdjudication(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := holding(t, w, mode, heldConsequential)
		if err := engine.Halt(t.Context(), operator, LevelRoutine); err != nil {
			t.Fatalf("Halt: %v", err)
		}
		for _, decision := range []Vote{Approve, Reject} {
			wantUntaken(t, w, engine, vote(decision, "carol"), untaken(UnadjudicatedHalted, HaltOperatorStop))
		}
		wantChain(t, w, 2)
	})
}

// Negative: an adjudication that cannot be read is refused, by the loader
// where a length does not fit its prefix and by the module for the rest. It
// reaches no effect and leaves the action held.
func TestAnAdjudicationThatCannotBeReadIsRefused(t *testing.T) {
	long := strings.Repeat("p", MaxPersonBytes+1)
	cases := []struct {
		name         string
		adjudication Adjudication
	}{
		{"no checker", vote(Approve)},
		{"three checkers", vote(Approve, "a", "b", "c")},
		{"an empty intent id", Adjudication{Vote: Approve, Checkers: []string{"carol"}}},
		{"an intent id past its bound", Adjudication{IntentID: long, Vote: Approve, Checkers: []string{"carol"}}},
		{"an empty checker", vote(Approve, "carol", "")},
		{"a checker past its bound", vote(Approve, long)},
		{"no vote", vote(voteUnset, "carol")},
		{"a vote past the last", vote(Reject+1, "carol")},
		{"an intent id outside the character set", Adjudication{IntentID: "bad id!", Vote: Approve, Checkers: []string{"carol"}}},
		{"a checker outside the character set", vote(Approve, "carol", "bad name!")},
		{"a checker that is no text", vote(Approve, "\xff\xfe")},
	}
	refused := Outcome{Class: Refused, Detail: RefusedAdjudication}
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := holding(t, w, mode, heldConsequential)
		for _, c := range cases {
			if outcome := adjudicate(t, engine, c.adjudication); outcome != refused || outcome.Permits() {
				t.Fatalf("%s gave %+v", c.name, outcome)
			}
		}
		if w.offered != 1 {
			t.Fatalf("refused adjudications offered %d records", w.offered-1)
		}
		want(t, adjudicate(t, engine, vote(Approve, "carol")), Outcome{Class: Allowed})
	})
}

// Negative, planted: the module holds the bytes of an adjudication to their
// layout by itself and does not rely on the loader for it.
func TestAdjudicationBytesTheModuleCannotReadAreRefused(t *testing.T) {
	good, written := encodeAdjudication(vote(Approve, "carol"))
	if !written {
		t.Fatal("the control adjudication was not written")
	}
	cases := []struct {
		name  string
		bytes []byte
	}{
		{"no bytes", nil},
		{"a vote alone", []byte{1}},
		{"no checker", []byte{1, 1, 'i', 0}},
		{"three checkers", []byte{1, 1, 'i', 3, 1, 'a', 1, 'b', 1, 'c'}},
		{"a count beyond the checkers", []byte{1, 1, 'i', 2, 1, 'a'}},
		{"a count of zero before two checkers", []byte{1, 1, 'i', 0, 1, 'a', 1, 'b'}},
		{"a count of three before two checkers", []byte{1, 1, 'i', 3, 1, 'a', 1, 'b'}},
		{"a length beyond the bytes", []byte{1, 1, 'i', 1, 5, 'a'}},
		{"bytes behind the last checker", append(bytes.Clone(good), 0)},
		{"an empty checker", []byte{1, 1, 'i', 1, 0}},
		{"a checker past its bound", append([]byte{1, 1, 'i', 1, MaxPersonBytes + 1}, bytes.Repeat([]byte{'p'}, MaxPersonBytes+1)...)},
	}
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := holding(t, w, mode, heldConsequential)
		for _, c := range cases {
			want(t, raw(t, engine, c.bytes), Outcome{Class: Refused, Detail: RefusedAdjudication})
		}
		past := make([]byte, engine.inputCapacity+1)
		want(t, raw(t, engine, past), Outcome{Class: Refused, Detail: RefusedTooLong})
		code, err := call(t.Context(), engine.adjudicate, math.MaxUint32)
		if err != nil || code != uint32(RefusedTooLong)<<8|wireRefused {
			t.Fatalf("the largest length gave the code %#x, error %v", code, err)
		}
		if w.offered != 1 {
			t.Fatalf("refused bytes offered %d records", w.offered-1)
		}
		want(t, raw(t, engine, good), Outcome{Class: Allowed})
	})
}

// Boundary: an adjudication at the bound of every part is written and taken:
// the longest intent id and two checkers of the longest name.
func TestAnAdjudicationAtTheBoundOfEveryPartIsTaken(t *testing.T) {
	intent := strings.Repeat("i", MaxPersonBytes)
	checkers := []string{strings.Repeat("c", MaxPersonBytes), strings.Repeat("d", MaxPersonBytes)}
	adjudication := Adjudication{IntentID: intent, Vote: Approve, Checkers: checkers}
	encoded, written := encodeAdjudication(adjudication)
	if !written || len(encoded) != 1+3*(1+MaxPersonBytes)+1 {
		t.Fatalf("the widest adjudication was written as %d bytes", len(encoded))
	}
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := holding(t, w, mode, strings.Replace(heldBiometric, heldID, intent, 1))
		want(t, adjudicate(t, engine, adjudication), Outcome{Class: Allowed})
		wantChain(t, w, 2)
	})
}

// Negative: an adjudication is written as the module reads it, byte for
// byte.
func TestAnAdjudicationIsWrittenInTheLayoutOfTheModule(t *testing.T) {
	encoded, written := encodeAdjudication(Adjudication{IntentID: "id-7", Vote: Reject, Checkers: []string{"al", "bea"}})
	expected := []byte{2, 4, 'i', 'd', '-', '7', 2, 2, 'a', 'l', 3, 'b', 'e', 'a'}
	if !written || !bytes.Equal(encoded, expected) {
		t.Fatalf("written as %v, want %v", encoded, expected)
	}
	if Approve != 1 || Reject != 2 {
		t.Fatalf("the votes are %d and %d", Approve, Reject)
	}
}

// Planted: an adjudication a part of which does not fit its length prefix or
// its count is not written at all. A name of 261 bytes would otherwise be
// written under the length 5 and read as another adjudication.
func TestAnAdjudicationThatDoesNotFitItsLayoutIsNotWritten(t *testing.T) {
	widest := strings.Repeat("p", MaxPersonBytes)
	unwritten := map[string]Adjudication{
		"no checker":                   vote(Approve),
		"three checkers":               vote(Approve, "a", "b", "c"),
		"an empty intent id":           {Vote: Approve, Checkers: []string{"carol"}},
		"an intent id past its bound":  {IntentID: widest + "p", Vote: Approve, Checkers: []string{"carol"}},
		"an empty checker":             vote(Approve, "carol", ""),
		"a checker past its bound":     vote(Approve, widest+"p"),
		"a checker past a length byte": vote(Approve, strings.Repeat("p", 261)),
	}
	for name, adjudication := range unwritten {
		if encoded, written := encodeAdjudication(adjudication); written || encoded != nil {
			t.Fatalf("%s was written as %d bytes", name, len(encoded))
		}
	}
	if _, written := encodeAdjudication(Adjudication{IntentID: widest, Vote: Reject, Checkers: []string{widest, widest}}); !written {
		t.Fatal("an adjudication at its bounds was not written")
	}
}

// Positive: an operator halt is a record of the chain at the level the
// caller names, for every level, and the engine blocks from then on.
func TestAnOperatorHaltIsARecordAtTheLevelItNames(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		for level := LevelRoutine; level <= LevelAnnexIIIConsequential; level++ {
			w := newWorld()
			engine := engineFor(t, w, mode)
			allow(t, engine, 1)
			if err := engine.Halt(t.Context(), operator, level); err != nil {
				t.Fatalf("Halt at level %d: %v", level, err)
			}
			checkOperatorHaltRecord(t, head(t, w).Preimage, level)
			outcome := decide(t, engine, routine)
			if outcome != halted(HaltOperatorStop) || outcome.Permits() {
				t.Fatalf("a halted engine decided %+v", outcome)
			}
			wantChain(t, w, 3)
		}
	})
	if LevelRoutine != levelLowest || LevelAnnexIIIConsequential != levelHighest {
		t.Fatal("the levels are not the tags one to six")
	}
}

func checkOperatorHaltRecord(t *testing.T, content []byte, level Level) {
	t.Helper()
	if content[statusAt] != statusHaltEngaged || content[latchAt] != 1 || content[reasonAt] != HaltOperatorStop || content[levelAt] != byte(level) {
		t.Fatalf("the halt record at level %d has status %d, reason %d and level %d", level, content[statusAt], content[reasonAt], content[levelAt])
	}
}

// Planted: a level value that is the tag of no level. The halt is not
// refused for it and stands at the highest level, also where the low byte of
// the value the module is handed is the tag of a lower one.
func TestAHaltAtNoLevelStandsAtTheHighest(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		for _, level := range []Level{0, 7, math.MaxUint8} {
			checkHaltStandsAtHighest(t, mode, level)
		}
		for _, level := range []uint64{256, 257, 0x0100_0003, math.MaxUint32} {
			checkHaltUnnamedStandsAtHighest(t, mode, level)
		}
	})
}

func checkHaltStandsAtHighest(t *testing.T, mode Mode, level Level) {
	t.Helper()
	w := newWorld()
	if err := engineFor(t, w, mode).Halt(t.Context(), operator, level); err != nil {
		t.Fatalf("Halt at %d: %v", level, err)
	}
	if stands := head(t, w).Preimage[levelAt]; stands != levelHighest {
		t.Fatalf("a halt at %d stands at level %d", level, stands)
	}
}

func checkHaltUnnamedStandsAtHighest(t *testing.T, mode Mode, level uint64) {
	t.Helper()
	w := newWorld()
	// No person is written: the halt of this call names nobody.
	status, err := call(t.Context(), engineFor(t, w, mode).halt, level, 0)
	if err != nil || status != haltUnnamed {
		t.Fatalf("the module answered a halt at %d with status %d, error %v", level, status, err)
	}
	if stands := head(t, w).Preimage[levelAt]; stands != levelHighest {
		t.Fatalf("a halt at %d stands at level %d", level, stands)
	}
}

// Planted: a host that cannot sign the record of a halt, or cannot store it.
// The engine is halted all the same and blocks while the fault lasts; the
// stored chain shows the halt once the host delivers again.
func TestAHaltThatCannotBeRecordedIsStillAHalt(t *testing.T) {
	for _, fault := range recordFaults {
		t.Run(fault.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				checkHaltRecordFault(t, mode, fault)
			})
		})
	}
}

func checkHaltRecordFault(t *testing.T, mode Mode, fault recordFault) {
	t.Helper()
	w := newWorld()
	engine := engineFor(t, w, mode)
	allow(t, engine, 1)
	fault.plant(w)
	if err := engine.Halt(t.Context(), operator, LevelMaterial); !errors.Is(err, ErrHaltUnrecorded) {
		t.Fatalf("a halt that cannot be recorded gave the error %v", err)
	}
	outcome := decide(t, engine, routine)
	if outcome != halted(HaltOperatorStop) || outcome.Permits() || len(w.stored) != 1 {
		t.Fatalf("an engine halted without a record decided %+v with %d records", outcome, len(w.stored))
	}
	fault.mend(w)
	if err := engine.Halt(t.Context(), operator, LevelMaterial); err != nil {
		t.Fatalf("the halt repeated under a host that delivers: %v", err)
	}
	content := head(t, w).Preimage
	if content[latchAt] != 1 || content[levelAt] != byte(LevelMaterial) {
		t.Fatalf("the stored chain does not show the halt: latch %d, level %d", content[latchAt], content[levelAt])
	}
	want(t, decide(t, engine, routine), halted(HaltOperatorStop))
}

// Boundary: a halt is never made weaker. A second halt at a stricter level
// raises the level and is a record; one at a lower level, or at no level
// where the highest stands, changes nothing and writes nothing.
func TestASecondHaltNeverLowersTheLevel(t *testing.T) {
	steps := []struct {
		asked   Level
		stands  byte
		records int
	}{{1, 1, 1}, {3, 3, 2}, {1, 3, 2}, {6, 6, 3}, {3, 6, 3}, {0, 6, 3}}
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		for _, step := range steps {
			if err := engine.Halt(t.Context(), operator, step.asked); err != nil {
				t.Fatalf("Halt at %d: %v", step.asked, err)
			}
			if stands := head(t, w).Preimage[levelAt]; stands != step.stands || len(w.stored) != step.records {
				t.Fatalf("after a halt at %d the level is %d in %d records", step.asked, stands, len(w.stored))
			}
		}
		wantChain(t, w, 3)
	})
}

// Planted, both ways: an operator halt is released as every halt is, at a
// continuation and with the approval of the level it stands at.
func TestAnOperatorHaltIsReleasedWithTheApprovalOfItsLevel(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		if err := engine.Halt(t.Context(), operator, LevelConsequential); err != nil {
			t.Fatalf("Halt: %v", err)
		}
		if err := engine.Close(t.Context()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		wantRefused(t, w, mode, Continuation{Head: head(t, w), Release: by("olga")}, ErrApproval)
		wantHalted(t, w, mode, HaltOperatorStop)
	})
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		if err := engineFor(t, w, mode).Halt(t.Context(), operator, LevelConsequential); err != nil {
			t.Fatalf("Halt: %v", err)
		}
		released := continued(t, w, mode, Continuation{Head: head(t, w), Release: by("olga", "petra")})
		allow(t, released, 1)
		wantChain(t, w, 3)
	})
}

// Boundary: an adjudication and a halt that find the module's window full
// drop it as a decision does, and their records go on the one chain.
func TestAnAdjudicationAndAHaltRunPastAFullWindow(t *testing.T) {
	const window = 4096
	w := newWorld()
	engine := holding(t, w, Compiled, heldConsequential)
	allow(t, engine, window-1)
	want(t, adjudicate(t, engine, vote(Approve, "carol")), Outcome{Class: Allowed})
	allow(t, engine, window-1)
	if err := engine.Halt(t.Context(), operator, LevelRoutine); err != nil {
		t.Fatalf("Halt: %v", err)
	}
	wantChain(t, w, 2*window+1)
}

// Negative: a closed engine takes no adjudication and no halt, readable or
// not.
func TestAClosedEngineTakesNoAdjudicationAndNoHalt(t *testing.T) {
	w := newWorld()
	engine := holding(t, w, Interpreted, heldConsequential)
	if err := engine.Close(t.Context()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, adjudication := range []Adjudication{vote(Approve, "carol"), vote(Approve)} {
		outcome, err := engine.Adjudicate(t.Context(), adjudication)
		if !errors.Is(err, errClosed) || outcome != loaderFault || outcome.Permits() {
			t.Fatalf("a closed engine gave %+v and the error %v", outcome, err)
		}
	}
	if err := engine.Halt(t.Context(), operator, LevelRoutine); !errors.Is(err, errClosed) {
		t.Fatalf("a closed engine halted with the error %v", err)
	}
	if w.offered != 1 {
		t.Fatalf("a closed engine offered %d records", w.offered-1)
	}
}

// An answer to an adjudication the module cannot have written blocks, and
// the engine is not asked again: no such answer is read as an approval.
func TestAnAdjudicationAnswerTheModuleDoesNotWriteBlocksAndPoisons(t *testing.T) {
	answers := []int64{9, 0x0101, 0x0002, 0x0203, 0x0100, 0x010000, 0x01000000, 0x0105, 0x0006, 0x0906, 0x0106, 0x010104}
	inBothModes(t, func(t *testing.T, mode Mode) {
		for _, answer := range answers {
			checkBadAdjudicationAnswer(t, mode, answer)
		}
	})
}

func checkBadAdjudicationAnswer(t *testing.T, mode Mode, answer int64) {
	t.Helper()
	s := realSurface()
	s.export(exportAdjudicate).value = answer
	engine, err := loadShape(t, s, mode)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for range 2 {
		outcome, err := engine.Adjudicate(t.Context(), vote(Approve, "carol"))
		if err == nil || outcome != loaderFault || outcome.Permits() {
			t.Fatalf("answer %#x gave %+v and the error %v", answer, outcome, err)
		}
	}
	if outcome, err := engine.Decide(t.Context(), []byte(routine)); err == nil || outcome != loaderFault {
		t.Fatalf("after answer %#x the engine decided %+v", answer, outcome)
	}
}

// A halt the module answers with a status the loader does not know is no
// halt the loader can rely on: the engine blocks from then on. The one
// status that says the halt stands unrecorded is ErrHaltUnrecorded, the one
// that says it names nobody is ErrHaltUnnamed, and both leave the engine to
// the module.
func TestAHaltTheModuleDoesNotConfirmPoisonsTheEngine(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		for _, status := range []int64{1, 2, 5, 0xff, -1} {
			checkUnknownHaltStatusPoisons(t, mode, status)
		}
		for status, want := range map[int64]error{haltUnrecorded: ErrHaltUnrecorded, haltUnnamed: ErrHaltUnnamed} {
			checkKnownHaltStatus(t, mode, status, want)
		}
	})
}

func checkUnknownHaltStatusPoisons(t *testing.T, mode Mode, status int64) {
	t.Helper()
	s := realSurface()
	s.export(exportHalt).value = status
	engine, err := loadShape(t, s, mode)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := engine.Halt(t.Context(), operator, LevelRoutine); err == nil || errors.Is(err, ErrHaltUnrecorded) || errors.Is(err, ErrHaltUnnamed) {
		t.Fatalf("halt status %d gave the error %v", status, err)
	}
	outcome, err := engine.Decide(t.Context(), []byte(routine))
	if err == nil || outcome != loaderFault || outcome.Permits() {
		t.Fatalf("after halt status %d the engine decided %+v, error %v", status, outcome, err)
	}
}

func checkKnownHaltStatus(t *testing.T, mode Mode, status int64, want error) {
	t.Helper()
	s := realSurface()
	s.export(exportHalt).value = status
	engine, err := loadShape(t, s, mode)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := engine.Halt(t.Context(), operator, LevelRoutine); !errors.Is(err, want) || engine.fault != nil {
		t.Fatalf("halt status %d gave the error %v and the fault %v", status, err, engine.fault)
	}
}

func TestOnlyTheAdjudicationCodesTheModuleWritesAreRead(t *testing.T) {
	read := map[uint32]Outcome{
		0x000000: {Class: Allowed},
		0x000005: {Class: Rejected},
		0x000206: untaken(UnadjudicatedUnknownRequest, 0),
		0x010106: untaken(UnadjudicatedHalted, HaltOperatorStop),
		0x020706: untaken(UnadjudicatedUnrecorded, HaltAuditUnavailable),
		0x000806: untaken(UnadjudicatedEngine, 0),
		0x000804: {Class: Refused, Detail: RefusedAdjudication},
	}
	for code, expected := range read {
		outcome, err := decodeAdjudication(code)
		if err != nil || outcome != expected || outcome.Permits() != (code == 0) {
			t.Fatalf("code %#x read as %+v, error %v", code, outcome, err)
		}
	}
	refused := []uint32{
		0x000100,   // approval with a detail
		0x010000,   // approval with a halt
		0x01000000, // approval with the reserved byte
		0x000101,   // a warning
		0x000002,   // a hold
		0x000203,   // a block
		0x000105,   // rejection with a detail
		0x010005,   // rejection with a halt
		0x000006,   // not taken, without a reason
		0x000906,   // not taken, for a reason past the last
		0x000106,   // halted, without the reason of the halt
		0x000004,   // refusal without a reason
		0x010804,   // refusal with a halt
		0x000007,   // a class past the last
		0xffffffff,
	}
	for _, code := range refused {
		if outcome, err := decodeAdjudication(code); err == nil || outcome != (Outcome{}) || outcome.Permits() {
			t.Fatalf("code %#x was read as %+v", code, outcome)
		}
	}
}
