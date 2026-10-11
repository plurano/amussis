// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

// Where the content of a record names what it is about: the intent id and
// the agent id, each behind a length of four bytes, then the persons.
const namesAt = levelAt + 1

// The maker of the proposals of these tests.
const maker = "maker-alice"

// persons is what the content of a record says about the persons it names:
// the risk level the approval rule was asked at, and the maker (or the
// releaser) followed by the checkers. A record that names nobody states
// level zero and no person.
type persons struct {
	level byte
	named []string
}

// framed takes one field behind its four-byte length off rest.
func framed(t *testing.T, rest *[]byte) string {
	t.Helper()
	if len(*rest) < 4 {
		t.Fatalf("the content ends %d bytes into a length", len(*rest))
	}
	length := int(binary.BigEndian.Uint32(*rest))
	if length > len(*rest)-4 {
		t.Fatalf("a field of %d bytes runs past the content", length)
	}
	field := string((*rest)[4 : 4+length])
	*rest = (*rest)[4+length:]
	return field
}

// namedIn reads the persons the content of a stored record names. The
// content ends with them: a byte behind the second checker is a failure.
func namedIn(t *testing.T, record Record) persons {
	t.Helper()
	if len(record.Preimage) <= namesAt {
		t.Fatalf("a content of %d bytes names nothing", len(record.Preimage))
	}
	rest := record.Preimage[namesAt:]
	framed(t, &rest)
	framed(t, &rest)
	if len(rest) == 0 {
		t.Fatal("the content ends behind the agent id and names no person")
	}
	found := persons{level: rest[0]}
	rest = rest[1:]
	for range 1 + MaxCheckers {
		if person := framed(t, &rest); person != "" {
			found.named = append(found.named, person)
		}
	}
	if len(rest) != 0 {
		t.Fatalf("%d bytes follow the second checker", len(rest))
	}
	return found
}

func wantNamed(t *testing.T, record Record, level Level, named ...string) {
	t.Helper()
	found := namedIn(t, record)
	if found.level != byte(level) || !slices.Equal(found.named, named) {
		t.Fatalf("the record names %q at level %d, want %q at level %d", found.named, found.level, named, level)
	}
}

// Positive: the record of a decision names the maker of the proposal and the
// level of the action, and no checker: an action that passes, and one that
// is held for its checkers.
func TestTheRecordOfADecisionNamesTheMaker(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		want(t, decide(t, engine, routine), Outcome{Class: Allowed})
		wantNamed(t, head(t, w), LevelRoutine, maker)
		want(t, decide(t, engine, heldConsequential), Outcome{Class: RequireApproval})
		wantNamed(t, head(t, w), LevelConsequential, maker)
	})
}

// Positive: the record of a vote names the maker and the checkers who cast
// it, in the order the caller named them: one checker, and two.
func TestTheRecordOfAVoteNamesTheCheckers(t *testing.T) {
	votes := []struct {
		name     string
		proposal string
		level    Level
		vote     Vote
		checkers []string
	}{
		{"one checker approves", heldConsequential, LevelConsequential, Approve, []string{"carol"}},
		{"one checker rejects", heldConsequential, LevelConsequential, Reject, []string{"carol"}},
		{"two checkers approve", heldBiometric, LevelAnnexIIIRoutine, Approve, []string{"dave", "carol"}},
	}
	for _, cast := range votes {
		t.Run(cast.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := newWorld()
				engine := holding(t, w, mode, cast.proposal)
				adjudicate(t, engine, vote(cast.vote, cast.checkers...))
				wantNamed(t, head(t, w), cast.level, append([]string{maker}, cast.checkers...)...)
				wantChain(t, w, 2)
			})
		})
	}
}

// Positive: the record of a release names the level the halt stood at, the
// person who released it and the checkers who approved.
func TestTheRecordOfAReleaseNamesTheReleaserAndTheApprovers(t *testing.T) {
	releases := []struct {
		name     string
		proposal string
		level    Level
		release  *Release
	}{
		{"alone", routine, LevelRoutine, by("olga")},
		{"with one checker", consequential, LevelConsequential, by("olga", "petra")},
		{"with two checkers", biometric, LevelAnnexIIIRoutine, by("olga", "quinn", "petra")},
	}
	for _, lifted := range releases {
		t.Run(lifted.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := haltedOver(t, mode, lifted.proposal)
				continued(t, w, mode, Continuation{Head: head(t, w), Release: lifted.release})
				record := head(t, w)
				if record.Preimage[statusAt] != statusHaltReleased {
					t.Fatalf("the head has status %d, not the one of a release", record.Preimage[statusAt])
				}
				wantNamed(t, record, lifted.level, append([]string{lifted.release.Releaser}, lifted.release.Checkers...)...)
			})
		})
	}
}

// Negative: the record of a halt names nobody. Halt takes no person, and
// the record states level zero where a person's record states its level.
func TestTheRecordOfAHaltNamesNobody(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		if err := engine.Halt(t.Context(), LevelConsequential); err != nil {
			t.Fatalf("Halt: %v", err)
		}
		record := head(t, w)
		if record.Preimage[statusAt] != statusHaltEngaged || record.Preimage[levelAt] != byte(LevelConsequential) {
			t.Fatalf("the head is no halt at the level asked: status %d", record.Preimage[statusAt])
		}
		wantNamed(t, record, 0)
	})
}

// Boundary: an identity of the longest length, the 64 characters a keyed
// hash in hexadecimal has, is recorded byte for byte in every place a
// person stands in, and the record stays within the bound of a content.
func TestAnIdentityOfSixtyFourBytesIsRecordedByteForByte(t *testing.T) {
	hashOf := func(digit string) string { return strings.Repeat(digit, MaxPersonBytes) }
	proposal := strings.Replace(heldBiometric, maker, hashOf("a"), 1)
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := holding(t, w, mode, proposal)
		wantNamed(t, head(t, w), LevelAnnexIIIRoutine, hashOf("a"))
		adjudicate(t, engine, vote(Approve, hashOf("b"), hashOf("c")))
		wantNamed(t, head(t, w), LevelAnnexIIIRoutine, hashOf("a"), hashOf("b"), hashOf("c"))
		wantChain(t, w, 2)
	})
}

// Negative: one person is one string of bytes. A checker whose identity is
// the maker's is not taken and no record names it; the same identity in
// another letter case is another person to the engine, which is why a host
// writes every role's hash the same way.
func TestAMakerAmongTheCheckersIsNotRecorded(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := holding(t, w, mode, heldConsequential)
		wantUntaken(t, w, engine, vote(Approve, maker), untaken(UnadjudicatedApproval, 0))
		adjudicate(t, engine, vote(Approve, strings.ToUpper(maker)))
		wantNamed(t, head(t, w), LevelConsequential, maker, strings.ToUpper(maker))
	})
}

// Negative: a head record in the layout of the interface version before this
// one, which ends behind the agent id, is no head. The record hashes to its
// digest; what refuses it is that it names nobody in any form. The same
// record as the engine wrote it continues the chain.
func TestAHeadWithoutTheNamesIsNoHead(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		allow(t, engineFor(t, w, mode), 1)
		written := head(t, w)
		names := 1 + 4 + len(maker) + 4*MaxCheckers
		earlier := written
		earlier.Preimage = bytes.Clone(written.Preimage[:len(written.Preimage)-names])
		earlier.Digest = sha256.Sum256(earlier.Preimage)
		wantRefused(t, w, mode, Continuation{Head: earlier}, ErrHead)
		allow(t, continued(t, w, mode, Continuation{Head: written}), 1)
		wantChain(t, w, 2)
	})
}
