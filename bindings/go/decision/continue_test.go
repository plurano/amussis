// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

// Where a walk over stored records reads the content of a record: the
// sequence number, the digest of the record before, the status, the halt
// flag, the halt reason and the risk level of the halt.
const (
	sequenceAt = 50
	previousAt = 58
	statusAt   = 98
	latchAt    = 102
	reasonAt   = 111
	levelAt    = 112
)

// What the content of a record says in those places.
const (
	statusHaltReleased = 7
	levelLowest        = 1
	levelHighest       = 6
)

// Proposals of the two risk levels above the routine one: an action one
// checker approves, and one two checkers approve.
var (
	consequential = strings.Replace(routine, "tier-c-routine-bounded", "tier-a-consequential", 1)
	biometric     = strings.Replace(routine, `"oversight":"standard"`, `"oversight":"annex-iii-biometric"`, 1)
)

func by(releaser string, checkers ...string) *Release {
	return &Release{Releaser: releaser, Checkers: checkers}
}

// walk reads stored records the way a reader of the store checks them: every
// content hashes to its digest, carries the next sequence number and names
// the record before. It returns the number of the last record.
func walk(stored []Record) (uint64, error) {
	var previous [DigestBytes]byte
	sequence := uint64(0)
	for _, record := range stored {
		sequence++
		if len(record.Preimage) <= reasonAt || sha256.Sum256(record.Preimage) != record.Digest {
			return 0, fmt.Errorf("record %d does not hash to its digest", sequence)
		}
		number := binary.BigEndian.Uint64(record.Preimage[sequenceAt:previousAt])
		link := record.Preimage[previousAt : previousAt+DigestBytes]
		if number != sequence || !bytes.Equal(link, previous[:]) {
			return 0, fmt.Errorf("record %d does not follow the one before", sequence)
		}
		previous = record.Digest
	}
	return sequence, nil
}

func wantChain(t *testing.T, w *world, records uint64) {
	t.Helper()
	last, err := walk(w.stored)
	if err != nil || last != records {
		t.Fatalf("the store holds a chain of %d records, error %v; want %d", last, err, records)
	}
}

func allow(t *testing.T, engine *Engine, count int) {
	t.Helper()
	for range count {
		want(t, decide(t, engine, routine), Outcome{Class: Allowed})
	}
}

// head is the last record the world's sink stored.
func head(t *testing.T, w *world) Record {
	t.Helper()
	if len(w.stored) == 0 {
		t.Fatal("the sink stored no record")
	}
	return w.stored[len(w.stored)-1]
}

// rehashed is record with one content byte set and the digest taken again: a
// record that hashes, with content no engine wrote.
func rehashed(record Record, at int, value byte) Record {
	record.Preimage = bytes.Clone(record.Preimage)
	record.Preimage[at] = value
	record.Digest = sha256.Sum256(record.Preimage)
	return record
}

func continued(t *testing.T, w *world, mode Mode, from Continuation) *Engine {
	t.Helper()
	needCompiler(t, mode)
	engine, err := Continue(t.Context(), w.config(mode), from)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	closeAtEnd(t, engine)
	return engine
}

// haltedOver is a world whose chain ends with the record of a decision
// blocked for want of a clock: two allowed records, then the halted one. The
// halt stands at the risk level of proposal, the action the engine had in
// hand when the clock failed.
func haltedOver(t *testing.T, mode Mode, proposal string) *world {
	t.Helper()
	w := newWorld()
	engine := engineFor(t, w, mode)
	allow(t, engine, 2)
	w.clockErr = errPlanted
	want(t, decide(t, engine, proposal), Outcome{Class: Blocked, Detail: BlockClockUnavailable})
	w.clockErr = nil
	if last := head(t, w); len(w.stored) != 3 || last.Preimage[latchAt] != 1 || last.Preimage[reasonAt] != HaltClockUnavailable {
		t.Fatalf("the chain does not end with a halted record: %d records", len(w.stored))
	}
	return w
}

// haltedWorld is a world halted at the lowest level, which one person
// releases.
func haltedWorld(t *testing.T, mode Mode) *world {
	t.Helper()
	w := haltedOver(t, mode, routine)
	if level := head(t, w).Preimage[levelAt]; level != levelLowest {
		t.Fatalf("a halt over a routine action stands at level %d", level)
	}
	return w
}

// wantRefused holds a release to the error it is refused with: no engine, no
// record, and the chain still continues halted.
func wantRefused(t *testing.T, w *world, mode Mode, from Continuation, refusal error) error {
	t.Helper()
	stored, offered := len(w.stored), w.offered
	engine, err := Continue(t.Context(), w.config(mode), from)
	if !errors.Is(err, refusal) || engine != nil {
		t.Fatalf("the release by %+v gave the error %v, want %v", from.Release, err, refusal)
	}
	if len(w.stored) != stored || (refusal != ErrReleaseFailed && w.offered != offered) {
		t.Fatalf("a refused release left %d records of %d offered, was %d of %d", len(w.stored), w.offered, stored, offered)
	}
	return err
}

// wantHalted holds a chain to continuing halted from its head.
func wantHalted(t *testing.T, w *world, mode Mode, why uint8) {
	t.Helper()
	kept := continued(t, w, mode, Continuation{Head: head(t, w)})
	want(t, decide(t, kept, routine), halted(why))
}

// Boundary: the module keeps a window of 4,096 records in memory. An engine
// decides that many, drops the window at the next decision and goes on; what
// the sink stored stays one chain.
func TestTheChainRunsPastTheWindowAsOneChain(t *testing.T) {
	const window = 4096
	w := newWorld()
	engine := engineFor(t, w, Compiled)
	allow(t, engine, window)
	wantChain(t, w, window)
	allow(t, engine, 3)
	wantChain(t, w, window+3)
}

func TestANewEngineContinuesTheChainFromItsStoredHead(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		first := engineFor(t, w, mode)
		allow(t, first, 3)
		if err := first.Close(t.Context()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		second := continued(t, w, mode, Continuation{Head: head(t, w)})
		if second.Mode() != mode {
			t.Fatalf("the engine runs %v, asked for %v", second.Mode(), mode)
		}
		allow(t, second, 2)
		wantChain(t, w, 5)
	})
}

// Negative: a release given for a chain that does not end halted is refused,
// whoever approves it, and the chain goes on without it.
func TestAReleaseOfAChainThatIsNotHaltedIsRefused(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		allow(t, engineFor(t, w, mode), 2)
		for _, release := range []*Release{by("olga"), by("olga", "petra", "quinn")} {
			wantRefused(t, w, mode, Continuation{Head: head(t, w), Release: release}, ErrNotHalted)
		}
		allow(t, continued(t, w, mode, Continuation{Head: head(t, w)}), 1)
		wantChain(t, w, 3)
	})
}

// The planted case of the head: a record that is not the last one stored is a
// record of the chain, so the module takes it. The store then holds two
// records with one sequence number, and the walk refuses it.
func TestAContinuationFromAnotherRecordThanTheHeadShowsInTheStore(t *testing.T) {
	w := newWorld()
	allow(t, engineFor(t, w, Compiled), 3)
	wantChain(t, w, 3)
	engine := continued(t, w, Compiled, Continuation{Head: w.stored[1]})
	allow(t, engine, 1)
	last, err := walk(w.stored)
	if err == nil || !strings.Contains(err.Error(), "record 4 does not follow") {
		t.Fatalf("a chain continued from its second record walked to %d, error %v", last, err)
	}
}

func TestAHeadThatIsNoRecordOfTheChainIsRefused(t *testing.T) {
	plants := []struct {
		name  string
		plant func(r *Record)
		// refusal is a text of the error, for a head the loader itself
		// refuses before the module sees it.
		refusal string
	}{
		{"content edited after it was hashed", func(r *Record) { r.Preimage = bytes.Clone(r.Preimage); r.Preimage[sequenceAt+7] ^= 1 }, "status 6"},
		{"another digest", func(r *Record) { r.Digest[0] ^= 1 }, "status 6"},
		{"another sequence number, hashed again, with one byte too many", func(r *Record) {
			*r = rehashed(Record{Preimage: append(bytes.Clone(r.Preimage), 0), KeyID: r.KeyID, Signature: r.Signature}, sequenceAt, 9)
		}, "status 5"},
		{"content of another format, hashed", func(r *Record) { *r = rehashed(*r, 0, 'x') }, "status 5"},
		{"sequence number zero, hashed", func(r *Record) { *r = rehashed(*r, sequenceAt+7, 0) }, "status 5"},
		{"a halt flag that is neither set nor clear, hashed", func(r *Record) { *r = rehashed(*r, latchAt, 2) }, "status 5"},
		{"no content", func(r *Record) { r.Preimage, r.Digest = nil, sha256.Sum256(nil) }, "status 5"},
		{"no key identifier", func(r *Record) { r.KeyID = "" }, "status 5"},
		{"no signature", func(r *Record) { r.Signature = nil }, "status 5"},
		{"a key identifier beyond its length prefix", func(r *Record) { r.KeyID = strings.Repeat("k", 256) }, errFrame.Error()},
		{"a signature beyond the input buffer", func(r *Record) { r.Signature = make([]byte, 4096) }, "do not fit the module's input buffer"},
		{"the zero record", func(r *Record) { *r = Record{} }, "status 5"},
	}
	for _, plant := range plants {
		t.Run(plant.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := newWorld()
				allow(t, engineFor(t, w, mode), 2)
				record := head(t, w)
				plant.plant(&record)
				for _, release := range []*Release{nil, by("olga")} {
					engine, err := Continue(t.Context(), w.config(mode), Continuation{Head: record, Release: release})
					if !errors.Is(err, ErrHead) || engine != nil || !strings.Contains(err.Error(), plant.refusal) {
						t.Fatalf("release %+v: a head with %s gave the error %v", release, plant.name, err)
					}
				}
				if len(w.stored) != 2 {
					t.Fatal("a refused continuation reached the sink")
				}
			})
		})
	}
}

func TestAChainThatEndsHaltedContinuesHalted(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		engine := continued(t, w, mode, Continuation{Head: head(t, w)})
		for range 3 {
			outcome := decide(t, engine, routine)
			want(t, outcome, halted(HaltClockUnavailable))
			if outcome.Permits() {
				t.Fatal("a halted chain permits an action after a restart")
			}
		}
		again := continued(t, w, mode, Continuation{Head: head(t, w)})
		want(t, decide(t, again, routine), halted(HaltClockUnavailable))
		wantChain(t, w, uint64(len(w.stored)))
	})
}

// Positive: a halt at the lowest level is released by one person. The
// release is a record of its own, and the chain shows the halt, the release
// and the decisions after it as one chain.
func TestTheLowestLevelIsReleasedByOnePerson(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		engine := continued(t, w, mode, Continuation{Head: head(t, w), Release: by("olga")})
		if release := head(t, w).Preimage; len(w.stored) != 4 || release[statusAt] != statusHaltReleased || release[latchAt] != 0 {
			t.Fatalf("the release is not the fourth record of the chain: %d records", len(w.stored))
		}
		allow(t, engine, 2)
		wantChain(t, w, 6)
		if w.stored[2].Preimage[latchAt] != 1 || w.stored[4].Preimage[latchAt] != 0 {
			t.Fatal("the chain does not show the halt before the release and none after it")
		}
	})
}

// Planted, both ways: a release without the approval the halted level
// demands is refused, and the same release with it passes. One checker for a
// level whose actions take one, two distinct ones for a level whose actions
// take two; the releaser is no checker of the own release.
func TestAReleaseWithoutTheNeededApprovalIsRefused(t *testing.T) {
	levels := []struct {
		name     string
		proposal string
		lacking  []*Release
		enough   *Release
	}{
		{"one checker", consequential, []*Release{by("olga"), by("olga", "olga")}, by("olga", "petra")},
		{"two checkers", biometric, []*Release{
			by("olga"), by("olga", "petra"), by("olga", "petra", "petra"), by("olga", "petra", "olga"), by("olga", "olga", "petra"),
		}, by("olga", "petra", "quinn")},
	}
	for _, level := range levels {
		t.Run(level.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := haltedOver(t, mode, level.proposal)
				for _, release := range level.lacking {
					wantRefused(t, w, mode, Continuation{Head: head(t, w), Release: release}, ErrApproval)
					wantHalted(t, w, mode, HaltClockUnavailable)
				}
				stored := len(w.stored)
				engine := continued(t, w, mode, Continuation{Head: head(t, w), Release: level.enough})
				allow(t, engine, 1)
				wantChain(t, w, uint64(stored)+2)
			})
		})
	}
}

// Boundary: the level of a halt is what the head record states. A head
// halted at the lowest level, with the level set to the highest and hashed
// again, takes two checkers; a halted head that states no level, or one the
// engine does not have, is no head.
func TestTheLevelOfTheHeadRecordDecidesTheApproval(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		highest := rehashed(head(t, w), levelAt, levelHighest)
		for _, release := range []*Release{by("olga"), by("olga", "petra")} {
			wantRefused(t, w, mode, Continuation{Head: highest, Release: release}, ErrApproval)
		}
		for _, level := range []byte{0, levelHighest + 1, 255} {
			for _, release := range []*Release{nil, by("olga", "petra", "quinn")} {
				wantRefused(t, w, mode, Continuation{Head: rehashed(head(t, w), levelAt, level), Release: release}, ErrHead)
			}
		}
		allow(t, continued(t, w, mode, Continuation{Head: highest, Release: by("olga", "petra", "quinn")}), 1)
	})
}

// Planted: the level of a halt travels with every record written under it.
// A chain halted at a level that takes one checker continues halted, blocks
// a routine action there, and is continued again from the record of that
// block: the release still takes the checker.
func TestTheLevelOfAHaltIsCarriedOverEveryContinuation(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedOver(t, mode, consequential)
		level := head(t, w).Preimage[levelAt]
		wantHalted(t, w, mode, HaltClockUnavailable)
		if last := head(t, w).Preimage; len(w.stored) != 4 || last[levelAt] != level || level == levelLowest {
			t.Fatalf("the record of a block under the halt states level %d, the halt %d", last[levelAt], level)
		}
		wantRefused(t, w, mode, Continuation{Head: head(t, w), Release: by("olga")}, ErrApproval)
		allow(t, continued(t, w, mode, Continuation{Head: head(t, w), Release: by("olga", "petra")}), 1)
		wantChain(t, w, 6)
	})
}

// Planted: a release the engine approved and could not record. Each effect
// fails in turn; no engine is set up, the store is as it was, and the same
// release from the same head passes once the host delivers.
func TestAReleaseThatCannotBeRecordedSetsUpNoEngine(t *testing.T) {
	faults := map[string]func(w *world, fault error){
		"clock":  func(w *world, fault error) { w.clockErr = fault },
		"signer": func(w *world, fault error) { w.signErr = fault },
		"sink":   func(w *world, fault error) { w.sinkErr = fault },
	}
	for name, plant := range faults {
		t.Run(name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := haltedWorld(t, mode)
				from := Continuation{Head: head(t, w), Release: by("olga")}
				plant(w, errPlanted)
				wantRefused(t, w, mode, from, ErrReleaseFailed)
				plant(w, nil)
				wantHalted(t, w, mode, HaltClockUnavailable)
				allow(t, continued(t, w, mode, Continuation{Head: head(t, w), Release: by("olga")}), 1)
				wantChain(t, w, 6)
			})
		})
	}
}

func TestAChainHaltedAsCompromisedIsNotReleased(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		compromised := rehashed(head(t, w), reasonAt, HaltLedgerCompromised)
		for _, release := range []*Release{by("olga"), by("olga", "petra", "quinn")} {
			engine, err := Continue(t.Context(), w.config(mode), Continuation{Head: compromised, Release: release})
			if !errors.Is(err, ErrCompromised) || errors.Is(err, ErrHead) || engine != nil {
				t.Fatalf("the release of a compromised chain by %+v gave the error %v", release, err)
			}
		}
		kept := continued(t, w, mode, Continuation{Head: compromised})
		for range 2 {
			want(t, decide(t, kept, routine), halted(HaltLedgerCompromised))
		}
	})
}

// Negative: a release that names no person the engine knows as one, or more
// checkers than a release has, is refused: by the loader where a name does
// not fit its bound or the checkers are too many, by the module where a name
// is no identity. The text of the error says which of the two refused.
func TestAReleaseThatNamesNoPersonIsRefused(t *testing.T) {
	const length, count, module = "outside 1 to 64", "at most 2", "status 8"
	long := strings.Repeat("p", MaxPersonBytes+1)
	plants := []struct {
		name    string
		release *Release
		refusal string
	}{
		{"no releaser", by(""), length},
		{"a releaser past the bound", by(long), length},
		{"an empty checker", by("olga", ""), length},
		{"a checker past the bound", by("olga", long), length},
		{"three checkers", by("olga", "petra", "quinn", "rosa"), count},
		{"a releaser outside the alphabet", by("bad name!"), module},
		{"a releaser that is no text", by("\xff\xfe"), module},
		{"a checker outside the alphabet", by("olga", "bad name!"), module},
		{"a second checker outside the alphabet", by("olga", "petra", "bad name!"), module},
	}
	for _, plant := range plants {
		t.Run(plant.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := haltedOver(t, mode, biometric)
				err := wantRefused(t, w, mode, Continuation{Head: head(t, w), Release: plant.release}, ErrRelease)
				if !strings.Contains(err.Error(), plant.refusal) {
					t.Fatalf("the release was refused with %v, want %q", err, plant.refusal)
				}
				wantHalted(t, w, mode, HaltClockUnavailable)
			})
		})
	}
}

// Boundary: a person is named with 1 to MaxPersonBytes bytes, and a release
// at the bound of every part is taken.
func TestAReleaseAtTheBoundOfEveryPartIsTaken(t *testing.T) {
	widest := func(first string) string { return first + strings.Repeat("p", MaxPersonBytes-1) }
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedOver(t, mode, biometric)
		release := by(widest("a"), widest("b"), widest("c"))
		encoded, err := encodeRelease(release)
		if err != nil || len(encoded) != 1+3*(1+MaxPersonBytes) {
			t.Fatalf("the widest release has %d bytes, error %v", len(encoded), err)
		}
		allow(t, continued(t, w, mode, Continuation{Head: head(t, w), Release: release}), 1)
		wantChain(t, w, 5)
	})
	if encoded, err := encodeRelease(nil); encoded != nil || err != nil {
		t.Fatalf("no release was encoded as %x, error %v", encoded, err)
	}
	if encoded, err := encodeRelease(by("olga", "petra")); err != nil || string(encoded) != "\x02\x04olga\x05petra" {
		t.Fatalf("a release was encoded as %q, error %v", encoded, err)
	}
}

// The release bytes are closed: the module refuses bytes that are no release,
// and the loader reports the refusal with its status. Nothing is written.
func TestReleaseBytesTheModuleCannotReadAreRefused(t *testing.T) {
	plants := map[string][]byte{
		"no person":                            {0},
		"a count of zero before one person":    []byte("\x00\x04olga"),
		"a count of four before three persons": []byte("\x04\x01a\x01b\x01c"),
		"four persons":                         []byte("\x04\x01a\x01b\x01c\x01d"),
		"a count beyond the persons":           []byte("\x02\x04olga"),
		"a byte behind the last name":          []byte("\x01\x04olga\x00"),
		"an empty name":                        {1, 0},
		"a name beyond the bytes":              []byte("\x01\x09olga"),
		"a name past its bound":                append([]byte{1, MaxPersonBytes + 1}, strings.Repeat("p", MaxPersonBytes+1)...),
		"more than the input buffer":           make([]byte, 4096),
	}
	for name, release := range plants {
		t.Run(name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := haltedWorld(t, mode)
				stored, err := encodeFrame(head(t, w))
				if err != nil {
					t.Fatalf("encodeFrame: %v", err)
				}
				effects := &host{clock: w, signer: w, sink: w}
				engine, err := load(t.Context(), w.config(mode), embedded, effects.functions(), &chain{head: stored, release: release})
				if !errors.Is(err, ErrRelease) || engine != nil || w.offered != 3 {
					t.Fatalf("release bytes with %s gave the error %v, %d records offered", name, err, w.offered)
				}
				if overflow := len(release) > MaxPersonBytes*4; overflow == strings.Contains(err.Error(), "status 8") {
					t.Fatalf("release bytes with %s were refused in the wrong place: %v", name, err)
				}
			})
		})
	}
}

// A set-up of either kind on an engine that is set up is refused: a running
// engine takes no other chain, and the release of a halt that a continuation
// can carry does not reach it.
func TestAnEngineThatIsSetUpTakesNoSecondSetUp(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		stored, err := encodeFrame(head(t, w))
		if err != nil {
			t.Fatalf("encodeFrame: %v", err)
		}
		olga, err := encodeRelease(by("olga"))
		if err != nil {
			t.Fatalf("encodeRelease: %v", err)
		}
		input := append(append([]byte(testKeyID), stored...), olga...)
		key, millis := uint64(len(testKeyID)), uint64(testDeadline.Milliseconds())
		engines := []*Engine{engineFor(t, newWorld(), mode), continued(t, w, mode, Continuation{Head: head(t, w)})}
		for _, engine := range engines {
			before := decide(t, engine, routine)
			release := engine.begin(t.Context(), exportContinue, input, key, uint64(len(stored)), uint64(len(olga)), millis)
			again := engine.begin(t.Context(), exportInit, []byte(testKeyID), key, millis)
			for _, err := range []error{release, again} {
				if err == nil || !strings.Contains(err.Error(), "status 1") {
					t.Fatalf("a second set-up gave the error %v", err)
				}
			}
			want(t, decide(t, engine, routine), before)
		}
		want(t, decide(t, engines[1], routine), halted(HaltClockUnavailable))
	})
}

// linked is the module instantiated and not set up, so that a test reaches
// its set-up functions with lengths the loader never sends.
func linked(t *testing.T, w *world, mode Mode) *Engine {
	t.Helper()
	settings, _, err := checked(w.config(mode))
	if err != nil {
		t.Fatalf("checked: %v", err)
	}
	effects := &host{clock: w, signer: w, sink: w}
	engine, err := link(t.Context(), mode, settings, embedded, effects.functions())
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	closeAtEnd(t, engine)
	if engine.inputAt, err = call(t.Context(), engine.instance.ExportedFunction(exportInput)); err != nil {
		t.Fatalf("the input buffer: %v", err)
	}
	if engine.inputCapacity, err = call(t.Context(), engine.instance.ExportedFunction(exportInputCapacity)); err != nil {
		t.Fatalf("the size of the input buffer: %v", err)
	}
	return engine
}

// Negative, planted: the module holds the lengths it is given to its input
// buffer by itself and does not rely on the loader for it. A head past the
// buffer is refused as a head, a release past it as a release, also where
// the sum of the lengths does not fit 32 bits. A refused set-up leaves no
// engine behind: the same instance then takes the true lengths.
func TestLengthsPastTheInputBufferAreRefusedByTheModule(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		stored, err := encodeFrame(head(t, w))
		if err != nil {
			t.Fatalf("encodeFrame: %v", err)
		}
		input := append([]byte(testKeyID), stored...)
		key, frame, millis := uint64(len(testKeyID)), uint64(len(stored)), uint64(testDeadline.Milliseconds())
		engine := linked(t, w, mode)
		room := uint64(engine.inputCapacity) - key
		plants := []struct {
			name          string
			head, release uint64
			refusal       error
			status        string
		}{
			{"a head one byte past the buffer", room + 1, 0, ErrHead, "status 5"},
			{"a head of the largest length", math.MaxUint32, 0, ErrHead, "status 5"},
			{"a release one byte past the buffer", frame, room - frame + 1, ErrRelease, "status 8"},
			{"a release of the largest length", frame, math.MaxUint32, ErrRelease, "status 8"},
		}
		for _, plant := range plants {
			err := engine.begin(t.Context(), exportContinue, input, key, plant.head, plant.release, millis)
			if !errors.Is(err, plant.refusal) || !strings.Contains(err.Error(), plant.status) || w.offered != 3 {
				t.Fatalf("%s gave the error %v, %d records offered", plant.name, err, w.offered)
			}
		}
		if err := engine.begin(t.Context(), exportContinue, input, key, frame, 0, millis); err != nil {
			t.Fatalf("the true lengths were refused after the false ones: %v", err)
		}
		want(t, decide(t, engine, routine), halted(HaltClockUnavailable))
	})
}

func TestAContinuationRefusesWhatASetUpRefuses(t *testing.T) {
	w := newWorld()
	allow(t, engineFor(t, w, Compiled), 1)
	from := Continuation{Head: head(t, w)}
	plants := map[string]func(c *Config){
		"no clock":          func(c *Config) { c.Clock = nil },
		"no signer":         func(c *Config) { c.Signer = nil },
		"no sink":           func(c *Config) { c.Sink = nil },
		"no mode":           func(c *Config) { c.Mode = modeUnset },
		"no key identifier": func(c *Config) { c.KeyID = "" },
		"no deadline":       func(c *Config) { c.SinkDeadline = 0 },
	}
	for name, plant := range plants {
		t.Run(name, func(t *testing.T) {
			config := w.config(Compiled)
			plant(&config)
			engine, err := Continue(t.Context(), config, from)
			if err == nil || engine != nil || errors.Is(err, ErrHead) {
				t.Fatalf("Continue with %s gave the error %v", name, err)
			}
		})
	}
	if w.offered != 1 {
		t.Fatal("a refused continuation reached the sink")
	}
}

func TestARecordIsEncodedAsTheFrameItWasParsedFrom(t *testing.T) {
	w := newWorld()
	allow(t, engineFor(t, w, Compiled), 1)
	record := head(t, w)
	encoded, err := encodeFrame(record)
	if err != nil || !bytes.Equal(encoded, frame(record.Preimage, record.Digest, record.KeyID, record.Signature)) {
		t.Fatalf("the record was encoded as %x, error %v", encoded, err)
	}
	parsed, err := parseFrame(encoded)
	if err != nil || !bytes.Equal(parsed.Preimage, record.Preimage) || parsed.Digest != record.Digest || parsed.KeyID != record.KeyID || !bytes.Equal(parsed.Signature, record.Signature) {
		t.Fatalf("the encoded record was read as %+v, error %v", parsed, err)
	}
}

// Boundary: every part of a record fits its length prefix or the record is
// not encoded.
func TestARecordIsEncodedUpToTheBoundsOfItsLengthPrefixes(t *testing.T) {
	bounds := []struct {
		name                     string
		preimage, key, signature int
		encoded                  bool
	}{
		{"every part at its bound", 65535, 255, 65535, true},
		{"content one byte over", 65536, 255, 65535, false},
		{"key identifier one byte over", 65535, 256, 65535, false},
		{"signature one byte over", 65535, 255, 65536, false},
		{"empty parts", 0, 0, 0, true},
	}
	for _, bound := range bounds {
		record := Record{Preimage: make([]byte, bound.preimage), KeyID: strings.Repeat("k", bound.key), Signature: make([]byte, bound.signature)}
		encoded, err := encodeFrame(record)
		length := 1 + 2 + bound.preimage + DigestBytes + 1 + bound.key + 2 + bound.signature
		if bound.encoded && (err != nil || len(encoded) != length) {
			t.Fatalf("%s: encoded %d bytes, error %v; want %d", bound.name, len(encoded), err, length)
		}
		if !bound.encoded && (!errors.Is(err, errFrame) || encoded != nil) {
			t.Fatalf("%s: encoded %d bytes, error %v", bound.name, len(encoded), err)
		}
	}
}
