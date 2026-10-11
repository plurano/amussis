// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Where a walk over stored records reads the content of a record: the
// sequence number, the digest of the record before, the halt flag and the
// halt reason.
const (
	sequenceAt = 50
	previousAt = 58
	latchAt    = 102
	reasonAt   = 111
)

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
	engine, err := Continue(t.Context(), w.config(mode), from)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close(context.Background()) })
	return engine
}

// haltedWorld is a world whose chain ends with the record of a decision
// blocked for want of a clock: two allowed records, then the halted one.
func haltedWorld(t *testing.T, mode Mode) *world {
	t.Helper()
	w := newWorld()
	engine := engineFor(t, w, mode)
	allow(t, engine, 2)
	w.clockErr = errPlanted
	want(t, decide(t, engine, routine), Outcome{Class: Blocked, Detail: BlockClockUnavailable})
	w.clockErr = nil
	if last := head(t, w); len(w.stored) != 3 || last.Preimage[latchAt] != 1 || last.Preimage[reasonAt] != HaltClockUnavailable {
		t.Fatalf("the chain does not end with a halted record: %d records", len(w.stored))
	}
	return w
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
		third := continued(t, w, mode, Continuation{Head: head(t, w), ReleaseHalt: true})
		allow(t, third, 1)
		wantChain(t, w, 6)
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
				for _, release := range []bool{false, true} {
					engine, err := Continue(t.Context(), w.config(mode), Continuation{Head: record, ReleaseHalt: release})
					if !errors.Is(err, ErrHead) || engine != nil || !strings.Contains(err.Error(), plant.refusal) {
						t.Fatalf("release %v: a head with %s gave the error %v", release, plant.name, err)
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

func TestAHaltedChainGoesOnOnlyThroughTheNamedRelease(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		engine := continued(t, w, mode, Continuation{Head: head(t, w), ReleaseHalt: true})
		allow(t, engine, 2)
		wantChain(t, w, 5)
		if w.stored[2].Preimage[latchAt] != 1 || w.stored[3].Preimage[latchAt] != 0 {
			t.Fatal("the chain does not show the release as the step from a halted record to one that is not")
		}
	})
}

func TestAChainHaltedAsCompromisedIsNotReleased(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		compromised := rehashed(head(t, w), reasonAt, HaltLedgerCompromised)
		engine, err := Continue(t.Context(), w.config(mode), Continuation{Head: compromised, ReleaseHalt: true})
		if !errors.Is(err, ErrCompromised) || errors.Is(err, ErrHead) || engine != nil {
			t.Fatalf("the release of a compromised chain gave the error %v", err)
		}
		kept := continued(t, w, mode, Continuation{Head: compromised})
		for range 2 {
			want(t, decide(t, kept, routine), halted(HaltLedgerCompromised))
		}
	})
}

// The latch flag is closed: the module refuses a value it does not know, and
// the loader reports the refusal with its status.
func TestALatchFlagTheModuleDoesNotKnowIsRefused(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := haltedWorld(t, mode)
		stored, err := encodeFrame(head(t, w))
		if err != nil {
			t.Fatalf("encodeFrame: %v", err)
		}
		for _, flag := range []uint32{2, 255, 1 << 31} {
			effects := &host{clock: w, signer: w, sink: w}
			engine, err := load(t.Context(), w.config(mode), embedded, effects.functions(), &chain{head: stored, latch: flag})
			if err == nil || engine != nil || !strings.Contains(err.Error(), "status 8") {
				t.Fatalf("the latch flag %d gave the error %v", flag, err)
			}
		}
	})
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
		input := append([]byte(testKeyID), stored...)
		key, millis := uint64(len(testKeyID)), uint64(testDeadline.Milliseconds())
		engines := []*Engine{engineFor(t, newWorld(), mode), continued(t, w, mode, Continuation{Head: head(t, w)})}
		for _, engine := range engines {
			before := decide(t, engine, routine)
			release := engine.begin(t.Context(), exportContinue, input, key, uint64(len(stored)), millis, latchRelease)
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
