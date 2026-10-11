// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testKeyID    = "host-key-01"
	testDeadline = 250 * time.Millisecond
	testStart    = int64(1_000)
	routine      = `{"schema":"amussis.decision.proposal.v1","id":"intent-0001","agent":"agent-01",` +
		`"maker":"maker-alice","action":"file-modification","target":"/srv/data/report.txt",` +
		`"declared-tier":"tier-c-routine-bounded","oversight":"standard"}`
)

var errPlanted = errors.New("planted failure")

// world is the test host: what it answers, and what it was handed.
type world struct {
	now        int64
	clockErr   error
	signature  func(digest [DigestBytes]byte) []byte
	signErr    error
	sinkErr    error
	sinkPanics bool
	stored     []Record
	offered    int
	within     []time.Duration
}

func newWorld() *world {
	return &world{now: testStart, signature: func(digest [DigestBytes]byte) []byte {
		reversed := bytes.Clone(digest[:])
		slices.Reverse(reversed)
		return reversed
	}}
}

func (w *world) Now(context.Context) (int64, error) { return w.now, w.clockErr }

func (w *world) Sign(_ context.Context, digest [DigestBytes]byte) ([]byte, error) {
	return w.signature(digest), w.signErr
}

func (w *world) Append(_ context.Context, record Record, within time.Duration) error {
	w.offered++
	w.within = append(w.within, within)
	if w.sinkPanics {
		panic("planted panic in the sink")
	}
	if w.sinkErr != nil {
		return w.sinkErr
	}
	w.stored = append(w.stored, record)
	return nil
}

func (w *world) config(mode Mode) Config {
	return Config{KeyID: testKeyID, SinkDeadline: testDeadline, Mode: mode, Clock: w, Signer: w, Sink: w}
}

// inBothModes runs a test on the compiled and on the interpreted module, so
// neither mode is trusted on the strength of the other.
func inBothModes(t *testing.T, test func(t *testing.T, mode Mode)) {
	t.Helper()
	for _, mode := range []Mode{Compiled, Interpreted} {
		t.Run(mode.String(), func(t *testing.T) { test(t, mode) })
	}
}

func engineFor(t *testing.T, w *world, mode Mode) *Engine {
	t.Helper()
	engine, err := New(t.Context(), w.config(mode))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close(context.Background()) })
	if engine.Mode() != mode {
		t.Fatalf("the engine runs %v, asked for %v", engine.Mode(), mode)
	}
	return engine
}

func decide(t *testing.T, engine *Engine, proposal string) Outcome {
	t.Helper()
	outcome, err := engine.Decide(t.Context(), []byte(proposal))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return outcome
}

func want(t *testing.T, got, expected Outcome) {
	t.Helper()
	if got != expected {
		t.Fatalf("outcome %+v, want %+v", got, expected)
	}
}

func halted(why uint8) Outcome {
	return Outcome{Class: Blocked, Detail: BlockHalted, Halt: why}
}

func TestARoutineProposalIsAllowedAndItsRecordReachesTheSink(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		outcome := decide(t, engine, routine)
		want(t, outcome, Outcome{Class: Allowed})
		if !outcome.Permits() {
			t.Fatal("an allowed action is not permitted")
		}
		if len(w.stored) != 1 || w.offered != 1 {
			t.Fatalf("stored %d of %d offered records, want 1 of 1", len(w.stored), w.offered)
		}
		record := w.stored[0]
		if sha256.Sum256(record.Preimage) != record.Digest {
			t.Fatal("the record's digest is not the SHA-256 of its pre-image")
		}
		if record.KeyID != testKeyID || !bytes.Equal(record.Signature, w.signature(record.Digest)) {
			t.Fatalf("the record carries key %q and a signature of %d bytes", record.KeyID, len(record.Signature))
		}
		if !bytes.Contains(record.Preimage, []byte("intent-0001")) || w.within[0] != testDeadline {
			t.Fatalf("the record does not name the intent, or the sink was given %v", w.within[0])
		}
	})
}

func TestTheSecondRecordCarriesTheDigestOfTheFirst(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		decide(t, engine, routine)
		decide(t, engine, routine)
		if len(w.stored) != 2 {
			t.Fatalf("stored %d records, want 2", len(w.stored))
		}
		first, second := w.stored[0], w.stored[1]
		if !bytes.Contains(second.Preimage, first.Digest[:]) || bytes.Contains(first.Preimage, first.Digest[:]) {
			t.Fatal("the second record does not chain to the first")
		}
	})
}

func TestEachTierYieldsItsClass(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		monitored := decide(t, engine, strings.Replace(routine, "tier-c-routine-bounded", "tier-b-material-reversible", 1))
		want(t, monitored, Outcome{Class: Warned, Detail: 1})
		held := decide(t, engine, strings.Replace(routine, "tier-c-routine-bounded", "tier-a-consequential", 1))
		want(t, held, Outcome{Class: RequireApproval})
		if !monitored.Permits() || held.Permits() {
			t.Fatal("a monitored action must be permitted and a held one must not")
		}
		if len(w.stored) != 2 {
			t.Fatalf("stored %d records, want 2", len(w.stored))
		}
	})
}

func TestRefusedInputReachesNoEffect(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		cases := map[string]uint8{
			"\xff\xfe\xfd":             RefusedNotUTF8,
			strings.Repeat(" ", 4097):  RefusedTooLong,
			strings.Repeat(" ", 1<<20): RefusedTooLong,
			"{":                        RefusedMalformed,
			"":                         RefusedMalformed,
			strings.Replace(routine, "proposal.v1", "proposal.v2", 1):         RefusedUnknownVersion,
			strings.Replace(routine, "file-modification", "file-deletion", 1): RefusedIntent,
		}
		for proposal, why := range cases {
			outcome := decide(t, engine, proposal)
			want(t, outcome, Outcome{Class: Refused, Detail: why})
			if outcome.Permits() {
				t.Fatal("a refused proposal is permitted")
			}
		}
		if w.offered != 0 {
			t.Fatalf("a refused proposal reached the sink %d times", w.offered)
		}
		// A refusal is not a halt: the next good proposal is decided.
		want(t, decide(t, engine, routine), Outcome{Class: Allowed})
	})
}

// The three planted cases of the host side: each effect fails in every way
// its interface allows. Each time the decision is blocked, no record of a
// permitted action is stored, and the engine stays halted once the effect
// works again. The engine writes a record of its own block where the signer
// and the sink still work: that is the one record a failed clock leaves. A
// failed sink is offered two records, the one of the decision and the one of
// the halt that follows, and stores neither.
func TestAnEffectThatCannotDeliverBlocksAndTheEngineStaysHalted(t *testing.T) {
	long := make([]byte, MaxSignatureBytes+1)
	clock := Outcome{Class: Blocked, Detail: BlockClockUnavailable}
	audit := Outcome{Class: Blocked, Detail: BlockAuditUnavailable}
	plants := []struct {
		name            string
		plant           func(w *world)
		first, later    Outcome
		stored, offered int
	}{
		{"clock returns an error", func(w *world) { w.clockErr = errPlanted }, clock, halted(HaltClockUnavailable), 1, 1},
		{"clock is before the epoch", func(w *world) { w.now = -5 }, clock, halted(HaltClockUnavailable), 1, 1},
		{"signer returns an error beside a signature", func(w *world) { w.signErr = errPlanted }, audit, halted(HaltAuditUnavailable), 0, 0},
		{"signer returns nothing", func(w *world) { w.signature = func([DigestBytes]byte) []byte { return nil } }, audit, halted(HaltAuditUnavailable), 0, 0},
		{"signer returns too much", func(w *world) { w.signature = func([DigestBytes]byte) []byte { return long } }, audit, halted(HaltAuditUnavailable), 0, 0},
		{"sink returns an error", func(w *world) { w.sinkErr = errPlanted }, audit, halted(HaltAuditUnavailable), 0, 2},
	}
	for _, plant := range plants {
		t.Run(plant.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				w := newWorld()
				engine := engineFor(t, w, mode)
				plant.plant(w)
				first := decide(t, engine, routine)
				want(t, first, plant.first)
				if first.Permits() {
					t.Fatal("a blocked action is permitted")
				}
				if len(w.stored) != plant.stored || w.offered != plant.offered {
					t.Fatalf("stored %d of %d offered records, want %d of %d", len(w.stored), w.offered, plant.stored, plant.offered)
				}
				*w = *newWorld()
				for range 3 {
					want(t, decide(t, engine, routine), plant.later)
				}
			})
		})
	}
}

func TestAClockThatStepsBackBlocks(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		want(t, decide(t, engine, routine), Outcome{Class: Allowed})
		w.now = testStart - 1
		want(t, decide(t, engine, routine), Outcome{Class: Blocked, Detail: BlockClockUnavailable})
		w.now = testStart + 1
		want(t, decide(t, engine, routine), halted(HaltClockUnavailable))
	})
}

func TestASignatureIsStoredAtTheLengthTheSignerGave(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		for _, length := range []int{1, 3, MaxSignatureBytes} {
			w := newWorld()
			w.signature = func([DigestBytes]byte) []byte { return bytes.Repeat([]byte{0xa5}, length) }
			engine := engineFor(t, w, mode)
			want(t, decide(t, engine, routine), Outcome{Class: Allowed})
			if len(w.stored) != 1 || len(w.stored[0].Signature) != length {
				t.Fatalf("a signature of %d bytes was not stored at that length", length)
			}
		}
	})
}

// A sink that panics leaves the module in a state nobody checked. The
// decision is blocked, the caller gets the error, and the engine is not asked
// again.
func TestASinkThatPanicsBlocksAndPoisonsTheEngine(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		engine := engineFor(t, w, mode)
		w.sinkPanics = true
		outcome, err := engine.Decide(t.Context(), []byte(routine))
		if err == nil || outcome != loaderFault || outcome.Permits() {
			t.Fatalf("a panicking sink gave %+v and the error %v", outcome, err)
		}
		w.sinkPanics = false
		outcome, later := engine.Decide(t.Context(), []byte(routine))
		if later == nil || outcome != loaderFault || w.offered != 1 || len(w.stored) != 0 {
			t.Fatalf("after the fault: %+v, error %v, offered %d, stored %d", outcome, later, w.offered, len(w.stored))
		}
	})
}

func TestAMissingEffectIsRefusedAndHasNoDefault(t *testing.T) {
	w := newWorld()
	plants := map[string]func(c *Config){
		"no clock":                       func(c *Config) { c.Clock = nil },
		"no signer":                      func(c *Config) { c.Signer = nil },
		"no sink":                        func(c *Config) { c.Sink = nil },
		"no mode":                        func(c *Config) { c.Mode = modeUnset },
		"unknown mode":                   func(c *Config) { c.Mode = 9 },
		"no key identifier":              func(c *Config) { c.KeyID = "" },
		"long key identifier":            func(c *Config) { c.KeyID = strings.Repeat("k", MaxKeyIDBytes+1) },
		"bad key identifier":             func(c *Config) { c.KeyID = "key\x00id" },
		"no deadline":                    func(c *Config) { c.SinkDeadline = 0 },
		"negative deadline":              func(c *Config) { c.SinkDeadline = -time.Second },
		"deadline below one millisecond": func(c *Config) { c.SinkDeadline = 999 * time.Microsecond },
		"deadline beyond the interface":  func(c *Config) { c.SinkDeadline = (1 << 32) * time.Millisecond },
	}
	for name, plant := range plants {
		t.Run(name, func(t *testing.T) {
			config := w.config(Compiled)
			plant(&config)
			engine, err := New(t.Context(), config)
			if err == nil || engine != nil {
				t.Fatalf("New accepted a configuration with %s", name)
			}
		})
	}
	if w.offered != 0 {
		t.Fatal("a refused configuration reached the sink")
	}
}

// The planted case of the module side: the module imports a host function the
// host does not hold. Loading must fail; no stand-in may be linked.
func TestAHostFunctionTheHostDoesNotHoldFailsTheLoad(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		for _, withheld := range []string{"clock_now", "signer_sign", "sink_append"} {
			w := newWorld()
			effects := &host{clock: w, signer: w, sink: w}
			functions := slices.DeleteFunc(effects.functions(), func(f hostFunction) bool { return f.name == withheld })
			if len(functions) != 2 {
				t.Fatalf("withholding %s left %d host functions", withheld, len(functions))
			}
			engine, err := load(t.Context(), w.config(mode), embedded, functions, nil)
			if err == nil || engine != nil || !strings.Contains(err.Error(), withheld) {
				t.Fatalf("a host without %s loaded the module: %v", withheld, err)
			}
		}
	})
}

func TestAClosedEngineBlocks(t *testing.T) {
	w := newWorld()
	engine := engineFor(t, w, Interpreted)
	if err := engine.Close(t.Context()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	outcome, err := engine.Decide(t.Context(), []byte(routine))
	if !errors.Is(err, errClosed) || outcome != loaderFault {
		t.Fatalf("a closed engine gave %+v and the error %v", outcome, err)
	}
}

func TestTwoEnginesKeepSeparateChains(t *testing.T) {
	first, second := newWorld(), newWorld()
	one, two := engineFor(t, first, Compiled), engineFor(t, second, Compiled)
	decide(t, one, routine)
	decide(t, one, routine)
	decide(t, two, routine)
	if len(first.stored) != 2 || len(second.stored) != 1 {
		t.Fatalf("stored %d and %d records, want 2 and 1", len(first.stored), len(second.stored))
	}
}

func TestTheZeroOutcomePermitsNothing(t *testing.T) {
	var zero Outcome
	if zero.Class != Blocked || zero.Permits() || loaderFault.Permits() {
		t.Fatal("the zero outcome or the loader fault permits an action")
	}
	for class := Blocked; class <= NotAdjudicated+1; class++ {
		permits := Outcome{Class: class}.Permits()
		if permits != (class == Allowed || class == Warned) {
			t.Fatalf("class %d permits: %v", class, permits)
		}
	}
}
