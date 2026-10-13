// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Value types of the WebAssembly binary format.
const (
	i32 = 0x7f
	i64 = 0x7e
)

// shape describes a small module, assembled by hand so that a test can give
// the loader a surface the real module does not have.
type shape struct {
	imports        []shapeImport
	exports        []shapeFunction
	memoryName     string
	importedMemory bool
}

type shapeImport struct {
	module, name    string
	params, results []byte
}

// shapeFunction is an exported function that ignores its parameters and
// returns one constant, or traps when it is called.
type shapeFunction struct {
	name    string
	params  []byte
	results []byte
	value   int64
	traps   bool
}

// realSurface is the surface of the real module, over functions that answer:
// the loader's interface version, a 4,096-byte input buffer at address 16, two
// set-ups that succeed, a decision that allows, an adjudication that approves
// and a halt that is recorded.
func realSurface() shape {
	return shape{
		imports: []shapeImport{
			{hostModule, "clock_now", nil, []byte{i64}},
			{hostModule, "signer_sign", []byte{i32, i32, i32}, []byte{i32}},
			{hostModule, "sink_append", []byte{i32, i32, i32}, []byte{i32}},
		},
		exports: []shapeFunction{
			{exportABIVersion, nil, []byte{i32}, abiVersion, false},
			{exportInput, nil, []byte{i32}, 16, false},
			{exportInputCapacity, nil, []byte{i32}, 4096, false},
			{exportInit, []byte{i32, i32}, []byte{i32}, 0, false},
			{exportContinue, []byte{i32, i32, i32, i32}, []byte{i32}, 0, false},
			{exportDecide, []byte{i32}, []byte{i32}, 0, false},
			{exportAdjudicate, []byte{i32}, []byte{i32}, 0, false},
			{exportHalt, []byte{i32, i32}, []byte{i32}, 0, false},
		},
		memoryName: exportMemory,
	}
}

// without removes the exports of the given names.
func (s *shape) without(names ...string) {
	s.exports = slices.DeleteFunc(s.exports, func(f shapeFunction) bool { return slices.Contains(names, f.name) })
}

func (s *shape) export(name string) *shapeFunction {
	for index := range s.exports {
		if s.exports[index].name == name {
			return &s.exports[index]
		}
	}
	panic("the shape has no export " + name)
}

// groups is the most seven-bit groups a 64-bit number is written in.
const groups = 10

func uleb(value uint64) []byte {
	var out []byte
	for range groups {
		low := byte(value & 0x7f)
		value >>= 7
		if value == 0 {
			return append(out, low)
		}
		out = append(out, low|0x80)
	}
	panic("a 64-bit number does not end within ten groups")
}

func sleb(value int64) []byte {
	var out []byte
	for range groups {
		low := byte(value & 0x7f)
		value >>= 7
		if (value == 0 && low&0x40 == 0) || (value == -1 && low&0x40 != 0) {
			return append(out, low)
		}
		out = append(out, low|0x80)
	}
	panic("a 64-bit number does not end within ten groups")
}

func vector(items ...[]byte) []byte {
	return append(uleb(uint64(len(items))), bytes.Join(items, nil)...)
}

func sized(content []byte) []byte {
	return append(uleb(uint64(len(content))), content...)
}

func section(id byte, content []byte) []byte {
	return append([]byte{id}, sized(content)...)
}

// assemble writes the module in the WebAssembly binary format.
func (s shape) assemble() []byte {
	var types, imports, functions, exports, bodies [][]byte
	functionType := func(params, results []byte) []byte {
		types = append(types, bytes.Join([][]byte{{0x60}, sized(params), sized(results)}, nil))
		return uleb(uint64(len(types) - 1))
	}
	for _, imported := range s.imports {
		entry := [][]byte{sized([]byte(imported.module)), sized([]byte(imported.name)), {0x00}, functionType(imported.params, imported.results)}
		imports = append(imports, bytes.Join(entry, nil))
	}
	if s.importedMemory {
		imports = append(imports, bytes.Join([][]byte{sized([]byte(hostModule)), sized([]byte("memory")), {0x02, 0x00, 0x01}}, nil))
	}
	for index, exported := range s.exports {
		functions = append(functions, functionType(exported.params, exported.results))
		entry := [][]byte{sized([]byte(exported.name)), {0x00}, uleb(uint64(len(s.imports) + index))}
		exports = append(exports, bytes.Join(entry, nil))
		constant := byte(0x41)
		if bytes.Equal(exported.results, []byte{i64}) {
			constant = 0x42
		}
		body := bytes.Join([][]byte{{0x00, constant}, sleb(exported.value), {0x0b}}, nil)
		if exported.traps {
			// No locals, unreachable, end.
			body = []byte{0x00, 0x00, 0x0b}
		}
		bodies = append(bodies, sized(body))
	}
	if s.memoryName != "" {
		exports = append(exports, bytes.Join([][]byte{sized([]byte(s.memoryName)), {0x02, 0x00}}, nil))
	}
	module := [][]byte{[]byte("\x00asm\x01\x00\x00\x00"), section(1, vector(types...)), section(2, vector(imports...)), section(3, vector(functions...))}
	if !s.importedMemory {
		module = append(module, section(5, vector([]byte{0x00, 0x01})))
	}
	module = append(module, section(7, vector(exports...)), section(10, vector(bodies...)))
	return bytes.Join(module, nil)
}

func loadShape(t *testing.T, s shape, mode Mode) (*Engine, error) {
	t.Helper()
	w := newWorld()
	effects := &host{clock: w, signer: w, sink: w}
	engine, err := load(t.Context(), w.config(mode), s.assemble(), effects.functions(), nil)
	if engine != nil {
		closeAtEnd(t, engine)
	}
	return engine, err
}

// The control of the plants below: the hand-assembled module with the real
// surface loads and answers. Without it, every plant could be refused merely
// for being assembled wrongly.
func TestTheAssembledModuleWithTheRealSurfaceLoads(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		engine, err := loadShape(t, realSurface(), mode)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		want(t, decide(t, engine, routine), Outcome{Class: Allowed})
	})
}

func TestAModuleWithAnotherSurfaceIsRefused(t *testing.T) {
	plants := []struct {
		name     string
		plant    func(s *shape)
		expected string
	}{
		{"a fourth host function", func(s *shape) {
			s.imports = append(s.imports, shapeImport{hostModule, "net_send", []byte{i32, i32}, []byte{i32}})
		}, "no host effect"},
		{"a host function of another module", func(s *shape) { s.imports[0].module = "env" }, "no host effect"},
		{"a system interface import", func(s *shape) {
			s.imports = append(s.imports, shapeImport{"wasi_snapshot_preview1", "fd_write", []byte{i32, i32, i32, i32}, []byte{i32}})
		}, "no host effect"},
		{"a clock of another type", func(s *shape) { s.imports[0].results = []byte{i32} }, "another type"},
		{"a signer with one parameter less", func(s *shape) { s.imports[1].params = []byte{i32, i32} }, "another type"},
		{"a host function imported twice", func(s *shape) { s.imports = append(s.imports, s.imports[2]) }, "twice"},
		{"no sink import", func(s *shape) { s.imports = s.imports[:2] }, "imports 2 of the 3"},
		{"no import at all", func(s *shape) { s.imports = nil }, "imports 0 of the 3"},
		{"an imported memory", func(s *shape) { s.importedMemory = true }, "must own its memory"},
		{"an export beyond the interface", func(s *shape) {
			s.exports = append(s.exports, shapeFunction{"amussis_extra", nil, []byte{i32}, 0, false})
		}, "no function of this interface"},
		{"no decide function", func(s *shape) { s.without(exportDecide) }, "exports 7 of the 8"},
		{"no continue function", func(s *shape) { s.without(exportContinue) }, "exports 7 of the 8"},
		{"no adjudicate function", func(s *shape) { s.without(exportAdjudicate) }, "exports 7 of the 8"},
		{"no halt function", func(s *shape) { s.without(exportHalt) }, "exports 7 of the 8"},
		{"the exports of interface version 3, which can neither adjudicate nor halt", func(s *shape) {
			s.without(exportAdjudicate, exportHalt)
		}, "exports 6 of the 8"},
		{"an adjudicate function of another type", func(s *shape) { s.export(exportAdjudicate).params = []byte{i32, i32} }, "another type"},
		{"a halt function without its level", func(s *shape) { s.export(exportHalt).params = nil }, "another type"},
		{"the halt function of interface version 5, which takes no person", func(s *shape) { s.export(exportHalt).params = []byte{i32} }, "another type"},
		{"a halt function with a wide result", func(s *shape) { s.export(exportHalt).results = []byte{i64} }, "another type"},
		{"a continue function without the length of its release", func(s *shape) { s.export(exportContinue).params = []byte{i32, i32, i32} }, "another type"},
		{"a decide function of another type", func(s *shape) { s.export(exportDecide).params = []byte{i32, i32} }, "another type"},
		{"a decide function with a wide result", func(s *shape) { s.export(exportDecide).results = []byte{i64} }, "another type"},
		{"no exported memory", func(s *shape) { s.memoryName = "" }, "exactly one memory"},
		{"a memory under another name", func(s *shape) { s.memoryName = "mem" }, "exactly one memory"},
		{"the interface version before this one", func(s *shape) { s.export(exportABIVersion).value = 5 }, "interface version 5"},
		{"the interface version after this one", func(s *shape) { s.export(exportABIVersion).value = 7 }, "interface version 7"},
		{"interface version zero", func(s *shape) { s.export(exportABIVersion).value = 0 }, "interface version 0"},
		{"an input buffer past the memory", func(s *shape) { s.export(exportInput).value = 65536 - 100 }, "not in its memory"},
		{"an input buffer at the highest address", func(s *shape) { s.export(exportInput).value = -1 }, "not in its memory"},
		{"an input buffer too short for a key", func(s *shape) { s.export(exportInputCapacity).value = 8 }, "not in its memory"},
		{"a refused set-up", func(s *shape) { s.export(exportInit).value = 2 }, "status 2"},
	}
	for _, plant := range plants {
		t.Run(plant.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				s := realSurface()
				plant.plant(&s)
				engine, err := loadShape(t, s, mode)
				if err == nil || engine != nil {
					t.Fatalf("a module with %s was loaded", plant.name)
				}
				if !strings.Contains(err.Error(), plant.expected) {
					t.Fatalf("refused for another reason: %v", err)
				}
			})
		})
	}
}

func TestBytesThatAreNoModuleAreRefused(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		w := newWorld()
		effects := &host{clock: w, signer: w, sink: w}
		for _, module := range [][]byte{nil, []byte("\x7fELF"), embedded[:len(embedded)/2]} {
			engine, err := load(t.Context(), w.config(mode), module, effects.functions(), nil)
			if err == nil || engine != nil || !strings.Contains(err.Error(), "does not compile") {
				t.Fatalf("%d bytes that are no module: %v", len(module), err)
			}
		}
	})
}

// An answer the module cannot have written blocks, and the engine is not
// asked again.
func TestAnAnswerTheModuleDoesNotWriteBlocksAndPoisons(t *testing.T) {
	inBothModes(t, func(t *testing.T, mode Mode) {
		s := realSurface()
		s.export(exportDecide).value = 9
		engine, err := loadShape(t, s, mode)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		for range 2 {
			outcome, err := engine.Decide(t.Context(), []byte(routine))
			if err == nil || outcome != loaderFault || outcome.Permits() {
				t.Fatalf("answer 9 gave %+v and the error %v", outcome, err)
			}
		}
	})
}

// trapped fails the test unless err is the trap of the module's code in the
// function exported as export, so a test of a trap cannot pass on a fault of
// another kind.
func trapped(t *testing.T, err error, export string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "unreachable") || !strings.Contains(err.Error(), export+" failed") {
		t.Fatalf("the error is not the trap of %s: %v", export, err)
	}
}

// askAfterTrap is one way to ask an engine. Halt answers no outcome; it is
// given the blocked outcome so that only its error is compared.
type askAfterTrap struct {
	name, export string
	ask          func(t *testing.T, engine *Engine) (Outcome, error)
}

var asksAfterTrap = []askAfterTrap{
	{"decide", exportDecide, func(t *testing.T, engine *Engine) (Outcome, error) {
		return engine.Decide(t.Context(), []byte(routine))
	}},
	{"adjudicate", exportAdjudicate, func(t *testing.T, engine *Engine) (Outcome, error) {
		return engine.Adjudicate(t.Context(), vote(Approve, "carol"))
	}},
	{"halt", exportHalt, func(t *testing.T, engine *Engine) (Outcome, error) {
		return loaderFault, engine.Halt(t.Context(), "operator-7", LevelConsequential)
	}},
}

// A module that traps blocks the call that met the trap with the trap as its
// error, and every call after it answers blocked with that same error: the
// module is in a state nobody checked and is not asked again.
func TestATrapBlocksAndTheEngineAnswersBlockedFromThenOn(t *testing.T) {
	for _, trap := range asksAfterTrap {
		t.Run(trap.name, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				s := realSurface()
				s.export(trap.export).traps = true
				engine, err := loadShape(t, s, mode)
				if err != nil {
					t.Fatalf("load: %v", err)
				}
				outcome, fault := trap.ask(t, engine)
				trapped(t, fault, trap.export)
				if outcome != loaderFault || outcome.Permits() {
					t.Fatalf("the trap gave %+v", outcome)
				}
				for _, then := range asksAfterTrap {
					outcome, err := then.ask(t, engine)
					if outcome != loaderFault || !errors.Is(err, fault) {
						t.Fatalf("%s after the trap gave %+v and the error %v", then.name, outcome, err)
					}
				}
			})
		})
	}
}

// Boundary: a module that traps while it is set up gives no engine.
func TestATrapWhileSettingUpGivesNoEngine(t *testing.T) {
	for _, export := range []string{exportABIVersion, exportInput, exportInit, exportContinue} {
		t.Run(export, func(t *testing.T) {
			inBothModes(t, func(t *testing.T, mode Mode) {
				s := realSurface()
				s.export(export).traps = true
				w := newWorld()
				effects := &host{clock: w, signer: w, sink: w}
				var from *chain
				if export == exportContinue {
					from = &chain{head: []byte{frameVersion}}
				}
				engine, err := load(t.Context(), w.config(mode), s.assemble(), effects.functions(), from)
				if engine != nil {
					closeAtEnd(t, engine)
					t.Fatal("a module that trapped while it was set up gave an engine")
				}
				trapped(t, err, export)
			})
		})
	}
}

func TestOnlyTheCodesTheModuleWritesAreRead(t *testing.T) {
	read := map[uint32]Outcome{
		0x000000: {Class: Allowed},
		0x000101: {Class: Warned, Detail: 1},
		0x000002: {Class: RequireApproval},
		0x000203: {Class: Blocked, Detail: BlockAuditUnavailable},
		0x040103: halted(HaltClockUnavailable),
		0x000504: {Class: Refused, Detail: RefusedMalformed},
	}
	for code, expected := range read {
		outcome, err := decode(code)
		if err != nil || outcome != expected {
			t.Fatalf("code %#x read as %+v, error %v", code, outcome, err)
		}
	}
	refused := []uint32{
		0x000100,   // allow with a detail
		0x010000,   // allow with a halt
		0x01000000, // allow with the reserved byte
		0x000001,   // warning without its tag
		0x010101,   // warning with a halt
		0x000102,   // held with a detail
		0x010002,   // held with a halt
		0x000003,   // block without a reason
		0x00ff03,   // block with the loader's own reason
		0x000004,   // refusal without a reason
		0x010104,   // refusal with a halt
		0x000005,   // the rejection of an adjudication
		0x000206,   // an adjudication that was not taken
		0x000007,   // a class past the last
		0x0000ff,
		0xffffffff,
	}
	for _, code := range refused {
		if outcome, err := decode(code); err == nil || outcome != (Outcome{}) || outcome.Permits() {
			t.Fatalf("code %#x was read as %+v", code, outcome)
		}
	}
}

func frame(preimage []byte, digest [DigestBytes]byte, keyID string, signature []byte) []byte {
	out := []byte{frameVersion}
	out = binary.LittleEndian.AppendUint16(out, uint16(len(preimage)))
	out = append(append(out, preimage...), digest[:]...)
	out = append(append(out, byte(len(keyID))), keyID...)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(signature)))
	return append(out, signature...)
}

func TestAFrameIsReadOnlyWhenItsDigestCoversItsPreimage(t *testing.T) {
	preimage, signature := []byte("the canonical record"), []byte{1, 2, 3}
	digest := sha256.Sum256(preimage)
	good := frame(preimage, digest, testKeyID, signature)
	record, err := parseFrame(good)
	if err != nil || !bytes.Equal(record.Preimage, preimage) || record.Digest != digest || record.KeyID != testKeyID || !bytes.Equal(record.Signature, signature) {
		t.Fatalf("the good frame was read as %+v, error %v", record, err)
	}
	flipped := bytes.Clone(good)
	flipped[4] ^= 1
	otherDigest := digest
	otherDigest[0] ^= 1
	version := bytes.Clone(good)
	version[0] = frameVersion + 1
	plants := map[string][]byte{
		"empty":                             nil,
		"another version":                   version,
		"one bit of the pre-image":          flipped,
		"one bit of the digest":             frame(preimage, otherDigest, testKeyID, signature),
		"cut short":                         good[:len(good)-1],
		"cut inside the digest":             good[:len(preimage)+10],
		"one byte after the signature":      append(bytes.Clone(good), 0),
		"no key identifier":                 frame(preimage, digest, "", signature),
		"no signature":                      frame(preimage, digest, testKeyID, nil),
		"a pre-image length past the frame": {frameVersion, 0xff, 0xff, 1, 2, 3},
	}
	for name, planted := range plants {
		if record, err := parseFrame(planted); err == nil {
			t.Fatalf("a frame with %s was read as %+v", name, record)
		}
	}
}
