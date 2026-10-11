// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

// Package decision runs the amussis decision engine from Go.
//
// The engine is the WebAssembly module of crates/amussis-decision-wasm,
// embedded in this package and run in the process by wazero: no cgo, no
// shared library, no Rust toolchain. The module has no access to the
// operating system. What it needs from outside it asks of three host
// effects the caller supplies: a Clock, a Signer and a Sink.
//
// The package fails closed. An effect that is missing is refused at New; an
// effect that cannot deliver blocks the decision and halts the engine; a
// module that cannot be run or whose answer cannot be read yields Blocked and
// an error, and the Engine answers Blocked from then on. No path puts a
// default in the place of an effect.
//
// The audit chain lives in the Sink and has no bound of its own. New starts a
// chain. A program that starts again does not start a second one: Continue
// takes the last record the Sink stored and links the next record onto it. A
// chain that ends halted continues halted; a restart is no release.
//
// A halt stands at a risk level, and its one release is part of a
// continuation: Continuation.Release names the person who releases it and the
// checkers that level demands of an action. The release is a record of its
// own in the chain. That record names no person; a host that has to show who
// released a halt keeps that itself.
//
// An action the engine holds (RequireApproval) is decided with Adjudicate. It
// is named by the id of its proposal, and the engine holds the checkers the
// caller names to the approval rule of the action. Who may approve is the
// caller's decision; the record of the vote names no checker.
//
// Halt stops a running engine as an operator stop at a risk level. No call
// lifts that halt on the engine it was set on: the chain is continued with a
// Release.
package decision

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// The module tools/wasm_module.py builds from the crate and holds to the
// source byte for byte.
//
//go:embed amussis_decision.wasm
var embedded []byte

// Mode names how the module's code is executed. The caller names it; the
// package never chooses one for the caller, and never falls back from one to
// the other.
type Mode uint8

const (
	modeUnset Mode = iota
	// Compiled translates the module to machine code at load. It needs
	// amd64 or arm64 on an operating system wazero compiles for; New
	// returns an error elsewhere.
	Compiled
	// Interpreted runs on every platform Go does, about ninety times slower
	// per decision as measured on amd64.
	Interpreted
)

func (m Mode) String() string {
	switch m {
	case Compiled:
		return "compiled"
	case Interpreted:
		return "interpreted"
	default:
		return "unset"
	}
}

// Config is what an Engine needs. Every field is required.
type Config struct {
	// KeyID names the key the Signer signs with, 1 to MaxKeyIDBytes bytes.
	// It is written into every record.
	KeyID string
	// SinkDeadline is the time the Sink is given per record, at least one
	// millisecond; a fraction of a millisecond is dropped.
	SinkDeadline time.Duration
	// Mode is Compiled or Interpreted.
	Mode Mode
	// Clock, Signer and Sink are the host effects. A nil one is refused.
	Clock  Clock
	Signer Signer
	Sink   Sink
}

// Continuation names the stored chain an Engine continues.
type Continuation struct {
	// Head is the last record the Sink stored for the chain, as the Sink
	// received it. The module checks that its content hashes to its digest
	// and reads the chain position and the halt state out of that content.
	// It does not verify the signature, and it cannot know whether the
	// record is the last one stored: both are the caller's statement. A
	// continuation from any other record leaves two records with one
	// sequence number in the store, which a walk over the store shows.
	Head Record
	// Release continues a chain that ends halted with the halt lifted. It is
	// the only release of a halt this package has. Left nil, a chain that
	// ends halted continues halted and every decision is Blocked.
	Release *Release
}

// Release names the persons who lift a halt. The engine holds it to the
// approval rule it holds an action of the halt's risk level to, with the
// releaser in the place of the maker: no checker for the lowest level, one
// checker or two distinct ones above it, none of them the releaser. The
// level is the one the head record states.
type Release struct {
	// Releaser is the person who releases the halt, 1 to MaxPersonBytes
	// bytes of the engine's identity alphabet.
	Releaser string
	// Checkers are the persons who approve the release, at most
	// MaxCheckers, each written as the releaser is.
	Checkers []string
}

const (
	// MaxPersonBytes is the longest name of a person in a Release or an
	// Adjudication, and the longest intent id an Adjudication names.
	MaxPersonBytes = 64
	// MaxCheckers is the largest number of checkers a Release or an
	// Adjudication names.
	MaxCheckers = 2
)

// Errors of Continue; test for them with errors.Is.
var (
	// ErrHead: the head record is not a record of the chain format, or its
	// content does not hash to its digest.
	ErrHead = errors.New("decision: the head record is refused")
	// ErrCompromised: the chain ends halted as compromised. Its halt is not
	// released; without a Release it continues halted.
	ErrCompromised = errors.New("decision: a chain halted as compromised is not released")
	// ErrRelease: the Release cannot be read: a person that is no identity
	// of the engine, or more checkers than MaxCheckers.
	ErrRelease = errors.New("decision: the release is refused")
	// ErrNotHalted: a Release was given for a chain that does not end
	// halted.
	ErrNotHalted = errors.New("decision: a chain that is not halted is not released")
	// ErrApproval: the Release lacks the approval the risk level of the halt
	// demands: a checker is missing, is named twice or is the releaser.
	ErrApproval = errors.New("decision: the release lacks the approval its risk level demands")
	// ErrReleaseFailed: the release was approved and its record could not be
	// written: the clock, the signer or the sink did not deliver. The chain
	// is as it was and still ends halted.
	ErrReleaseFailed = errors.New("decision: the release could not be recorded")
)

// Vote is the checkers' decision of a held action. The zero value is no vote
// and is refused.
type Vote uint8

const (
	voteUnset Vote = iota
	// Approve: the held action may run.
	Approve
	// Reject: the held action must not run.
	Reject
)

// Adjudication is the checkers' decision of one held action.
type Adjudication struct {
	// IntentID names the held action: the "id" of the proposal Decide
	// answered with RequireApproval.
	IntentID string
	// Vote is Approve or Reject.
	Vote Vote
	// Checkers are the persons who decide, one or two, each 1 to
	// MaxPersonBytes bytes of the engine's identity alphabet. The engine
	// holds them to the approval rule of the action: one checker, or two
	// distinct ones for an action under Annex III oversight, none of them
	// the maker of the proposal.
	Checkers []string
}

// Level is a risk level a halt stands at; its release is held to the
// approval rule of an action of that level. The zero value names no level,
// and a halt at no level stands at the highest.
type Level uint8

const (
	// LevelRoutine: a routine action under standard oversight.
	LevelRoutine Level = 1
	// LevelMaterial: a material action under standard oversight.
	LevelMaterial Level = 2
	// LevelConsequential: a consequential action under standard oversight.
	LevelConsequential Level = 3
	// LevelAnnexIIIRoutine: a routine action under Annex III oversight.
	LevelAnnexIIIRoutine Level = 4
	// LevelAnnexIIIMaterial: a material action under Annex III oversight.
	LevelAnnexIIIMaterial Level = 5
	// LevelAnnexIIIConsequential: a consequential action under Annex III
	// oversight, the highest level.
	LevelAnnexIIIConsequential Level = 6
)

// ErrHaltUnrecorded: the engine is halted, and the record of the halt could
// not be signed or stored. The stored chain does not show the halt until the
// engine writes its next record. Test for it with errors.Is.
var ErrHaltUnrecorded = errors.New("decision: the engine is halted and the halt could not be recorded")

// The halt statuses of the module's interface.
const (
	haltRecorded   = 0
	haltUnrecorded = 3
)

// encodeAdjudication writes an Adjudication as the module reads it: the vote,
// the intent id as a length byte and its text, the number of checkers, then
// each checker as the intent id is written. What the vote and a name may
// spell is the module's to judge; the lengths are checked here, because each
// has to fit its prefix. It reports false for an adjudication that cannot be
// written.
func encodeAdjudication(adjudication Adjudication) ([]byte, bool) {
	if len(adjudication.Checkers) == 0 || len(adjudication.Checkers) > MaxCheckers {
		return nil, false
	}
	encoded := []byte{byte(adjudication.Vote)}
	names := append([]string{adjudication.IntentID}, adjudication.Checkers...)
	for index, name := range names {
		if len(name) == 0 || len(name) > MaxPersonBytes {
			return nil, false
		}
		if index == 1 {
			encoded = append(encoded, byte(len(adjudication.Checkers)))
		}
		encoded = append(encoded, byte(len(name)))
		encoded = append(encoded, name...)
	}
	return encoded, true
}

// chain is a Continuation as the module takes it: the frame of the head
// record and the bytes of the release, none for a chain that keeps its
// state.
type chain struct {
	head    []byte
	release []byte
}

// The set-up statuses of the module's interface.
const (
	statusHead          = 5
	statusHeadDigest    = 6
	statusCompromised   = 7
	statusRelease       = 8
	statusNotHalted     = 9
	statusApproval      = 10
	statusReleaseFailed = 11
)

// refusals maps a set-up status of the module onto the error of Continue.
var refusals = map[uint32]error{
	statusHead:          ErrHead,
	statusHeadDigest:    ErrHead,
	statusCompromised:   ErrCompromised,
	statusRelease:       ErrRelease,
	statusNotHalted:     ErrNotHalted,
	statusApproval:      ErrApproval,
	statusReleaseFailed: ErrReleaseFailed,
}

// encodeRelease writes a Release as the module reads it: the number of
// persons, then each as a length byte and its name, the releaser first. What
// a name may spell is the module's to judge; its length is checked here,
// because it has to fit its prefix.
func encodeRelease(release *Release) ([]byte, error) {
	if release == nil {
		return nil, nil
	}
	if len(release.Checkers) > MaxCheckers {
		return nil, fmt.Errorf("%w: it names %d checkers, at most %d", ErrRelease, len(release.Checkers), MaxCheckers)
	}
	persons := append([]string{release.Releaser}, release.Checkers...)
	encoded := []byte{byte(len(persons))}
	for _, person := range persons {
		if len(person) == 0 || len(person) > MaxPersonBytes {
			return nil, fmt.Errorf("%w: a person has %d bytes, outside 1 to %d", ErrRelease, len(person), MaxPersonBytes)
		}
		encoded = append(encoded, byte(len(person)))
		encoded = append(encoded, person...)
	}
	return encoded, nil
}

// Engine is one decision engine with its own chain of audit records. It is
// safe for use by several goroutines; its calls run one at a time. An effect
// must not call the Engine it serves.
type Engine struct {
	mu            sync.Mutex
	mode          Mode
	runtime       wazero.Runtime
	instance      api.Module
	memory        api.Memory
	decide        api.Function
	adjudicate    api.Function
	halt          api.Function
	inputAt       uint32
	inputCapacity uint32
	fault         error
}

// New loads the embedded module, checks its interface and sets the engine up
// at the start of a new chain.
func New(ctx context.Context, config Config) (*Engine, error) {
	return start(ctx, config, nil)
}

// Continue is New for an engine that continues the stored chain from names:
// its first record links onto from.Head and carries the next sequence number.
// Actions the earlier engine held are not carried over and stay unreleased.
//
// It returns ErrHead when the head record is refused. With from.Release it
// returns ErrRelease for a release that cannot be read, ErrNotHalted for a
// chain that does not end halted, ErrCompromised for a chain halted as
// compromised, ErrApproval for a release without the approval the halt's
// risk level demands and ErrReleaseFailed when the release cannot be
// recorded. No engine is set up in any of these cases, and none of them
// writes a record.
func Continue(ctx context.Context, config Config, from Continuation) (*Engine, error) {
	head, err := encodeFrame(from.Head)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHead, err)
	}
	release, err := encodeRelease(from.Release)
	if err != nil {
		return nil, err
	}
	return start(ctx, config, &chain{head: head, release: release})
}

// start loads the embedded module over the caller's effects.
func start(ctx context.Context, config Config, from *chain) (*Engine, error) {
	if config.Clock == nil || config.Signer == nil || config.Sink == nil {
		return nil, errors.New("decision: a clock, a signer and a sink are required; none has a default")
	}
	effects := &host{clock: config.Clock, signer: config.Signer, sink: config.Sink}
	return load(ctx, config, embedded, effects.functions(), from)
}

// load is New or Continue with the module and the host functions named by
// the caller; a nil chain starts a new one.
func load(ctx context.Context, config Config, module []byte, functions []hostFunction, from *chain) (*Engine, error) {
	settings, millis, err := checked(config)
	if err != nil {
		return nil, err
	}
	engine, err := link(ctx, config.Mode, settings, module, functions)
	if err != nil {
		return nil, err
	}
	if err := engine.setUp(ctx, config.KeyID, millis, from); err != nil {
		return nil, errors.Join(err, engine.runtime.Close(ctx))
	}
	return engine, nil
}

// checked reads the configuration: the runtime settings of the mode the
// caller named, and the sink deadline in milliseconds.
func checked(config Config) (wazero.RuntimeConfig, uint32, error) {
	var settings wazero.RuntimeConfig
	switch config.Mode {
	case Compiled:
		settings = wazero.NewRuntimeConfigCompiler()
	case Interpreted:
		settings = wazero.NewRuntimeConfigInterpreter()
	default:
		return nil, 0, errors.New("decision: Config.Mode must be Compiled or Interpreted; none is the default")
	}
	millis := config.SinkDeadline / time.Millisecond
	if millis < 1 || millis > math.MaxUint32 {
		return nil, 0, fmt.Errorf("decision: the sink deadline %v is outside one millisecond to %d", config.SinkDeadline, uint32(math.MaxUint32))
	}
	if len(config.KeyID) == 0 || len(config.KeyID) > MaxKeyIDBytes {
		return nil, 0, fmt.Errorf("decision: the key identifier has %d bytes, outside 1 to %d", len(config.KeyID), MaxKeyIDBytes)
	}
	return settings, uint32(millis), nil
}

// link compiles the module, holds it to the interface and links it to the
// host functions. None of the module's code has run when it returns.
func link(ctx context.Context, mode Mode, settings wazero.RuntimeConfig, module []byte, functions []hostFunction) (engine *Engine, err error) {
	var runtime wazero.Runtime
	defer func() {
		// wazero panics where its compiler does not serve the platform. That
		// is an error of New, never a reason to run the other mode.
		if caught := recover(); caught != nil {
			err = fmt.Errorf("decision: the %s mode cannot run here: %v", mode, caught)
		}
		if err != nil && runtime != nil {
			engine, err = nil, errors.Join(err, runtime.Close(ctx))
		}
	}()
	runtime = wazero.NewRuntimeWithConfig(ctx, settings)

	compiled, err := runtime.CompileModule(ctx, module)
	if err != nil {
		return nil, fmt.Errorf("decision: the module does not compile: %w", err)
	}
	if err := checkSurface(compiled); err != nil {
		return nil, fmt.Errorf("decision: %w", err)
	}
	builder := runtime.NewHostModuleBuilder(hostModule)
	for _, function := range functions {
		builder.NewFunctionBuilder().WithGoModuleFunction(function.call, function.params, function.results).Export(function.name)
	}
	if _, err := builder.Instantiate(ctx); err != nil {
		return nil, fmt.Errorf("decision: the host functions cannot be set up: %w", err)
	}
	// A host function the module imports and the host does not hold fails here.
	instance, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return nil, fmt.Errorf("decision: the module cannot be linked to its host functions: %w", err)
	}
	engine = &Engine{
		mode: mode, runtime: runtime, instance: instance, memory: instance.Memory(),
		decide:     instance.ExportedFunction(exportDecide),
		adjudicate: instance.ExportedFunction(exportAdjudicate),
		halt:       instance.ExportedFunction(exportHalt),
	}
	if engine.memory == nil || engine.decide == nil || engine.adjudicate == nil || engine.halt == nil {
		return nil, errors.New("decision: the module lost its memory or a function of its interface")
	}
	return engine, nil
}

// setUp checks the interface version, finds the input buffer and hands the
// module its key identifier and sink deadline, and the head of the chain it
// continues when there is one.
func (e *Engine) setUp(ctx context.Context, keyID string, millis uint32, from *chain) error {
	version, err := call(ctx, e.instance.ExportedFunction(exportABIVersion))
	if err != nil {
		return err
	}
	if version != abiVersion {
		return fmt.Errorf("decision: the module speaks interface version %d, this loader version %d", version, abiVersion)
	}
	if e.inputAt, err = call(ctx, e.instance.ExportedFunction(exportInput)); err != nil {
		return err
	}
	if e.inputCapacity, err = call(ctx, e.instance.ExportedFunction(exportInputCapacity)); err != nil {
		return err
	}
	if _, ok := e.memory.Read(e.inputAt, e.inputCapacity); !ok || e.inputCapacity < MaxKeyIDBytes {
		return fmt.Errorf("decision: the module's input buffer (%d bytes at %d) is not in its memory", e.inputCapacity, e.inputAt)
	}
	if from == nil {
		return e.begin(ctx, exportInit, []byte(keyID), uint64(len(keyID)), uint64(millis))
	}
	input := append([]byte(keyID), from.head...)
	if uint64(len(input)) > uint64(e.inputCapacity) {
		return fmt.Errorf("%w: its %d bytes do not fit the module's input buffer", ErrHead, len(from.head))
	}
	input = append(input, from.release...)
	if uint64(len(input)) > uint64(e.inputCapacity) {
		return fmt.Errorf("%w: its %d bytes do not fit the module's input buffer", ErrRelease, len(from.release))
	}
	return e.begin(ctx, exportContinue, input, uint64(len(keyID)), uint64(len(from.head)), uint64(len(from.release)), uint64(millis))
}

// begin writes the set-up input to the module and calls one of its two
// set-up functions.
func (e *Engine) begin(ctx context.Context, export string, input []byte, params ...uint64) error {
	if !e.memory.Write(e.inputAt, input) {
		return errors.New("decision: the set-up input cannot be written to the module")
	}
	status, err := call(ctx, e.instance.ExportedFunction(export), params...)
	if err != nil {
		return err
	}
	if status == 0 {
		return nil
	}
	if refusal, known := refusals[status]; known {
		return fmt.Errorf("%w (status %d)", refusal, status)
	}
	return fmt.Errorf("decision: the module refused its set-up with status %d", status)
}

// call runs one exported function that returns a single 32-bit value.
func call(ctx context.Context, function api.Function, params ...uint64) (uint32, error) {
	if function == nil {
		return 0, errors.New("decision: the module lacks a function of its interface")
	}
	results, err := function.Call(ctx, params...)
	if err != nil {
		return 0, fmt.Errorf("decision: %s failed: %w", function.Definition().Name(), err)
	}
	if len(results) != 1 {
		return 0, fmt.Errorf("decision: %s returned %d values", function.Definition().Name(), len(results))
	}
	return api.DecodeU32(results[0]), nil
}

// Mode returns the mode the module runs in.
func (e *Engine) Mode() Mode {
	return e.mode
}

// Decide asks the engine about one proposal, the JSON text of the library's
// proposal schema.
//
// The Outcome is the answer in every case; test it with Permits. The error is
// nil when the engine answered, also when it answered Blocked or Refused. It
// is non-nil only when the module could not be run or its answer could not be
// read: the Outcome is then Blocked with BlockLoaderFault, and so is every
// later one.
func (e *Engine) Decide(ctx context.Context, proposal []byte) (Outcome, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ask(ctx, e.decide, proposal, decode)
}

// Adjudicate brings the checkers' decision of a held action to the engine.
//
// Allowed says the checkers approved and the action may run; Rejected says
// they rejected it. Each is a record of the chain. NotAdjudicated says the
// engine took no decision and recorded no vote, and Outcome.Detail says why;
// Refused with RefusedAdjudication says the Adjudication cannot be read. Only
// Allowed permits.
//
// A vote that cannot be signed or stored is no vote: the outcome is
// NotAdjudicated with UnadjudicatedUnrecorded, the action is no longer held
// and the engine is halted. The error is as for Decide.
func (e *Engine) Adjudicate(ctx context.Context, adjudication Adjudication) (Outcome, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	input, written := encodeAdjudication(adjudication)
	if e.fault == nil && !written {
		// The module refuses these bytes the same way; they are not sent
		// because a length that does not fit its prefix cannot be written.
		return Outcome{Class: Refused, Detail: RefusedAdjudication}, nil
	}
	return e.ask(ctx, e.adjudicate, input, decodeAdjudication)
}

// ask hands input to one of the module's two deciding functions and reads
// the outcome code with read. The caller holds the lock.
func (e *Engine) ask(ctx context.Context, function api.Function, input []byte, read func(uint32) (Outcome, error)) (Outcome, error) {
	if e.fault != nil {
		return loaderFault, e.fault
	}
	// Input longer than the buffer is not written; the module is told its
	// true length and refuses it.
	length := min(uint64(len(input)), math.MaxUint32)
	if length <= uint64(e.inputCapacity) && !e.memory.Write(e.inputAt, input) {
		return e.poison(errors.New("decision: the input cannot be written to the module"))
	}
	code, err := call(ctx, function, length)
	if err != nil {
		return e.poison(err)
	}
	outcome, err := read(code)
	if err != nil {
		return e.poison(fmt.Errorf("decision: %w", err))
	}
	return outcome, nil
}

// Halt halts the engine as an operator stop at the risk level the caller
// names; a Level that is none of the six halts at the highest. Every decision
// is Blocked from then on and no adjudication is taken. A halt that stands
// already is never made weaker: it keeps its reason, and takes the stricter
// of the two levels.
//
// The engine permits nothing after Halt, whatever Halt returns. Nil says the
// halt is a record of the chain. ErrHaltUnrecorded says the engine is halted
// and the record could not be signed or stored. Every other error says the
// module could not be run or gave an answer the loader cannot read: the
// engine then answers Blocked with BlockLoaderFault from then on.
//
// No call lifts the halt on this Engine. The program continues the stored
// chain with Continue and a Release.
func (e *Engine) Halt(ctx context.Context, level Level) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fault != nil {
		return e.fault
	}
	status, err := call(ctx, e.halt, uint64(level))
	switch {
	case err != nil:
		_, err = e.poison(err)
	case status == haltUnrecorded:
		err = ErrHaltUnrecorded
	case status != haltRecorded:
		_, err = e.poison(fmt.Errorf("decision: the module answered the halt with status %d", status))
	}
	return err
}

var (
	loaderFault = Outcome{Class: Blocked, Detail: BlockLoaderFault}
	errClosed   = errors.New("decision: the engine is closed")
)

// poison records the first fault; the engine answers with it from then on. A
// module that trapped is in a state nobody checked, so it is not asked again.
func (e *Engine) poison(fault error) (Outcome, error) {
	e.fault = fault
	return loaderFault, fault
}

// Close releases the module. Decide and Adjudicate answer Blocked afterwards.
func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fault == nil {
		e.fault = errClosed
	}
	return e.runtime.Close(ctx)
}
