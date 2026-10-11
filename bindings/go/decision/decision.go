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

// Engine is one decision engine with its own chain of audit records. It is
// safe for use by several goroutines; decisions run one at a time. An effect
// must not call the Engine it serves.
type Engine struct {
	mu            sync.Mutex
	mode          Mode
	runtime       wazero.Runtime
	instance      api.Module
	memory        api.Memory
	decide        api.Function
	inputAt       uint32
	inputCapacity uint32
	fault         error
}

// New loads the embedded module, checks its interface and sets the engine up.
func New(ctx context.Context, config Config) (*Engine, error) {
	if config.Clock == nil || config.Signer == nil || config.Sink == nil {
		return nil, errors.New("decision: a clock, a signer and a sink are required; none has a default")
	}
	effects := &host{clock: config.Clock, signer: config.Signer, sink: config.Sink}
	return load(ctx, config, embedded, effects.functions())
}

// load is New with the module and the host functions named by the caller.
func load(ctx context.Context, config Config, module []byte, functions []hostFunction) (*Engine, error) {
	settings, millis, err := checked(config)
	if err != nil {
		return nil, err
	}
	engine, err := link(ctx, config.Mode, settings, module, functions)
	if err != nil {
		return nil, err
	}
	if err := engine.setUp(ctx, config.KeyID, millis); err != nil {
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
	engine = &Engine{mode: mode, runtime: runtime, instance: instance, memory: instance.Memory(), decide: instance.ExportedFunction(exportDecide)}
	if engine.memory == nil || engine.decide == nil {
		return nil, errors.New("decision: the module lost its memory or its decide function")
	}
	return engine, nil
}

// setUp checks the interface version, finds the input buffer and hands the
// module its key identifier and sink deadline.
func (e *Engine) setUp(ctx context.Context, keyID string, millis uint32) error {
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
	if !e.memory.Write(e.inputAt, []byte(keyID)) {
		return errors.New("decision: the key identifier cannot be written to the module")
	}
	status, err := call(ctx, e.instance.ExportedFunction(exportInit), uint64(len(keyID)), uint64(millis))
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("decision: the module refused its set-up with status %d", status)
	}
	return nil
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
	if e.fault != nil {
		return loaderFault, e.fault
	}
	// A proposal longer than the buffer is not written; the module is told
	// its true length and refuses it.
	length := min(uint64(len(proposal)), math.MaxUint32)
	if length <= uint64(e.inputCapacity) && !e.memory.Write(e.inputAt, proposal) {
		return e.poison(errors.New("decision: the proposal cannot be written to the module"))
	}
	code, err := call(ctx, e.decide, length)
	if err != nil {
		return e.poison(err)
	}
	outcome, err := decode(code)
	if err != nil {
		return e.poison(fmt.Errorf("decision: %w", err))
	}
	return outcome, nil
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

// Close releases the module. Decide answers Blocked afterwards.
func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fault == nil {
		e.fault = errClosed
	}
	return e.runtime.Close(ctx)
}
