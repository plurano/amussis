// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"fmt"
	"slices"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// abiVersion is the interface version this loader speaks.
const abiVersion = 4

const (
	exportMemory        = "memory"
	exportABIVersion    = "amussis_abi_version"
	exportInput         = "amussis_input"
	exportInputCapacity = "amussis_input_capacity"
	exportInit          = "amussis_init"
	exportContinue      = "amussis_continue"
	exportDecide        = "amussis_decide"
	exportAdjudicate    = "amussis_adjudicate"
	exportHalt          = "amussis_halt"
)

// signature is the type of one function of the interface.
type signature struct {
	params, results []api.ValueType
}

func (s signature) equals(definition api.FunctionDefinition) bool {
	return slices.Equal(s.params, definition.ParamTypes()) && slices.Equal(s.results, definition.ResultTypes())
}

func moduleExports() map[string]signature {
	i32 := api.ValueTypeI32
	return map[string]signature{
		exportABIVersion:    {nil, []api.ValueType{i32}},
		exportInput:         {nil, []api.ValueType{i32}},
		exportInputCapacity: {nil, []api.ValueType{i32}},
		exportInit:          {[]api.ValueType{i32, i32}, []api.ValueType{i32}},
		exportContinue:      {[]api.ValueType{i32, i32, i32, i32}, []api.ValueType{i32}},
		exportDecide:        {[]api.ValueType{i32}, []api.ValueType{i32}},
		exportAdjudicate:    {[]api.ValueType{i32}, []api.ValueType{i32}},
		exportHalt:          {[]api.ValueType{i32}, []api.ValueType{i32}},
	}
}

func moduleImports() map[string]signature {
	imports := map[string]signature{}
	for _, function := range (&host{}).functions() {
		imports[function.name] = signature{function.params, function.results}
	}
	return imports
}

// checkSurface holds a module to the interface before any of its code runs:
// it imports the three host functions and nothing else, and exports the eight
// functions and its memory and nothing else. A module that asks for more than
// a clock, a signer and a sink is not this library's module.
func checkSurface(module wazero.CompiledModule) error {
	if imported := module.ImportedMemories(); len(imported) != 0 {
		return fmt.Errorf("the module imports %d memories; it must own its memory", len(imported))
	}
	wanted := moduleImports()
	imported := module.ImportedFunctions()
	seen := map[string]bool{}
	for _, definition := range imported {
		from, name, _ := definition.Import()
		expected, known := wanted[name]
		switch {
		case from != hostModule || !known:
			return fmt.Errorf("the module imports %s.%s, which is no host effect of this interface", from, name)
		case seen[name]:
			return fmt.Errorf("the module imports %s.%s twice", from, name)
		case !expected.equals(definition):
			return fmt.Errorf("the module imports %s.%s with another type", from, name)
		}
		seen[name] = true
	}
	if len(seen) != len(wanted) {
		return fmt.Errorf("the module imports %d of the %d host effects", len(seen), len(wanted))
	}

	exports := moduleExports()
	exported := module.ExportedFunctions()
	for name, definition := range exported {
		expected, known := exports[name]
		if !known {
			return fmt.Errorf("the module exports %s, which is no function of this interface", name)
		}
		if !expected.equals(definition) {
			return fmt.Errorf("the module exports %s with another type", name)
		}
	}
	if len(exported) != len(exports) {
		return fmt.Errorf("the module exports %d of the %d functions", len(exported), len(exports))
	}
	memories := module.ExportedMemories()
	if _, ok := memories[exportMemory]; !ok || len(memories) != 1 {
		return fmt.Errorf("the module must export exactly one memory, named %q", exportMemory)
	}
	return nil
}
