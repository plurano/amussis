// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

// A program outside the binding's module: it requires the binding through this
// file as any consumer does. The replace line points at the binding in this
// tree, so the examples run against the code they sit next to. The internal
// element keeps the module out of the published API: no program can import it,
// and tools/apicompat/gate reports it as not public instead of comparing it.
module github.com/plurano/amussis/internal/examples/go-consumer

go 1.27

require github.com/plurano/amussis/bindings/go v0.0.0

require (
	github.com/tetratelabs/wazero v1.12.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

replace github.com/plurano/amussis/bindings/go => ../../bindings/go
