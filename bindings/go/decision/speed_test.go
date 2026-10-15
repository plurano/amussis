// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	// speedBatches is how often each mode times its decisions; the fastest
	// batch counts, so a pause of the host in one batch does not decide.
	speedBatches = 5
	// speedDecisions is how many decisions one batch of a mode takes.
	speedDecisions = 40
	// speedMargin is how many times faster Compiled has to decide than
	// Interpreted. The README states about ninety on amd64; ten leaves room
	// for a slow host and still fails an engine that interprets either way.
	speedMargin = 10
)

// fastestDecision is the shortest time per decision of the routine proposal
// over speedBatches batches on one engine of mode.
func fastestDecision(t testing.TB, mode Mode) time.Duration {
	t.Helper()
	w := newWorld()
	engine, err := New(t.Context(), w.config(mode))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := engine.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	proposal := []byte(routine)
	fastest := time.Duration(1<<63 - 1)
	for range speedBatches {
		start := time.Now()
		for range speedDecisions {
			outcome, err := engine.Decide(t.Context(), proposal)
			if err != nil || outcome != (Outcome{Class: Allowed}) {
				t.Fatalf("Decide: %+v, %v", outcome, err)
			}
		}
		fastest = min(fastest, time.Since(start)/speedDecisions)
		w.stored = w.stored[:0]
	}
	return fastest
}

// TestCompiledDecidesFasterThanInterpreted holds the two modes apart by the
// time they take: an engine asked for Compiled that interprets the module
// reports Compiled all the same, and only its speed tells.
func TestCompiledDecidesFasterThanInterpreted(t *testing.T) {
	needCompiler(t, Compiled)
	compiled := fastestDecision(t, Compiled)
	interpreted := fastestDecision(t, Interpreted)
	t.Logf("per decision: compiled %v, interpreted %v, %.1f times", compiled, interpreted, float64(interpreted)/float64(compiled))
	if interpreted < speedMargin*compiled {
		t.Fatalf("interpreted %v is not %d times compiled %v", interpreted, speedMargin, compiled)
	}
}

// BenchmarkDecide times one decision of the routine proposal in each mode,
// the figure behind the README's ratio of the two:
//
//	go test -run '^$' -bench Decide ./decision
func BenchmarkDecide(b *testing.B) {
	for _, mode := range []Mode{Compiled, Interpreted} {
		b.Run(mode.String(), func(b *testing.B) {
			benchmarkMode(b, mode)
		})
	}
}

func benchmarkMode(b *testing.B, mode Mode) {
	w := newWorld()
	engine, err := New(b.Context(), w.config(mode))
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	b.Cleanup(func() {
		if err := engine.Close(context.Background()); err != nil {
			b.Errorf("Close: %v", err)
		}
	})
	proposal := []byte(routine)
	b.ResetTimer()
	for range b.N {
		outcome, err := engine.Decide(b.Context(), proposal)
		if err != nil || outcome != (Outcome{Class: Allowed}) {
			b.Fatalf("Decide: %+v, %v", outcome, err)
		}
		w.stored = w.stored[:0]
	}
}

// TestCompiledRunsOnlyWhereWazeroCompiles holds Compiled to the architectures
// wazero compiles for: amd64 and arm64 run it, any other makes New fail with
// an error and no engine. The make target verify-go runs this test for
// linux/386 as well, where it takes the second branch.
func TestCompiledRunsOnlyWhereWazeroCompiles(t *testing.T) {
	engine, err := New(t.Context(), newWorld().config(Compiled))
	if !compiles() {
		if err == nil || engine != nil || !strings.Contains(err.Error(), "the compiled mode cannot run here") {
			t.Fatalf("New on %s: engine %v, error %v; want no engine and the mode refused", runtime.GOARCH, engine, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("New on %s: %v", runtime.GOARCH, err)
	}
	closeAtEnd(t, engine)
}

// compiles says whether wazero compiles for the architecture of this run.
func compiles() bool {
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

// needCompiler skips a test of Compiled where wazero does not compile, as on
// the linux/386 run of verify-go; TestCompiledRunsOnlyWhereWazeroCompiles
// holds New to its error there. Interpreted is never skipped.
func needCompiler(t testing.TB, mode Mode) {
	t.Helper()
	if mode == Compiled && !compiles() {
		t.Skipf("wazero compiles for amd64 and arm64, not %s", runtime.GOARCH)
	}
}

// TestNoTestOfCompiledIsSkippedWhereWazeroCompiles holds needCompiler to
// its one case: on amd64 and arm64 it skips nothing, and it never skips
// Interpreted.
func TestNoTestOfCompiledIsSkippedWhereWazeroCompiles(t *testing.T) {
	for _, mode := range []Mode{Compiled, Interpreted} {
		var skipped bool
		t.Run(mode.String(), func(t *testing.T) {
			t.Cleanup(func() { skipped = t.Skipped() })
			needCompiler(t, mode)
		})
		if skipped && (compiles() || mode == Interpreted) {
			t.Fatalf("needCompiler skipped %v on %s", mode, runtime.GOARCH)
		}
	}
}
