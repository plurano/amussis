// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

// Package consumer uses the Go binding as a program outside this repository
// does: through its import path, required in go.mod. Every Go block of the
// README stands in this file line for line, inside a function an example
// runs and checks; tools/readme_snippets.py refuses a README block that does
// not.
package consumer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/plurano/amussis/bindings/go/decision"
)

// start is the time the clock of the examples reads, in seconds.
const start = 1_760_000_000

// The proposals of the examples: a routine action the engine allows, and a
// consequential one it holds until a checker decides it.
const (
	routine = `{"schema":"amussis.decision.proposal.v1","id":"intent-0001","agent":"agent-01",` +
		`"maker":"maker-alice","action":"file-modification","target":"/srv/data/report.txt",` +
		`"declared-tier":"tier-c-routine-bounded","oversight":"standard"}`
	consequential = `{"schema":"amussis.decision.proposal.v1","id":"intent-0042","agent":"agent-01",` +
		`"maker":"maker-alice","action":"file-modification","target":"/srv/data/report.txt",` +
		`"declared-tier":"tier-a-consequential","oversight":"standard"}`
)

// store is the host of the examples: a clock that reads start, a signer that
// writes the digest backwards and a sink that keeps every record in memory.
// A real host signs with a key and stores each record durably.
type store struct {
	records []decision.Record
}

func (s *store) Now(context.Context) (int64, error) { return start, nil }

func (s *store) Sign(_ context.Context, digest [decision.DigestBytes]byte) ([]byte, error) {
	signature := slices.Clone(digest[:])
	slices.Reverse(signature)
	return signature, nil
}

func (s *store) Append(_ context.Context, record decision.Record, _ time.Duration) error {
	s.records = append(s.records, record)
	return nil
}

// last is the record the sink stored last.
func (s *store) last() (decision.Record, error) {
	if len(s.records) == 0 {
		return decision.Record{}, errors.New("the sink holds no record")
	}
	return s.records[len(s.records)-1], nil
}

func (s *store) config() decision.Config {
	return decision.Config{
		KeyID:        "host-key-01",
		SinkDeadline: 250 * time.Millisecond,
		Mode:         decision.Compiled,
		Clock:        s, Signer: s, Sink: s,
	}
}

// name spells an outcome class for the output the examples are checked by.
func name(class decision.Class) string {
	switch class {
	case decision.Allowed:
		return "allowed"
	case decision.Warned:
		return "warned"
	case decision.RequireApproval:
		return "held for approval"
	case decision.Rejected:
		return "rejected"
	case decision.NotAdjudicated:
		return "not adjudicated"
	case decision.Refused:
		return "refused"
	default:
		return "blocked"
	}
}

// decideOnce is the README's first block: an engine is set up and decides
// one proposal; act is the action, run only when the engine permits it.
func decideOnce(ctx context.Context, clock decision.Clock, signer decision.Signer, sink decision.Sink, proposalJSON []byte, act func()) error {
	engine, err := decision.New(ctx, decision.Config{
		KeyID:        "host-key-01",
		SinkDeadline: 250 * time.Millisecond,
		Mode:         decision.Compiled,
		Clock:        clock, Signer: signer, Sink: sink,
	})
	if err != nil {
		return err
	}
	outcome, err := engine.Decide(ctx, proposalJSON)
	if outcome.Permits() {
		act() // only a permitted action runs
	}
	fmt.Println("decided:", name(outcome.Class))
	return errors.Join(err, engine.Close(ctx))
}

// restart is a program that starts again and continues the stored chain.
func restart(ctx context.Context, config decision.Config, lastStored decision.Record, proposalJSON []byte) error {
	engine, err := decision.Continue(ctx, config, decision.Continuation{Head: lastStored})
	if err != nil {
		return err
	}
	outcome, err := engine.Decide(ctx, proposalJSON)
	fmt.Println("after a restart:", name(outcome.Class))
	return errors.Join(err, engine.Close(ctx))
}

// release continues a chain that ends halted with the halt lifted.
func release(ctx context.Context, config decision.Config, lastStored decision.Record) (*decision.Engine, error) {
	from := decision.Continuation{
		Head:    lastStored,
		Release: &decision.Release{Releaser: "olga", Checkers: []string{"petra"}},
	}
	engine, err := decision.Continue(ctx, config, from)
	return engine, err
}

// approve brings one checker's approval of the held action to the engine; act
// is the held action.
func approve(ctx context.Context, engine *decision.Engine, act func()) error {
	outcome, err := engine.Adjudicate(ctx, decision.Adjudication{
		IntentID: "intent-0042",
		Vote:     decision.Approve,
		Checkers: []string{"carol"},
	})
	if outcome.Permits() {
		act() // approved: the held action runs
	}
	fmt.Println("adjudicated:", name(outcome.Class))
	return err
}

// stop is the operator stop at the consequential level.
func stop(ctx context.Context, engine *decision.Engine, operatorHash string) error {
	err := engine.Halt(ctx, operatorHash, decision.LevelConsequential)
	return err
}

func identity(key []byte, id string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil))
}

func Example() {
	host := &store{}
	err := decideOnce(context.Background(), host, host, host, []byte(routine), func() {})
	fmt.Println("records:", len(host.records), "error:", err)
	// Output:
	// decided: allowed
	// records: 1 error: <nil>
}

// One engine holds an action until a checker approves it, and is then
// halted by the operator. The program starts again halted, and runs again
// once the halt is released.
func Example_lifecycle() {
	ctx := context.Background()
	host := &store{}
	engine, err := decision.New(ctx, host.config())
	if err != nil {
		fmt.Println(err)
		return
	}
	held, err := engine.Decide(ctx, []byte(consequential))
	fmt.Println("decided:", name(held.Class), "error:", err)
	fmt.Println("error:", approve(ctx, engine, func() {}))
	operator := identity([]byte("key of this log period"), "operator-7")
	fmt.Println("halt recorded:", stop(ctx, engine, operator) == nil)
	fmt.Println("closed:", engine.Close(ctx))

	halted, err := host.last()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("error:", restart(ctx, host.config(), halted, []byte(routine)))

	halted, err = host.last()
	if err != nil {
		fmt.Println(err)
		return
	}
	released, err := release(ctx, host.config(), halted)
	if err != nil {
		fmt.Println(err)
		return
	}
	outcome, err := released.Decide(ctx, []byte(routine))
	fmt.Println("after the release:", name(outcome.Class), "error:", err)
	fmt.Println("closed:", released.Close(ctx))
	// Output:
	// decided: held for approval error: <nil>
	// adjudicated: allowed
	// error: <nil>
	// halt recorded: true
	// closed: <nil>
	// after a restart: blocked
	// error: <nil>
	// after the release: allowed error: <nil>
	// closed: <nil>
}
