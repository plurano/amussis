// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// releasedChain holds the records a host of the v0.1.0 release stored for
// the run of releasedRun, one frame per line in hex. The module of that
// release wrote them: the file was written by TestWriteReleasedChain on a
// checkout of the tag v0.1.0, as its header says. A host keeps such records,
// so the module of every later build at the same interface version has to
// write the same bytes for the same run, and has to continue a chain that
// ends in one of them.
const releasedChain = "testdata/v0.1.0-chain.hex"

// writeReleasedChain names the variable that makes TestWriteReleasedChain
// write the file instead of skipping.
const writeReleasedChain = "AMUSSIS_WRITE_RELEASED_CHAIN"

// maxReleasedRecords bounds the records the file may hold.
const maxReleasedRecords = 64

// releasedRun is the run whose records the file holds: an allowed action, a
// consequential one held and then approved, a halt by the operator at the
// consequential level, and a continuation that releases the halt and allows
// one more action.
func releasedRun(t *testing.T, mode Mode) []Record {
	t.Helper()
	w := newWorld()
	engine := engineFor(t, w, mode)
	want(t, decide(t, engine, routine), Outcome{Class: Allowed})
	want(t, decide(t, engine, heldConsequential), Outcome{Class: RequireApproval})
	want(t, adjudicate(t, engine, vote(Approve, "carol")), Outcome{Class: Allowed})
	if err := engine.Halt(t.Context(), "operator-7", LevelConsequential); err != nil {
		t.Fatalf("Halt: %v", err)
	}
	next := continued(t, w, mode, Continuation{Head: head(t, w), Release: by("olga", "petra")})
	want(t, decide(t, next, routine), Outcome{Class: Allowed})
	return w.stored
}

// readReleasedChain returns the interface version the file names and its
// records.
func readReleasedChain(t *testing.T) (int, []Record) {
	t.Helper()
	file, err := os.Open(releasedChain)
	if err != nil {
		t.Fatalf("the stored chain: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close %s: %v", releasedChain, err)
		}
	}()
	version, records := 0, []Record{}
	lines := bufio.NewScanner(file)
	for lines.Scan() && len(records) <= maxReleasedRecords {
		line := strings.TrimSpace(lines.Text())
		record, ok, err := parseReleasedLine(t, line, &version)
		if err != nil {
			t.Fatalf("%s: %q: %v", releasedChain, line, err)
		}
		if ok {
			records = append(records, record)
		}
	}
	checkReleasedScan(t, lines, len(records))
	return version, records
}

func parseReleasedLine(t *testing.T, line string, version *int) (Record, bool, error) {
	if value, found := strings.CutPrefix(line, "interface "); found {
		v, err := strconv.Atoi(value)
		if err != nil {
			return Record{}, false, err
		}
		*version = v
		return Record{}, false, nil
	}
	if line == "" || strings.HasPrefix(line, "#") {
		return Record{}, false, nil
	}
	return releasedRecord(t, line), true, nil
}

func checkReleasedScan(t *testing.T, lines *bufio.Scanner, count int) {
	t.Helper()
	if err := lines.Err(); err != nil || count == 0 || count > maxReleasedRecords {
		t.Fatalf("%s holds %d records, error %v", releasedChain, count, err)
	}
}

func releasedRecord(t *testing.T, line string) Record {
	t.Helper()
	frame, err := hex.DecodeString(line)
	if err != nil {
		t.Fatalf("%s: a frame that is not hex: %v", releasedChain, err)
	}
	record, err := parseFrame(frame)
	if err != nil {
		t.Fatalf("%s: a frame the host does not read: %v", releasedChain, err)
	}
	return record
}

// firstDifference names the first record, and the first byte of its content,
// where got and stored part.
func firstDifference(got, stored []Record) string {
	for index := 0; index < len(got) && index < len(stored); index++ {
		a, b := got[index].Preimage, stored[index].Preimage
		for at := 0; at < len(a) && at < len(b); at++ {
			if a[at] != b[at] {
				return fmt.Sprintf("record %d, content byte %d: %#02x, stored %#02x", index+1, at, a[at], b[at])
			}
		}
		if len(a) != len(b) {
			return fmt.Sprintf("record %d: content of %d bytes, stored %d", index+1, len(a), len(b))
		}
		if !sameRecord(got[index], stored[index]) {
			return fmt.Sprintf("record %d: digest, key or signature", index+1)
		}
	}
	return fmt.Sprintf("%d records, stored %d", len(got), len(stored))
}

// Positive: the records of the released run come out of this build byte for
// byte, in both modes, while the interface version is the one the file names.
func TestTheReleasedRunIsWrittenByteForByte(t *testing.T) {
	version, stored := readReleasedChain(t)
	if version != abiVersion {
		t.Fatalf("this loader speaks interface version %d, the stored chain was written at %d: "+
			"a host that stored it needs a way to go on, and a chain of the new version needs a file of its own",
			abiVersion, version)
	}
	inBothModes(t, func(t *testing.T, mode Mode) {
		got := releasedRun(t, mode)
		for index := 0; index < len(got) || index < len(stored); index++ {
			if index >= len(got) || index >= len(stored) || !sameRecord(got[index], stored[index]) {
				t.Fatalf("this build writes other records than the released module: %s", firstDifference(got, stored))
			}
		}
	})
}

func sameRecord(a, b Record) bool {
	return bytes.Equal(a.Preimage, b.Preimage) && a.Digest == b.Digest && a.KeyID == b.KeyID &&
		bytes.Equal(a.Signature, b.Signature)
}

// Positive: a chain the released module stored reads as one chain and goes on
// from its head, and from the halted record it holds once the halt is
// released.
func TestAChainTheReleasedModuleStoredGoesOn(t *testing.T) {
	_, stored := readReleasedChain(t)
	if _, err := walk(stored); err != nil {
		t.Fatalf("the stored chain: %v", err)
	}
	halt := slices.IndexFunc(stored, func(record Record) bool { return record.Preimage[latchAt] == 1 })
	if halt < 0 || halt == len(stored)-1 {
		t.Fatalf("the stored chain holds no halt that a later record releases (halt at %d of %d)", halt+1, len(stored))
	}
	inBothModes(t, func(t *testing.T, mode Mode) {
		for _, from := range []Continuation{
			{Head: stored[len(stored)-1]},
			{Head: stored[halt], Release: by("olga", "petra")},
		} {
			w := newWorld()
			at := slices.IndexFunc(stored, func(record Record) bool { return sameRecord(record, from.Head) })
			w.stored = append(w.stored, stored[:at+1]...)
			engine := continued(t, w, mode, from)
			want(t, decide(t, engine, routine), Outcome{Class: Allowed})
			wantChain(t, w, uint64(len(w.stored)))
		}
	})
}

// TestWriteReleasedChain writes the file from the run of this build. It runs
// only when AMUSSIS_WRITE_RELEASED_CHAIN names the release the checkout is
// at, and is meant for a checkout of that tag: the file then holds what the
// released module wrote.
func TestWriteReleasedChain(t *testing.T) {
	release := os.Getenv(writeReleasedChain)
	if release == "" {
		t.Skip("writes " + releasedChain + " only when " + writeReleasedChain + " names the release")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "# Records a host of the %s release stored for the run of releasedRun\n", release)
	fmt.Fprintf(&out, "# (released_test.go), written by TestWriteReleasedChain on a checkout of\n")
	fmt.Fprintf(&out, "# the tag %s. One frame per line, in hex.\n", release)
	fmt.Fprintf(&out, "# module sha256 %x\n", sha256.Sum256(embedded))
	fmt.Fprintf(&out, "interface %d\n", abiVersion)
	for _, record := range releasedRun(t, Compiled) {
		frame, err := encodeFrame(record)
		if err != nil {
			t.Fatalf("encodeFrame: %v", err)
		}
		fmt.Fprintf(&out, "%s\n", hex.EncodeToString(frame))
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releasedChain, []byte(out.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
