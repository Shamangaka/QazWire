//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// R5 auditor tests for the UNMODIFIED klm16 at aa27727 (klm.go blob 6274939).
// klm.go is not changed. Each test PASSES when the reported behaviour is
// reproduced and logs a CONFIRMED line.
package klm16

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// R5-01: a ticket QUEUED on the previous generation is counted as a "pinned"
// generation although the very same Rotate flushes it. With maxPinned=1 the
// documented "previous-generation queued entries are flushed on the second
// rotation" never happens: the second rotation stops the whole session.
func TestR5_01_QueuedPreviousTicketTriggersBacklogStop(t *testing.T) {
	v, _ := NewLabSession(10, 1024, 1)
	s := v.(*labSession)
	tok, err := s.Prepare([]byte("queued, not in flight"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(); err != nil { // g1 -> previous, ticket stays queued
		t.Fatal(err)
	}
	snap := s.Snapshot()
	if snap.InFlight != 0 || snap.Pending != 1 {
		t.Fatalf("setup: %+v", snap)
	}
	err = s.Rotate() // documented: flush the previous-generation queue
	after := s.Snapshot()
	if !errors.Is(err, ErrBacklog) || !after.Closed {
		t.Fatalf("not reproduced: rotate=%v closed=%v", err, after.Closed)
	}
	if _, cerr := s.Consume(tok); !errors.Is(cerr, ErrBacklog) {
		t.Fatalf("unexpected consume after stop: %v", cerr)
	}
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	if err := s.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("CONFIRMED R5-01: no operation in flight, one ticket queued on the previous generation; the second Rotate returned %v and stopped the session instead of flushing the queue", err)
}

// R5-E1: every identity of a laboratory record, and the synthetic material
// itself, is a pure function of process-local counters, so a restarted
// process reproduces them exactly.
func TestR5_E1_RestartRepeatsIdentitiesAndMaterial(t *testing.T) {
	if os.Getenv("R5_KLM_CHILD") == "1" {
		v, _ := NewLabSession(4, 64, 2)
		s := v.(*labSession)
		var out bytes.Buffer
		for i := 0; i < 2; i++ {
			tok, err := s.Prepare([]byte{byte(i)})
			if err != nil {
				os.Exit(3)
			}
			s.mu.Lock()
			sum := sha256.Sum256(s.current.material.bytes[:])
			s.mu.Unlock()
			rec, err := s.Consume(tok)
			if err != nil {
				os.Exit(4)
			}
			fmt.Fprintf(&out, "%d/%d/%d/%d/%s;", rec.SessionID, rec.Epoch, rec.MaterialID, rec.Sequence, hex.EncodeToString(sum[:8]))
			if err := s.Rotate(); err != nil {
				os.Exit(5)
			}
		}
		os.Stdout.WriteString("R5OUT " + out.String() + "\n")
		os.Exit(0)
	}
	run := func() string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestR5_E1_RestartRepeatsIdentitiesAndMaterial$")
		cmd.Env = append(os.Environ(), "R5_KLM_CHILD=1")
		b, err := cmd.Output()
		if err != nil {
			t.Fatalf("child: %v", err)
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("R5OUT ")) {
				return string(line[6:])
			}
		}
		t.Fatalf("no child output: %q", b)
		return ""
	}
	a, b := run(), run()
	if a != b {
		t.Fatalf("not reproduced: %s vs %s", a, b)
	}
	t.Logf("CONFIRMED R5-E1: two process lifetimes produced identical (SessionID/Epoch/MaterialID/Sequence/material-hash) tuples: %s", a)
}
