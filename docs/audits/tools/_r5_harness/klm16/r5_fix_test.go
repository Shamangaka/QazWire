//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// R5 fix test: run ONLY on the copy patched with klm16_r5_fix.patch.
package klm16

import (
	"errors"
	"testing"
)

func TestR5Fix_01_QueuedPreviousTicketIsFlushedNotBacklog(t *testing.T) {
	s := lab(t, 10, 1024, 1)
	tok, err := s.Prepare([]byte("queued"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(); err != nil {
		t.Fatalf("queued ticket treated as pinned work: %v", err)
	}
	if _, err := s.Consume(tok); !errors.Is(err, ErrTicket) {
		t.Fatalf("flushed ticket still consumable: %v", err)
	}
	if snap := s.Snapshot(); snap.Closed || snap.Pending != 0 || snap.PendingBytes != 0 {
		t.Fatalf("unexpected state: %+v", snap)
	}
}
