//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package klm16

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// Regression R5-01: a queued grandparent ticket is not an in-flight lease.
// The second rotation must flush the ticket and remain operational.
func TestM162_QueuedGrandparentDoesNotConsumePinnedBudget(t *testing.T) {
	s := lab(t, 10, 1024, 1)
	old, err := s.Prepare([]byte("queued"))
	if err != nil {
		t.Fatal(err)
	}
	g0 := old.state.gen
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	before := s.Snapshot()
	if before.Pending != 1 || before.InFlight != 0 || before.Closed {
		t.Fatalf("invalid setup: %+v", before)
	}
	if err := s.Rotate(); err != nil {
		t.Fatalf("queued ticket incorrectly treated as active lease: %v", err)
	}
	after := s.Snapshot()
	if after.Closed || after.CurrentEpoch != 3 || after.Pending != 0 ||
		after.PendingBytes != 0 || after.ReservedBytes != 0 || after.InFlight != 0 {
		t.Fatalf("rotation did not drain superseded queue: %+v", after)
	}
	if !g0.wiped || old.state.gen != nil || old.state.session != nil {
		t.Fatal("superseded ticket retained an owner or a live generation")
	}
	if _, err := s.Consume(old); !errors.Is(err, ErrTicket) {
		t.Fatalf("superseded queued ticket remained consumable: %v", err)
	}
	current, err := s.Prepare([]byte("current"))
	if err != nil {
		t.Fatalf("session was unexpectedly stopped: %v", err)
	}
	rec, err := s.Consume(current)
	if err != nil || rec.Epoch != 3 {
		t.Fatalf("current generation failed: rec=%+v err=%v", rec, err)
	}
}

// R5-01 fix MUST NOT weaken genuine fail-closed behavior: even after
// flushing a queued grandparent, an in-flight grandparent lease remains.
func TestM162_GrandparentInFlightStillPoisonsOnBudget(t *testing.T) {
	s := lab(t, 20, 1024, 1)
	queued, err := s.Prepare([]byte("queued"))
	if err != nil {
		t.Fatal(err)
	}
	g0 := queued.state.gen
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	s.beforeQueue = func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	worker := make(chan error, 1)
	go func() {
		_, err := s.Prepare([]byte("stalled"))
		worker <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker never acquired a generation lease")
	}
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(); !errors.Is(err, ErrBacklog) {
		t.Fatalf("in-flight grandparent lease was not fail-closed: %v", err)
	}
	before := s.Snapshot()
	if !before.Closed || !before.Faulted || before.Pending != 0 || before.InFlight != 1 {
		t.Fatalf("incorrect emergency state: %+v", before)
	}
	if g0.wiped || queued.state.gen != nil || queued.state.session != nil {
		t.Fatal("generation wiped under active lease or stale ticket retained")
	}
	unblock()
	select {
	case err := <-worker:
		if !errors.Is(err, ErrBacklog) {
			t.Fatalf("stalled prepare escaped emergency: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker was not released")
	}
	if !g0.wiped {
		t.Fatal("grandparent was not wiped after final lease release")
	}
	after := s.Snapshot()
	if after.Pending != 0 || after.InFlight != 0 || after.ReservedBytes != 0 ||
		after.PendingBytes != 0 {
		t.Fatalf("resources retained after emergency: %+v", after)
	}
}

// After the original grandparent is flushed, consecutive rotations must
// not falsely count already-wiped generations or retain backing-array refs.
func TestM162_RepeatedQueuedFlushingAndPruning(t *testing.T) {
	s := lab(t, 20, 128, 1)
	for i := 0; i < 10; i++ {
		tok, err := s.Prepare([]byte("q"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Rotate(); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		if err := s.Rotate(); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
		if _, err := s.Consume(tok); !errors.Is(err, ErrTicket) {
			t.Fatalf("stale ticket after %d rotations: %v", i, err)
		}
		if snap := s.Snapshot(); snap.Closed || snap.Pending != 0 || snap.PendingBytes != 0 {
			t.Fatalf("rotation %d left stale queue or stopped: %+v", i, snap)
		}
	}
}
