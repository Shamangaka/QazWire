//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package klm16

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestM161_ReserveBeforeCopy makes the allocation gap deterministic:
// the first Prepare pauses after acquiring a lease, before copying its input.
// A second call must be denied before making another unbudgeted private copy.
func TestM161_ReserveBeforeCopy(t *testing.T) {
	s := lab(t, 100, 4, 3)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	s.beforeQueue = func() {
		entered <- struct{}{}
		<-release
	}
	result := make(chan error, 1)
	go func() {
		_, err := s.Prepare([]byte("abcd"))
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first worker never reached deterministic barrier")
	}
	snap := s.Snapshot()
	if snap.InFlight != 1 || snap.ReservedBytes != 4 || snap.Pending != 0 {
		t.Fatalf("copy gap not accounted: %+v", snap)
	}
	// Old M1.6 implementation would block inside the same scheduler hook,
	// allocating the second copy. The new one must fail before the hook.
	if _, err := s.Prepare([]byte("x")); !errors.Is(err, ErrBudget) {
		t.Fatalf("unaccounted second copy was admitted: %v", err)
	}
	s.Stop()
	close(release)
	if err := <-result; !errors.Is(err, ErrClosed) {
		t.Fatalf("blocked worker did not stop: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
	snap = s.Snapshot()
	if snap.InFlight != 0 || snap.ReservedBytes != 0 || snap.PendingBytes != 0 {
		t.Fatalf("reservation not released after abort: %+v", snap)
	}
}

func TestM161_ZeroLengthTicketsCannotEscapeCapacity(t *testing.T) {
	s := lab(t, 2*maxPendingTickets, 1, 3)
	tickets := make([]Ticket, 0, maxPendingTickets)
	for i := 0; i < maxPendingTickets; i++ {
		p, err := s.Prepare(nil)
		if err != nil {
			t.Fatalf("ticket %d: %v", i, err)
		}
		tickets = append(tickets, p)
	}
	if _, err := s.Prepare(nil); !errors.Is(err, ErrCapacity) {
		t.Fatalf("unbounded zero-byte tickets accepted: %v", err)
	}
	snap := s.Snapshot()
	if snap.Pending != maxPendingTickets || snap.PendingBytes != 0 {
		t.Fatalf("incorrect ticket accounting: %+v", snap)
	}
	for _, p := range tickets {
		if err := s.Discard(p); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := s.Prepare(nil); err != nil {
		t.Fatalf("capacity did not recover: %v", err)
	} else if err := s.Discard(p); err != nil {
		t.Fatal(err)
	}
}

func TestM161_InFlightOperationCountBound(t *testing.T) {
	s := lab(t, 2*maxInFlightPrepares, 4096, 3)
	entered := make(chan struct{}, maxInFlightPrepares)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	s.beforeQueue = func() {
		entered <- struct{}{}
		<-release
	}
	var wg sync.WaitGroup
	failures := make(chan error, maxInFlightPrepares)
	for i := 0; i < maxInFlightPrepares; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Prepare([]byte("x"))
			if err != nil && !errors.Is(err, ErrClosed) {
				failures <- err
			}
		}()
	}
	for i := 0; i < maxInFlightPrepares; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			s.Stop()
			t.Fatalf("only %d of %d operations admitted", i, maxInFlightPrepares)
		}
	}
	if got := s.Snapshot(); got.InFlight != maxInFlightPrepares {
		t.Fatalf("wrong admitted operations: %+v", got)
	}
	if _, err := s.Prepare([]byte("x")); !errors.Is(err, ErrInFlight) {
		t.Fatalf("no in-flight cap: %v", err)
	}
	s.Stop()
	close(release)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("worker failed: %v", err)
	}
	if got := s.Snapshot(); got.InFlight != 0 || got.ReservedBytes != 0 {
		t.Fatalf("retained in-flight reservation: %+v", got)
	}
}

func TestM161_PanicReleasesReservationAndPoisons(t *testing.T) {
	s := lab(t, 12, 12, 2)
	s.beforeQueue = func() { panic("injected synthetic operation crash") }
	if _, err := s.Prepare([]byte("message")); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("panic did not fail closed: %v", err)
	}
	got := s.Snapshot()
	if got.InFlight != 0 || got.ReservedBytes != 0 || got.PendingBytes != 0 || !got.Closed || !got.Faulted {
		t.Fatalf("resource leak after panic: %+v", got)
	}
	if err := s.Rotate(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("rotation reopened poisoned owner: %v", err)
	}
}

func TestM161_LinearizedScheduleBeforeAndAfterStop(t *testing.T) {
	// Check both deterministic partial orders, not probabilistic scheduler luck:
	// A: prepare commits, consume, stop; B: stop before prepare commits.
	for _, stopFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "consume-before-stop", true: "stop-before-commit"}[stopFirst], func(t *testing.T) {
			s := lab(t, 4, 512, 3)
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			s.beforeQueue = func() {
				entered <- struct{}{}
				<-release
			}
			type result struct {
				ticket Ticket
				err    error
			}
			finished := make(chan result, 1)
			go func() {
				p, err := s.Prepare([]byte("protected synthetic"))
				finished <- result{p, err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				close(release)
				t.Fatal("prepare not admitted")
			}
			if stopFirst {
				s.Stop()
			}
			close(release)
			select {
			case r := <-finished:
				if stopFirst {
					if !errors.Is(r.err, ErrClosed) || r.ticket.state != nil {
						t.Fatalf("packet escaped stop: %+v", r)
					}
				} else {
					if r.err != nil {
						t.Fatal(r.err)
					}
					if _, err := s.Consume(r.ticket); err != nil {
						t.Fatal(err)
					}
					s.Stop()
				}
			case <-time.After(time.Second):
				t.Fatal("blocked operation did not complete")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := s.AwaitDestroyed(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
