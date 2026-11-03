//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package klm16

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func lab(t *testing.T, tickets, bytes uint64, pinned int) *Session {
	t.Helper()
	s, err := NewLabSession(tickets, bytes, pinned)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Stop()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.AwaitDestroyed(ctx); err != nil {
			t.Errorf("synthetic destroy did not finish: %v", err)
		}
	})
	return s
}

func TestM16_ExclusiveMaterialAndEpochPerRotation(t *testing.T) {
	s := lab(t, 8, 4096, 3)
	seen := map[uint64]bool{}
	for round := uint64(1); round <= 12; round++ {
		g := s.current
		if g.epoch != round {
			t.Fatalf("epoch %d, expected %d", g.epoch, round)
		}
		if seen[g.material.id] {
			t.Fatalf("material identity repeated: %d", g.material.id)
		}
		seen[g.material.id] = true
		if round < 12 {
			if err := s.Rotate(); err != nil {
				t.Fatal(err)
			}
		}
	}
	// No arbitrary external provider or key buffer is accepted by the public
	// constructor; this test also checks the ONLY material minting path.
	if len(seen) != 12 {
		t.Fatal("missing generation identities")
	}
}

func TestM16_ProcessLocalSessionsSeparateIdentities(t *testing.T) {
	a := lab(t, 4, 1024, 2)
	b := lab(t, 4, 1024, 2)
	if a.id == b.id || a.current.material.id == b.current.material.id {
		t.Fatal("two sessions reused a local session or material identity")
	}
	pa, err := a.Prepare([]byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := b.Prepare([]byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	ra, err := a.Consume(pa)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := b.Consume(pb)
	if err != nil {
		t.Fatal(err)
	}
	if ra.SessionID == rb.SessionID || ra.MaterialID == rb.MaterialID {
		t.Fatal("same identity in two unrelated sessions")
	}
}

func TestM16_OneShotTicketCopiesForeignAndInputIsolation(t *testing.T) {
	s := lab(t, 5, 1024, 2)
	other := lab(t, 5, 1024, 2)
	input := []byte("immutable-after-return")
	p, err := s.Prepare(input)
	if err != nil {
		t.Fatal(err)
	}
	pcopy := p // A value copy must NOT create a new spendable ticket.
	if _, err := other.Consume(p); !errors.Is(err, ErrTicket) {
		t.Fatalf("foreign consumption accepted: %v", err)
	}
	for i := range input {
		input[i] = 'x'
	}
	r, err := s.Consume(pcopy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Data, []byte("immutable-after-return")) {
		t.Fatalf("caller modified queued payload: %q", r.Data)
	}
	if _, err := s.Consume(p); !errors.Is(err, ErrTicket) {
		t.Fatalf("ticket replay accepted: %v", err)
	}
	if err := s.Discard(p); !errors.Is(err, ErrTicket) {
		t.Fatalf("double discard accepted: %v", err)
	}
	if _, err := s.Consume(Ticket{}); !errors.Is(err, ErrTicket) {
		t.Fatalf("nil ticket accepted: %v", err)
	}
}

func TestM16_CounterDomainMustIncludeMaterialAndEpoch(t *testing.T) {
	s := lab(t, 1, 1024, 2)
	first, err := s.Prepare([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	r0, err := s.Consume(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prepare([]byte("second")); !errors.Is(err, ErrTicketExhausted) {
		t.Fatalf("counter exhaustion not enforced: %v", err)
	}
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	second, err := s.Prepare([]byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	r1, err := s.Consume(second)
	if err != nil {
		t.Fatal(err)
	}
	// Sequence restarts by DESIGN: only the material/epoch identity prevents
	// collision in this SYNTHETIC record. This is NOT a real AEAD nonce rule.
	if r0.Sequence != 0 || r1.Sequence != 0 {
		t.Fatalf("unexpected first ticket per generation: %d, %d", r0.Sequence, r1.Sequence)
	}
	if r0.MaterialID == r1.MaterialID || r0.Epoch == r1.Epoch {
		t.Fatalf("generation identity reused: %+v, %+v", r0, r1)
	}
	if err := s.Discard(second); !errors.Is(err, ErrTicket) {
		t.Fatalf("already consumed ticket accepted: %v", err)
	}
}

func TestM16_QueueByteBudgetAndOwnership(t *testing.T) {
	s := lab(t, 100, 6, 2)
	a, err := s.Prepare([]byte("1234"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prepare([]byte("abc")); !errors.Is(err, ErrBudget) {
		t.Fatalf("queue over budget: %v", err)
	}
	if got := s.Snapshot().PendingBytes; got != 4 {
		t.Fatalf("pending bytes=%d, want 4", got)
	}
	if err := s.Discard(a); err != nil {
		t.Fatal(err)
	}
	if got := s.Snapshot().PendingBytes; got != 0 {
		t.Fatalf("bytes retained after discard: %d", got)
	}
	if _, err := s.Prepare([]byte("1234567")); !errors.Is(err, ErrBudget) {
		t.Fatalf("oversized input accepted: %v", err)
	}
}

func TestM16_SecondRotationDropsGrandparentQueue(t *testing.T) {
	s := lab(t, 10, 1024, 3)
	packet, err := s.Prepare([]byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	g0 := packet.state.gen
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	if g0.wiped {
		t.Fatal("old generation wiped while its packet was pending")
	}
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(packet); !errors.Is(err, ErrTicket) {
		t.Fatalf("grandparent packet was admitted: %v", err)
	}
	if !g0.wiped || s.Snapshot().Pending != 0 {
		t.Fatal("stale queue did not release/erase retired generation")
	}
}

func TestM16_GrandparentInFlightRetriesCurrent(t *testing.T) {
	s := lab(t, 12, 1024, 3)
	first := s.current
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	s.beforeQueue = func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	type result struct {
		ticket Ticket
		err    error
	}
	done := make(chan result, 1)
	go func() {
		tok, err := s.Prepare([]byte("in-flight"))
		done <- result{tok, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("test worker did not reach scheduler hook")
	}
	if err := s.Rotate(); err != nil {
		close(release)
		t.Fatal(err)
	}
	if err := s.Rotate(); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.ticket.state.gen == first || r.ticket.state.gen != s.current {
			t.Fatal("stale generation escaped the second rotation")
		}
		rec, err := s.Consume(r.ticket)
		if err != nil || rec.Epoch != 3 {
			t.Fatalf("unexpected current-generation record: %v, %+v", err, rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prepare did not finish after release")
	}
	if !first.wiped {
		t.Fatal("old generation still reachable after release")
	}
}

func TestM16_StopAwaitsHeldReferenceWithDeadline(t *testing.T) {
	s := lab(t, 4, 1024, 3)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	s.beforeQueue = func() {
		entered <- struct{}{}
		<-release
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.Prepare([]byte("blocked"))
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("worker never entered hook")
	}
	s.Stop()
	if err := s.AwaitDestroyed(context.Background()); !errors.Is(err, ErrDeadlineRequired) {
		t.Fatalf("await without deadline: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if err := s.AwaitDestroyed(ctx); !errors.Is(err, ErrDeadline) {
		t.Fatalf("hung operation was incorrectly declared wiped: %v", err)
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("stopped prepare returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not leave after release")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := s.AwaitDestroyed(ctx2); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().LiveKeys != 0 {
		t.Fatal("generation remains live after successful stop")
	}
}

func TestM16_PanickingOperationPoisonsAndFences(t *testing.T) {
	s := lab(t, 4, 1024, 2)
	s.beforeQueue = func() { panic("synthetic fault injection") }
	if _, err := s.Prepare([]byte("panic")); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("panic not converted to poison: %v", err)
	}
	if !errors.Is(s.Fault(), ErrPoisoned) {
		t.Fatalf("fault not latched: %v", s.Fault())
	}
	if err := s.Rotate(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("rotation admitted after poison: %v", err)
	}
	if _, err := s.Prepare([]byte("after")); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("prepare admitted after poison: %v", err)
	}
	if !s.Snapshot().Closed {
		t.Fatal("poison did not close session")
	}
}

func TestM16_BacklogFailClosedAndNoErasureUnderLease(t *testing.T) {
	s := lab(t, 20, 4096, 1)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	s.beforeQueue = func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	done := make(chan error, 1)
	old := s.current
	go func() {
		_, err := s.Prepare([]byte("stalled"))
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("test operation was not admitted")
	}
	if err := s.Rotate(); err != nil {
		close(release)
		t.Fatal(err)
	}
	// First stale generation may be pinned; second rotation must fail-closed
	// rather than manufacture yet another live generation.
	if err := s.Rotate(); !errors.Is(err, ErrBacklog) {
		close(release)
		t.Fatalf("expected backlog emergency: %v", err)
	}
	if old.wiped {
		close(release)
		t.Fatal("material erased while operation lease was held")
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, ErrBacklog) {
			t.Fatalf("worker returned after emergency: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not finish")
	}
	if !old.wiped {
		t.Fatal("material never wiped after final release")
	}
}

func TestM16_PruneDoesNotRetainOldKeysInCapacity(t *testing.T) {
	s := lab(t, 10, 4096, 3)
	var old []*generation
	for i := 0; i < 15; i++ {
		old = append(old, s.current)
		if err := s.Rotate(); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	kept := make(map[*generation]bool)
	for _, g := range s.generations {
		kept[g] = true
	}
	ghost := 0
	all := s.generations[:cap(s.generations)]
	for i := len(s.generations); i < cap(s.generations); i++ {
		if all[i] != nil && !kept[all[i]] {
			ghost++
		}
	}
	s.mu.Unlock()
	if ghost != 0 {
		t.Fatalf("%d erased generations retained through backing capacity", ghost)
	}
	for _, g := range old[:len(old)-1] {
		if !g.wiped {
			t.Fatal("old no-reference generation not wiped")
		}
	}
}

func TestM16_EpochOverflowFailClosed(t *testing.T) {
	s := lab(t, 2, 128, 1)
	s.mu.Lock()
	s.current.epoch = math.MaxUint64
	s.mu.Unlock()
	if err := s.Rotate(); !errors.Is(err, ErrEpochExhausted) {
		t.Fatalf("epoch overflow accepted: %v", err)
	}
	if !s.Snapshot().Closed {
		t.Fatal("overflow did not trigger stop")
	}
}

func TestM16_ConcurrentRotatePrepareConsumeDiscard(t *testing.T) {
	s := lab(t, 10000, 1<<20, 200)
	var wg sync.WaitGroup
	var created atomic.Uint64
	workers := 6
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 120; i++ {
				p, err := s.Prepare([]byte("synthetic"))
				if err != nil {
					switch {
					case errors.Is(err, ErrRotated),
						errors.Is(err, ErrClosed),
						errors.Is(err, ErrBacklog):
						return
					default:
						t.Errorf("unexpected prepare error: %v", err)
						return
					}
				}
				if i%3 == 0 {
					if err := s.Discard(p); err != nil && !errors.Is(err, ErrTicket) {
						t.Errorf("unexpected discard error: %v", err)
					}
				} else {
					if _, err := s.Consume(p); err != nil && !errors.Is(err, ErrTicket) {
						t.Errorf("unexpected consume error: %v", err)
					}
				}
				created.Add(1)
			}
		}()
	}
	for i := 0; i < 40; i++ {
		if err := s.Rotate(); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	wg.Wait()
	if created.Load() == 0 {
		t.Fatal("no synthetic operations completed")
	}
	if snapshot := s.Snapshot(); snapshot.PendingBytes != 0 {
		t.Fatalf("bytes still queued: %+v", snapshot)
	}
}
