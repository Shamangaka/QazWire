//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// R5 deterministic interleavings on the UNMODIFIED klm16 (positive evidence).
// Only the package's own test hook (beforeQueue) is used to park a Prepare in
// the unlocked gap between admission and commit.
package klm16

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// parker parks the first n Prepare calls in the gap until released one by one.
type parker struct {
	mu      sync.Mutex
	left    int
	entered chan int
	gates   []chan struct{}
}

func park(s *labSession, n int) *parker {
	p := &parker{left: n, entered: make(chan int, n)}
	for i := 0; i < n; i++ {
		p.gates = append(p.gates, make(chan struct{}))
	}
	s.beforeQueue = func() {
		p.mu.Lock()
		if p.left == 0 {
			p.mu.Unlock()
			return
		}
		idx := n - p.left
		p.left--
		p.mu.Unlock()
		p.entered <- idx
		<-p.gates[idx]
	}
	return p
}

type prepResult struct {
	tok Ticket
	err error
}

func goPrepare(s *labSession, payload string) chan prepResult {
	out := make(chan prepResult, 1)
	go func() {
		tok, err := s.Prepare([]byte(payload))
		out <- prepResult{tok, err}
	}()
	return out
}

func deadline(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// Prepare parked in the gap / Stop / AwaitDestroyed: Await must not report
// destruction while the lease is held; the parked Prepare then fails closed.
func TestR5_C1_PrepareInGapVersusStopAndAwait(t *testing.T) {
	s := lab(t, 10, 64, 2)
	p := park(s, 1)
	res := goPrepare(s, "in gap")
	<-p.entered
	s.Stop()
	ctx, c := deadline(30 * time.Millisecond)
	if err := s.AwaitDestroyed(ctx); !errors.Is(err, ErrDeadline) {
		c()
		t.Fatalf("destruction confirmed under a held lease: %v", err)
	}
	c()
	if snap := s.Snapshot(); snap.InFlight != 1 || snap.ReservedBytes != 6 || snap.LiveKeys != 1 {
		t.Fatalf("reservation not visible: %+v", snap)
	}
	close(p.gates[0])
	r := <-res
	if !errors.Is(r.err, ErrClosed) {
		t.Fatalf("parked prepare after stop: %v", r.err)
	}
	ctx, c = deadline(time.Second)
	defer c()
	if err := s.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
	if snap := s.Snapshot(); snap.InFlight != 0 || snap.ReservedBytes != 0 || snap.LiveKeys != 0 {
		t.Fatalf("resources after destroy: %+v", snap)
	}
}

// Consume / Stop and Discard / Rotate.
func TestR5_C2_ConsumeStopAndDiscardRotate(t *testing.T) {
	s := lab(t, 10, 64, 2)
	a, _ := s.Prepare([]byte("a"))
	b, _ := s.Prepare([]byte("b"))
	g1 := s.current
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Discard(a); err != nil { // previous generation, still allowed
		t.Fatal(err)
	}
	if g1.wiped {
		t.Fatal("previous generation wiped while ticket b is queued")
	}
	if _, err := s.Consume(b); err != nil {
		t.Fatal(err)
	}
	if !g1.wiped {
		t.Fatal("previous generation not wiped after its last ticket")
	}
	c, _ := s.Prepare([]byte("c"))
	s.Stop()
	if _, err := s.Consume(c); !errors.Is(err, ErrClosed) {
		t.Fatalf("consume after stop: %v", err)
	}
	if err := s.Discard(c); !errors.Is(err, ErrTicket) {
		t.Fatalf("discard after stop: %v", err)
	}
}

// Poison / Rotate: a panic in the gap poisons; Rotate and Prepare fail with ErrPoisoned.
func TestR5_C3_PoisonVersusRotate(t *testing.T) {
	s := lab(t, 10, 64, 2)
	s.beforeQueue = func() { panic("synthetic") }
	if _, err := s.Prepare([]byte("x")); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("prepare: %v", err)
	}
	s.beforeQueue = nil
	if err := s.Rotate(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("rotate after poison: %v", err)
	}
	if _, err := s.Prepare([]byte("y")); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("prepare after poison: %v", err)
	}
	if snap := s.Snapshot(); snap.InFlight != 0 || snap.ReservedBytes != 0 {
		t.Fatalf("poison leaked a reservation: %+v", snap)
	}
}

// Several generations held at once by parked operations, consecutive
// rotations, then release: stale outputs are rejected and retried, every
// retired generation is wiped and pruned.
func TestR5_C4_SeveralPinnedGenerationsThenRelease(t *testing.T) {
	s := lab(t, 10, 64, 3)
	p := park(s, 2)
	r1 := goPrepare(s, "g1")
	<-p.entered
	if err := s.Rotate(); err != nil { // g2
		t.Fatal(err)
	}
	r2 := goPrepare(s, "g2")
	<-p.entered
	if err := s.Rotate(); err != nil { // g3: g1 discarded but pinned, g2 previous
		t.Fatal(err)
	}
	if err := s.Rotate(); err != nil { // g4: g1, g2 pinned by in-flight work
		t.Fatal(err)
	}
	// g1, g2 pinned by parked work; g3 (previous, no references) is wiped at
	// once by the last rotation; g4 is current.
	if live := s.Snapshot().LiveKeys; live != 3 {
		t.Fatalf("live generations = %d, want 3", live)
	}
	close(p.gates[0])
	close(p.gates[1])
	for _, r := range []chan prepResult{r1, r2} {
		res := <-r
		if res.err != nil {
			t.Fatal(res.err)
		}
		rec, err := s.Consume(res.tok)
		if err != nil || rec.Epoch != 4 {
			t.Fatalf("retry did not land on the current generation: %v %+v", err, rec)
		}
	}
	if snap := s.Snapshot(); snap.LiveKeys != 1 {
		t.Fatalf("retired generations not wiped: %+v", snap)
	}
	s.mu.Lock()
	n := len(s.generations)
	s.mu.Unlock()
	if n > 2 {
		t.Fatalf("wiped generations still registered: %d", n)
	}
}

// A hung operation keeps one generation alive forever; Go cannot reclaim it.
func TestR5_C5_HungOperationBlocksDestruction(t *testing.T) {
	v, _ := NewLabSession(10, 64, 2)
	s := v.(*labSession)
	p := park(s, 1)
	go func() { _, _ = s.Prepare([]byte("hung")) }()
	<-p.entered
	s.Stop()
	for i := 0; i < 3; i++ {
		ctx, c := deadline(20 * time.Millisecond)
		err := s.AwaitDestroyed(ctx)
		c()
		if !errors.Is(err, ErrDeadline) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	t.Logf("VERIFIED-in-test: a parked operation keeps destruction unconfirmed (ErrDeadline x3); only an external Stage D can end it")
	close(p.gates[0])
}
