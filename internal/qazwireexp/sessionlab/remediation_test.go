//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package sessionlab

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type remediationProcessor struct {
	action int
	wipes  atomic.Int64
}

func (p *remediationProcessor) process(_ uint64, payload []byte) ([]byte, error) {
	if p.action == 1 {
		panic("synthetic process panic")
	}
	if p.action == 2 {
		return nil, errors.New("synthetic process error")
	}
	return append([]byte(nil), payload...), nil
}
func (p *remediationProcessor) wipe() {
	p.wipes.Add(1)
	if p.action == 3 {
		panic("synthetic wipe panic")
	}
}

type remediationSink struct {
	count   atomic.Int64
	explode bool
}

func (w *remediationSink) send(_ uint64, _ []byte) error {
	if w.explode {
		panic("synthetic wire panic")
	}
	w.count.Add(1)
	return nil
}

func deadlineCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 2*time.Second)
}

func TestM151DuplicateAndForeignTicket(t *testing.T) {
	w1, w2 := &remediationSink{}, &remediationSink{}
	p := &remediationProcessor{}
	s1, _ := newSession(p, w1, 100)
	s2, _ := newSession(&remediationProcessor{}, w2, 100)
	pkt, err := s1.prepare([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.dispatch(pkt); !errors.Is(err, errTicket) {
		t.Fatalf("foreign ticket: %v", err)
	}
	if err := s1.dispatch(pkt); err != nil {
		t.Fatal(err)
	}
	if err := s1.dispatch(pkt); !errors.Is(err, errTicket) {
		t.Fatalf("ticket reused: %v", err)
	}
	if w1.count.Load() != 1 || w2.count.Load() != 0 {
		t.Fatal("duplicate or foreign send")
	}
	s1.beginEmergency()
	s2.beginEmergency()
	ctx, cancel := deadlineCtx(t)
	defer cancel()
	if err := s1.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s2.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestM151ExplicitDiscardAndEmergencyFlush(t *testing.T) {
	p := &remediationProcessor{}
	s, _ := newSession(p, &remediationSink{}, 10)
	a, _ := s.prepare([]byte{7})
	b, _ := s.prepare([]byte{8})
	s.discard(a)
	s.discard(a) // idempotent
	if err := s.dispatch(a); !errors.Is(err, errTicket) {
		t.Fatalf("discarded dispatched: %v", err)
	}
	s.beginEmergency() // must release un-dispatched b
	if err := s.dispatch(b); !errors.Is(err, errClosed) {
		t.Fatalf("post-close dispatch: %v", err)
	}
	ctx, cancel := deadlineCtx(t)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if p.wipes.Load() != 1 {
		t.Fatalf("wipes = %d", p.wipes.Load())
	}
}

func TestM151RotationPinsPendingPacket(t *testing.T) {
	old := &remediationProcessor{}
	fresh := &remediationProcessor{}
	sink := &remediationSink{}
	s, _ := newSession(old, sink, 10)
	pkt, err := s.prepare([]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.rotate(fresh, 10); err != nil {
		t.Fatal(err)
	}
	if old.wipes.Load() != 0 {
		t.Fatal("old key wiped while ticket queued")
	}
	if err := s.dispatch(pkt); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := deadlineCtx(t)
	defer cancel()
	s.mu.RLock()
	kold := s.keys[0]
	s.mu.RUnlock()
	if err := kold.gate.await(ctx); err != nil {
		t.Fatal(err)
	}
	if old.wipes.Load() != 1 {
		t.Fatal("old key never wiped")
	}
	s.beginEmergency()
	if err := s.rotate(&remediationProcessor{}, 1); !errors.Is(err, errClosed) {
		t.Fatalf("rotation after emergency: %v", err)
	}
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if fresh.wipes.Load() != 1 {
		t.Fatal("new key never wiped")
	}
}

func TestM151ProviderPanicPoisonsSession(t *testing.T) {
	for _, mode := range []int{1, 2} {
		p := &remediationProcessor{action: mode}
		s, _ := newSession(p, &remediationSink{}, 10)
		if _, err := s.prepare([]byte{1}); !errors.Is(err, errProviderFault) {
			t.Fatalf("mode %d: %v", mode, err)
		}
		if _, err := s.prepare(nil); !errors.Is(err, errClosed) {
			t.Fatalf("mode %d: session not closed: %v", mode, err)
		}
		ctx, cancel := deadlineCtx(t)
		if err := s.awaitDrained(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
		if p.wipes.Load() != 1 {
			t.Fatal("incorrect wipe count")
		}
	}
}

func TestM151WipePanicIsNotSuccess(t *testing.T) {
	p := &remediationProcessor{action: 3}
	s, _ := newSession(p, &remediationSink{}, 10)
	s.beginEmergency()
	ctx, cancel := deadlineCtx(t)
	defer cancel()
	if err := s.awaitDrained(ctx); !errors.Is(err, errWipeFailed) {
		t.Fatalf("false wipe success: %v", err)
	}
}

func TestM151DeadlineRequiredAndAwaitDoesNotClose(t *testing.T) {
	s, _ := newSession(&remediationProcessor{}, &remediationSink{}, 10)
	if err := s.awaitDrained(context.Background()); !errors.Is(err, errNoDeadline) {
		t.Fatal(err)
	}
	ctx, cancel := deadlineCtx(t)
	defer cancel()
	if err := s.awaitDrained(ctx); !errors.Is(err, errInvalid) {
		t.Fatalf("await implicitly closed: %v", err)
	}
	if _, err := s.prepare([]byte{1}); err != nil {
		t.Fatal(err)
	} // pending flushed during shutdown
	s.beginEmergency()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestM151UnpairedReleaseFailsWithoutCorruption(t *testing.T) {
	g := newGate(func() {})
	func() {
		defer func() {
			if recover() == nil {
				t.Error("missing panic")
			}
		}()
		g.leave()
	}()
	if g.state.Load() != 0 {
		t.Fatal("corrupted state")
	}
	g.beginClose()
	ctx, cancel := deadlineCtx(t)
	defer cancel()
	if err := g.await(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestM151ConcurrentTicketClaims(t *testing.T) {
	p := &remediationProcessor{}
	w := &remediationSink{}
	s, _ := newSession(p, w, 200)
	pkt, err := s.prepare([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.dispatch(pkt) == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || w.count.Load() != 1 {
		t.Fatalf("double claim ok=%d sends=%d", ok.Load(), w.count.Load())
	}
	s.beginEmergency()
	ctx, cancel := deadlineCtx(t)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestM151SyntheticSinkPanicClosesSession(t *testing.T) {
	s, _ := newSession(&remediationProcessor{}, &remediationSink{explode: true}, 10)
	pkt, err := s.prepare([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.dispatch(pkt); !errors.Is(err, errProviderFault) {
		t.Fatalf("sink panic: %v", err)
	}
	if _, err := s.prepare(nil); !errors.Is(err, errClosed) {
		t.Fatal(err)
	}
	ctx, cancel := deadlineCtx(t)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
}
