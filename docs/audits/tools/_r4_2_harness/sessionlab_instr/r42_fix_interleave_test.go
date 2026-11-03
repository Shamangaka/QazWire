//go:build qazwire_exp

// R4.2 fix interleavings on the instrumented PATCHED copy.
package sessionlab

import (
	"context"
	"errors"
	"testing"
	"time"
)

// FIX R42-07: the same interleaving as TestR42I_07 now retries on the current generation.
func TestR42IFix_07_SecondRotationBetweenSealAndFenceRetries(t *testing.T) {
	p0 := &fakeProcessor{started: make(chan struct{}, 1), release: make(chan struct{})}
	w := &countingWire{}
	s, _ := newSession(p0, w, 10)
	pp := pauseAt(t, "prepare:beforeLock")
	type res struct {
		pkt packet
		err error
	}
	out := make(chan res, 1)
	go func() { p, err := s.prepare([]byte("x")); out <- res{p, err} }()
	<-p0.started
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	close(p0.release)
	<-pp.arrived
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	close(pp.resume)
	r := <-out
	if r.err != nil {
		t.Fatalf("prepare did not retry: %v", r.err)
	}
	s.mu.RLock()
	owner, cur := r.pkt.guard.owner, s.k
	s.mu.RUnlock()
	if owner != cur {
		t.Fatal("retried packet is not on the current generation")
	}
	if err := s.dispatch(r.pkt); err != nil || w.n.Load() != 1 {
		t.Fatalf("dispatch: %v sent=%d", err, w.n.Load())
	}
}

// FIX R42-06: the same interleaving as TestR42I_06b; egress is fenced before the latch is published.
func TestR42IFix_06b_NoDispatchInsideLatchWindow(t *testing.T) {
	w := &countingWire{}
	s, _ := newSession(&failWipeProc{}, w, 10)
	a, err := s.prepare([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	b, err := s.prepare([]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	pp := pauseAt(t, "onFail:latched")
	s.discard(a)
	<-pp.arrived
	derr := s.dispatch(b)
	sent := w.n.Load()
	close(pp.resume)
	if !errors.Is(derr, errClosed) || sent != 0 {
		t.Fatalf("dispatch inside latch window: %v sent=%d", derr, sent)
	}
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.RLock()
		closed := s.closed
		s.mu.RUnlock()
		if closed || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	if err := s.awaitDrained(ctx); !errors.Is(err, errWipeFailed) {
		t.Fatalf("awaitDrained: %v", err)
	}
}
