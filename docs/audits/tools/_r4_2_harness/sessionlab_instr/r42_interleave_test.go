//go:build qazwire_exp

// Deterministic interleavings on an instrumented copy of session.go (only
// r42hook calls inserted; see make_instrumented.py). session_test.go is copied
// alongside for its fakeProcessor/fakeWire test doubles.
package sessionlab

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pausePoint struct {
	arrived, resume chan struct{}
	once            sync.Once
}

func pauseAt(t *testing.T, name string) *pausePoint {
	pp := &pausePoint{arrived: make(chan struct{}), resume: make(chan struct{})}
	f := func(p string) {
		if p == name {
			pp.once.Do(func() { close(pp.arrived); <-pp.resume })
		}
	}
	r42hookFn.Store(&f)
	t.Cleanup(func() { r42hookFn.Store(nil) })
	return pp
}

// R42-07: a packet sealed on the PREVIOUS generation is burnt by a second rotation
// between seal and the fence; prepare returns errClosed without retry while the
// session is open (availability, not safety).
func TestR42I_07_SecondRotationBetweenSealAndFence(t *testing.T) {
	p0 := &fakeProcessor{started: make(chan struct{}, 1), release: make(chan struct{})}
	s, _ := newSession(p0, &fakeWire{}, 10)
	pp := pauseAt(t, "prepare:beforeLock")
	res := make(chan error, 1)
	go func() { _, err := s.prepare([]byte("x")); res <- err }()
	<-p0.started
	if err := s.rotate(&fakeProcessor{}, 10); err != nil { // k0 -> previous (planned retire)
		t.Fatal(err)
	}
	close(p0.release)                                      // seal on k0 completes: discardFlag not set -> output kept
	<-pp.arrived                                           // prepare holds a valid k0 packet, before the fence
	if err := s.rotate(&fakeProcessor{}, 10); err != nil { // k0 -> grandparent
		t.Fatal(err)
	}
	close(pp.resume)
	err := <-res
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if !errors.Is(err, errClosed) || closed {
		t.Fatalf("not reproduced: %v closed=%v", err, closed)
	}
	t.Log("CONFIRMED R42-07 (LOW): second rotation between seal and fence -> packet burnt, prepare returns errClosed without retry although the session is open")
}

// R42-06 (natural interleaving): after the wipe-failure latch and before the
// asynchronous emergency runs, a queued packet is still dispatched.
type failWipeProc struct {
	providerClaim
}

func (*failWipeProc) process(_ uint64, b []byte) ([]byte, error) {
	return append([]byte(nil), b...), nil
}
func (*failWipeProc) wipe() { panic("wipe") }

type countingWire struct{ n atomic.Int64 }

func (w *countingWire) send(uint64, []byte) error { w.n.Add(1); return nil }

func TestR42I_06_DispatchAfterLatchBeforeEmergency(t *testing.T) {
	w := &countingWire{}
	s, _ := newSession(&failWipeProc{}, w, 10)
	pp := pauseAt(t, "onFail:latched")
	if err := s.rotate(&fakeProcessor{}, 10); err != nil { // k0 retired, refs 0 -> wipe panics
		t.Fatal(err)
	}
	<-pp.arrived // fault latched, emergency not yet started
	pkt, perr := s.prepare([]byte{1})
	if !errors.Is(perr, errClosed) {
		t.Fatalf("prepare not fenced: %v", perr)
	}
	_ = pkt
	// a packet queued BEFORE the failure (on k1) is still dispatchable:
	close(pp.resume)
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
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
	if err := s.awaitDrained(ctx); !errors.Is(err, errWipeFailed) {
		t.Fatalf("awaitDrained: %v", err)
	}
	t.Log("CONFIRMED R42-06: the latch fences prepare immediately; emergency (egress fence) follows asynchronously; awaitDrained reports errWipeFailed")
}

func TestR42I_06b_QueuedPacketSentInsideLatchWindow(t *testing.T) {
	w := &countingWire{}
	s, _ := newSession(&failWipeProc{}, w, 10)
	a, err := s.prepare([]byte{1}) // packet A on k0 (failing wipe) pins k0
	if err != nil {
		t.Fatal(err)
	}
	if err := s.rotate(&fakeProcessor{}, 10); err != nil { // k1 current, k0 previous (refs=1)
		t.Fatal(err)
	}
	b, err := s.prepare([]byte{2}) // packet B on k1
	if err != nil {
		t.Fatal(err)
	}
	pp := pauseAt(t, "onFail:latched")
	s.discard(a) // k0 refs -> 0 -> finish -> wipe panics -> latch, emergency not yet started
	<-pp.arrived
	if _, f := s.faultState(); !f {
		t.Fatal("latch not set")
	}
	derr := s.dispatch(b)
	sent := w.n.Load()
	close(pp.resume)
	if derr != nil || sent != 1 {
		t.Fatalf("not reproduced: %v sent=%d", derr, sent)
	}
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
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
	if err := s.awaitDrained(ctx); !errors.Is(err, errWipeFailed) {
		t.Fatalf("awaitDrained: %v", err)
	}
	t.Log("CONFIRMED R42-06 (LOW): WIPE_FAILED latched, emergency not yet started: a queued packet of another generation was sent (dispatch is fenced only by the asynchronous egress close)")
}
