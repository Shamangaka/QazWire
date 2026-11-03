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

type fakeProcessor struct {
	providerClaim
	started       chan struct{}
	release       chan struct{}
	wipeStarted   chan struct{}
	wipeRelease   chan struct{}
	active        atomic.Int64
	wipeCount     atomic.Int64
	prematureWipe atomic.Bool
	onProcess     func()
}

func (p *fakeProcessor) process(_ uint64, b []byte) ([]byte, error) {
	p.active.Add(1)
	defer p.active.Add(-1)
	if p.started != nil {
		select {
		case p.started <- struct{}{}:
		default:
		}
	}
	if p.onProcess != nil {
		p.onProcess()
	}
	if p.release != nil {
		<-p.release
	}
	return append([]byte(nil), b...), nil
}
func (p *fakeProcessor) wipe() {
	if p.active.Load() != 0 {
		p.prematureWipe.Store(true)
	}
	p.wipeCount.Add(1)
	if p.wipeStarted != nil {
		close(p.wipeStarted)
	}
	if p.wipeRelease != nil {
		<-p.wipeRelease
	}
}

type fakeWire struct {
	started chan struct{}
	release chan struct{}
	sends   atomic.Uint64
}

func (w *fakeWire) send(_ uint64, _ []byte) error {
	w.sends.Add(1)
	if w.started != nil {
		select {
		case w.started <- struct{}{}:
		default:
		}
	}
	if w.release != nil {
		<-w.release
	}
	return nil
}

func TestPreparedPacketNeverDispatchedAfterEmergency(t *testing.T) {
	p, w := &fakeProcessor{}, &fakeWire{}
	s, err := newSession(p, w, 10)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := s.prepare([]byte("fake plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	s.beginEmergency()
	if err := s.dispatch(prepared); !errors.Is(err, errClosed) {
		t.Fatalf("queued packet leaked: %v", err)
	}
	if w.sends.Load() != 0 {
		t.Fatal("network write admitted after emergency")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if p.wipeCount.Load() != 1 || p.prematureWipe.Load() {
		t.Fatal("wrong wipe lifecycle")
	}
}

func TestBlockedProcessorEmergencyDeadlineAndDrain(t *testing.T) {
	p := &fakeProcessor{started: make(chan struct{}, 1), release: make(chan struct{})}
	s, _ := newSession(p, &fakeWire{}, 100)
	finished := make(chan error, 1)
	go func() { _, err := s.prepare([]byte{1, 2, 3}); finished <- err }()
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("not entered")
	}
	begun := make(chan struct{})
	go func() { s.beginEmergency(); close(begun) }()
	select {
	case <-begun:
	case <-time.After(time.Second):
		t.Fatal("beginEmergency blocked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.awaitDrained(ctx); !errors.Is(err, errDeadline) {
		t.Fatalf("wanted deadline: %v", err)
	}
	if p.wipeCount.Load() != 0 {
		t.Fatal("wiped while operation in flight")
	}
	close(p.release)
	select {
	case err := <-finished:
		if !errors.Is(err, errClosed) {
			t.Fatalf("result not discarded: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("processor stuck")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := s.awaitDrained(ctx2); err != nil {
		t.Fatal(err)
	}
	if p.wipeCount.Load() != 1 || p.prematureWipe.Load() {
		t.Fatal("wipe count or ordering violation")
	}
}

func TestInFlightWireDrainedBeforeCompletion(t *testing.T) {
	w := &fakeWire{started: make(chan struct{}, 1), release: make(chan struct{})}
	p := &fakeProcessor{}
	s, _ := newSession(p, w, 100)
	rec, err := s.prepare([]byte("dummy"))
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { sent <- s.dispatch(rec) }()
	select {
	case <-w.started:
	case <-time.After(time.Second):
		t.Fatal("send never began")
	}
	s.beginEmergency()
	if err := s.dispatch(rec); !errors.Is(err, errClosed) {
		t.Fatalf("second send admitted: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.awaitDrained(ctx); !errors.Is(err, errDeadline) {
		t.Fatalf("send not drained, expected timeout: %v", err)
	}
	close(w.release)
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("send stuck")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := s.awaitDrained(ctx2); err != nil {
		t.Fatal(err)
	}
	if w.sends.Load() != 1 {
		t.Fatalf("writes=%d", w.sends.Load())
	}
}

func TestNoCounterReuseUnderContention(t *testing.T) {
	p := &fakeProcessor{}
	s, _ := newSession(p, &fakeWire{}, 2000)
	const workers = 16
	const iterations = 200
	tickets := make(chan uint64, 2000)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				r, err := s.prepare([]byte{7})
				if err == nil {
					tickets <- r.ticket
				} else if !errors.Is(err, errExhausted) {
					t.Errorf("error %v", err)
				}
			}
		}()
	}
	wg.Wait()
	close(tickets)
	seen := make(map[uint64]bool)
	for ticket := range tickets {
		if seen[ticket] {
			t.Fatalf("duplicate %d", ticket)
		}
		seen[ticket] = true
	}
	if len(seen) != 2000 {
		t.Fatalf("got %d tickets", len(seen))
	}
	if s.k.next.Load() != 2000 {
		t.Fatal("counter overrun")
	}
	s.beginEmergency()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentShutdownClaimsWipeOnlyOnce(t *testing.T) {
	for round := 0; round < 50; round++ {
		p := &fakeProcessor{}
		s, _ := newSession(p, &fakeWire{}, 10000)
		var wg sync.WaitGroup
		for j := 0; j < 16; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := 0; n < 50; n++ {
					_, _ = s.prepare([]byte{2})
				}
			}()
		}
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() { defer wg.Done(); s.beginEmergency() }()
		}
		wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := s.awaitDrained(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		if p.wipeCount.Load() != 1 || p.prematureWipe.Load() {
			t.Fatalf("round %d wipe wrong", round)
		}
	}
}

func TestWipeHangNeverReportsSuccess(t *testing.T) {
	p := &fakeProcessor{wipeStarted: make(chan struct{}), wipeRelease: make(chan struct{})}
	s, _ := newSession(p, &fakeWire{}, 10)
	s.beginEmergency()
	select {
	case <-p.wipeStarted:
	case <-time.After(time.Second):
		t.Fatal("wipe did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.awaitDrained(ctx); !errors.Is(err, errDeadline) {
		t.Fatalf("false wipe success: %v", err)
	}
	close(p.wipeRelease)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := s.awaitDrained(ctx2); err != nil {
		t.Fatal(err)
	}
}

func TestEmergencyCalledFromProcessorDoesNotSelfDeadlock(t *testing.T) {
	p := &fakeProcessor{}
	s, _ := newSession(p, &fakeWire{}, 10)
	p.onProcess = s.beginEmergency
	if _, err := s.prepare([]byte{3}); !errors.Is(err, errClosed) {
		t.Fatalf("no early close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTypedNilDependencyAndInvalidConfig(t *testing.T) {
	var p *fakeProcessor
	var w *fakeWire
	if s, err := newSession(p, &fakeWire{}, 1); s != nil || !errors.Is(err, errInvalid) {
		t.Fatalf("typed nil processor accepted: %v", err)
	}
	if s, err := newSession(&fakeProcessor{}, w, 1); s != nil || !errors.Is(err, errInvalid) {
		t.Fatalf("typed nil sink accepted: %v", err)
	}
	if s, err := newSession(&fakeProcessor{}, &fakeWire{}, 0); s != nil || !errors.Is(err, errInvalid) {
		t.Fatalf("zero limit accepted: %v", err)
	}
}
