//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package keylab

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type probeProcessor struct {
	started    chan struct{}
	unblock    chan struct{}
	active     atomic.Int64
	wipeCount  atomic.Int64
	unsafeWipe atomic.Bool
}

func (p *probeProcessor) process(_ uint64, in []byte) ([]byte, error) {
	p.active.Add(1)
	defer p.active.Add(-1)
	if p.started != nil {
		select {
		case p.started <- struct{}{}:
		default:
		}
	}
	if p.unblock != nil {
		<-p.unblock
	}
	return append([]byte(nil), in...), nil
}

func (p *probeProcessor) wipe() {
	if p.active.Load() != 0 {
		p.unsafeWipe.Store(true)
	}
	p.wipeCount.Add(1)
}

func TestEmergencyBlockedOperation(t *testing.T) {
	p := &probeProcessor{started: make(chan struct{}, 1), unblock: make(chan struct{})}
	k, err := newKeySlot(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, err := k.sealPacket([]byte("synthetic-only")); finished <- err }()
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("synthetic process did not enter")
	}

	began := make(chan struct{})
	go func() { k.beginEmergency(); close(began) }()
	select {
	case <-began:
	case <-time.After(time.Second):
		t.Fatal("beginEmergency blocked on provider")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := k.awaitDestroyed(ctx); !errors.Is(err, errDrainWait) {
		t.Fatalf("should require escalation, got %v", err)
	}
	if got := p.wipeCount.Load(); got != 0 {
		t.Fatalf("wiped %d times while processor blocked", got)
	}
	if _, err := k.sealPacket(nil); !errors.Is(err, errClosed) {
		t.Fatalf("new packet admitted after shutdown: %v", err)
	}

	close(p.unblock)
	select {
	case err := <-finished:
		if !errors.Is(err, errClosed) {
			t.Fatalf("in-flight packet was not discarded after shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("synthetic packet did not exit")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := k.awaitDestroyed(ctx2); err != nil {
		t.Fatalf("close did not drain: %v", err)
	}
	if p.wipeCount.Load() != 1 || p.unsafeWipe.Load() {
		t.Fatalf("wipe incorrectly timed: count=%d unsafe=%v", p.wipeCount.Load(), p.unsafeWipe.Load())
	}
}

func TestTicketsUniqueAndBoundedConcurrent(t *testing.T) {
	p := &probeProcessor{}
	const limit = 1500
	k, _ := newKeySlot(p, limit)
	var wg sync.WaitGroup
	tickets := make(chan uint64, limit)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				pkt, err := k.sealPacket([]byte{byte(j)})
				if err == nil {
					tickets <- pkt.sequence
					continue
				}
				if !errors.Is(err, errExhausted) {
					t.Errorf("unexpected error: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	close(tickets)
	seen := make(map[uint64]bool)
	for seq := range tickets {
		if seen[seq] {
			t.Fatalf("duplicate ticket %d", seq)
		}
		seen[seq] = true
	}
	if len(seen) != limit {
		t.Fatalf("got %d unique tickets, want %d", len(seen), limit)
	}
	for i := uint64(0); i < limit; i++ {
		if !seen[i] {
			t.Fatalf("missing ticket %d", i)
		}
	}
	if k.next.Load() != limit {
		t.Fatalf("counter exceeded limit: %d", k.next.Load())
	}
	k.beginEmergency()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := k.awaitDestroyed(ctx); err != nil || p.wipeCount.Load() != 1 {
		t.Fatalf("invalid shutdown %v, wipeCount=%d", err, p.wipeCount.Load())
	}
}

func TestConcurrentEmergencyIdempotent(t *testing.T) {
	for round := 0; round < 100; round++ {
		p := &probeProcessor{}
		k, _ := newKeySlot(p, 10000)
		var wg sync.WaitGroup
		for i := 0; i < 30; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					_, _ = k.sealPacket([]byte{1})
				}
			}()
		}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); k.beginEmergency() }()
		}
		wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := k.awaitDestroyed(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		if p.wipeCount.Load() != 1 || p.unsafeWipe.Load() {
			t.Fatalf("round %d: incorrect wipe count %d or active wipe", round, p.wipeCount.Load())
		}
	}
}

func TestInvalidAndZeroValueFailClosed(t *testing.T) {
	var k keySlot
	if _, err := k.sealPacket(nil); !errors.Is(err, errClosed) {
		t.Fatalf("zero value unexpectedly functional: %v", err)
	}
	if err := k.awaitDestroyed(context.Background()); !errors.Is(err, errInvalid) {
		t.Fatalf("zero value: %v", err)
	}
	if _, err := newKeySlot(nil, 1); !errors.Is(err, errInvalid) {
		t.Fatalf("nil provider admitted: %v", err)
	}
	if _, err := newKeySlot(&probeProcessor{}, 0); !errors.Is(err, errInvalid) {
		t.Fatalf("zero limit admitted: %v", err)
	}
}
