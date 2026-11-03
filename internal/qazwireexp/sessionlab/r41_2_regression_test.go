//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package sessionlab

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type r412OverlapProcessor struct{ providerClaim }

func (*r412OverlapProcessor) process(_ uint64, in []byte) ([]byte, error) {
	return in[1:], nil // offset subslice: start pointers do NOT match
}
func (*r412OverlapProcessor) wipe() {}

type r412Wire struct {
	payload []byte
	sends   atomic.Int64
}

func (w *r412Wire) send(_ uint64, p []byte) error {
	w.payload = append([]byte(nil), p...)
	w.sends.Add(1)
	return nil
}

func TestR412_OffsetAliasingDetached(t *testing.T) {
	w := &r412Wire{}
	s, err := newSession(&r412OverlapProcessor{}, w, 10)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("aAAAA")
	pkt, err := s.prepare(data)
	if err != nil {
		t.Fatal(err)
	}
	copy(data[1:], "BBBB")
	if err := s.dispatch(pkt); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.payload, []byte("AAAA")) {
		t.Fatalf("caller mutation leaked into queued data: %q", w.payload)
	}
	s.beginEmergency()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestR412_GrandparentInFlightDroppedOnSecondRotation(t *testing.T) {
	p := &fakeProcessor{started: make(chan struct{}, 1), release: make(chan struct{})}
	w := &remediationSink{}
	s, err := newSession(p, w, 10)
	if err != nil {
		t.Fatal(err)
	}

	grandparent := s.k // capture identity before rotations; s.keys can be pruned
	type prepared struct {
		packet packet
		err    error
	}
	finish := make(chan prepared, 1)
	go func() {
		pkt, err := s.prepare([]byte("grandparent"))
		finish <- prepared{packet: pkt, err: err}
	}()
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("first generation never entered process")
	}
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	close(p.release)

	var result prepared
	select {
	case result = <-finish:
		if result.err != nil && !errors.Is(result.err, errClosed) {
			t.Fatalf("unexpected prepare error: %v", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("older generation never completed")
	}
	// prepare may retry a rejected grandparent operation on the CURRENT key.
	// A successful retry is allowed, but the returned ticket MUST NOT belong
	// to the grandparent. This distinguishes actual stale-key emission from
	// a valid retry (the original test wrongly required errClosed).
	wantSends := int64(0)
	if result.err == nil {
		if result.packet.guard == nil {
			t.Fatal("successful retry returned no ticket")
		}
		s.mu.RLock()
		newest := s.k
		s.mu.RUnlock()
		if result.packet.guard.owner != newest {
			t.Fatal("packet does not belong to the current generation")
		}
		if err := s.dispatch(result.packet); err != nil {
			t.Fatalf("current-generation retry not dispatchable: %v", err)
		}
		wantSends = 1
	}
	s.mu.RLock()
	for _, queued := range s.pending {
		if queued.guard.owner == grandparent {
			s.mu.RUnlock()
			t.Fatal("grandparent packet reentered queue")
		}
	}
	s.mu.RUnlock()
	if got := w.count.Load(); got != wantSends {
		t.Fatalf("unexpected send count: got %d, want %d", got, wantSends)
	}
	s.beginEmergency()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if err := grandparent.gate.await(ctx); err != nil {
		t.Fatalf("grandparent did not drain: %v", err)
	}
	if p.wipeCount.Load() != 1 {
		t.Fatalf("grandparent wiped %d times, want 1", p.wipeCount.Load())
	}
}

func TestR412_ProviderReuseWithoutGlobalRetention(t *testing.T) {
	shared := &fakeProcessor{}
	s, err := newSession(shared, &remediationSink{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSession(shared, &remediationSink{}, 10); !errors.Is(err, errProviderReuse) {
		t.Fatalf("second session accepted same provider: %v", err)
	}
	if err := s.rotate(shared, 10); !errors.Is(err, errProviderReuse) {
		t.Fatalf("rotation accepted live provider: %v", err)
	}
	s.beginEmergency()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	// Ownership remains claimed even after wipe, but no process-global registry
	// holds a reference to the retired provider.
	if _, err := newSession(shared, &remediationSink{}, 10); !errors.Is(err, errProviderReuse) {
		t.Fatalf("reused wiped provider: %v", err)
	}
}
