//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// Negative audit tests against QazWire sessionlab M1.5.2 @45984d7.
// These are EXPECTED TO FAIL on the unmodified target; do not copy to product.
package sessionlab

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type r42Sink struct{}

func (*r42Sink) send(uint64, []byte) error { return nil }

type r42SharedMaterial struct{ wiped atomic.Bool }
type r42Provider struct {
	providerClaim
	shared    *r42SharedMaterial
	blockWipe <-chan struct{}
}

func (p *r42Provider) process(_ uint64, b []byte) ([]byte, error) {
	if p.shared != nil && p.shared.wiped.Load() {
		return nil, errors.New("shared synthetic material already wiped")
	}
	return append([]byte(nil), b...), nil
}
func (p *r42Provider) wipe() {
	if p.blockWipe != nil {
		<-p.blockWipe
	}
	if p.shared != nil {
		p.shared.wiped.Store(true)
	}
}

// R42-01: distinct claim tokens do NOT prove exclusive ownership of a shared
// resource. Reproduction does not copy atomic.Bool (thus passes go vet).
func TestR42_01_ProviderMaterialAliasMustNotBeAccepted(t *testing.T) {
	material := &r42SharedMaterial{}
	p0 := &r42Provider{shared: material}
	p1 := &r42Provider{shared: material} // two objects, same backing secret
	s0, err := newSession(p0, &r42Sink{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSession(p1, &r42Sink{}, 10); !errors.Is(err, errProviderReuse) {
		s0.beginEmergency()
		t.Fatalf("R42-01 material alias accepted (err=%v): distinct providerClaim does not imply unique key ownership", err)
	}
}

// R42-02: s.keys[:0] filters its visible slice but does not clear the tail of
// the backing array. The GC can keep references to retired providers via that
// hidden capacity. We intentionally hold wipe() so keys accumulate first.
func TestR42_02_PrunedKeysMustNotRemainInSliceCapacity(t *testing.T) {
	release := make(chan struct{})
	s, err := newSession(&r42Provider{blockWipe: release}, &r42Sink{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	retired := make([]*key, 0, 9)
	for i := 0; i < 8; i++ {
		retired = append(retired, s.k)
		if err := s.rotate(&r42Provider{blockWipe: release}, 10); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, k := range retired {
		if err := k.gate.await(ctx); err != nil {
			t.Fatalf("retired generation failed to complete wipe: %v", err)
		}
	}
	if err := s.rotate(&r42Provider{}, 10); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	active := make(map[*key]bool, len(s.keys))
	for _, k := range s.keys {
		active[k] = true
	}
	backing := s.keys[:cap(s.keys)]
	var retained int
	for i := len(s.keys); i < cap(s.keys); i++ {
		if k := backing[i]; k != nil && !active[k] {
			retained++
		}
	}
	s.mu.RUnlock()
	s.beginEmergency()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if retained != 0 {
		t.Fatalf("R42-02: %d pruned key pointers remain in s.keys backing capacity", retained)
	}
}
