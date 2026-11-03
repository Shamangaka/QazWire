//go:build qazwire_exp

// R4.2 fix tests. They run ONLY against the patched copy produced by
// session_r42_minimal_fix.patch (they reference errBacklog/faultBacklog,
// which do not exist at PR #13 HEAD 45984d7).
package sessionlab

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// FIX R42-04: a sink panic is reported AND latched.
func TestR42Fix_04_SinkPanicLatched(t *testing.T) {
	s, _ := newSession(&fakeProcessor{}, &r42PanicWire{}, 10)
	pkt, err := s.prepare([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.dispatch(pkt); !errors.Is(err, errProviderFault) {
		t.Fatalf("dispatch: %v", err)
	}
	if poisoned, _ := s.faultState(); !poisoned {
		t.Fatal("sink panic not latched")
	}
	ctx, c := r42ctx(time.Second)
	defer c()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
}

type hangWipeCount struct {
	providerClaim
	started chan struct{}
	release chan struct{}
	wipes   *atomic.Int64
}

func (p *hangWipeCount) process(_ uint64, b []byte) ([]byte, error) {
	p.started <- struct{}{}
	<-p.release
	return append([]byte(nil), b...), nil
}
func (p *hangWipeCount) wipe() { p.wipes.Add(1) }

// FIX R42-05: superseded generations pinned by unfinished operations are
// bounded; beyond the bound rotate fails closed, and the freshly claimed
// provider is still wiped through the managed lifecycle.
func TestR42Fix_05_PinnedGenerationsBounded(t *testing.T) {
	release := make(chan struct{})
	var wipes atomic.Int64
	mk := func() *hangWipeCount {
		return &hangWipeCount{started: make(chan struct{}, 1), release: release, wipes: &wipes}
	}
	cur := mk()
	s, _ := newSession(cur, &r42Wire{}, 10)
	results := make(chan error, 64)
	var fresh *hangWipeCount
	rot := 0
	for ; rot < 64; rot++ {
		go func() { _, err := s.prepare([]byte{1}); results <- err }()
		<-cur.started
		fresh = mk()
		if err := s.rotate(fresh, 10); err != nil {
			if !errors.Is(err, errBacklog) {
				t.Fatalf("rotate %d: %v", rot, err)
			}
			break
		}
		cur = fresh
	}
	if rot != maxPinnedSuperseded+1 {
		t.Fatalf("backlog detected at rotation %d, want %d", rot, maxPinnedSuperseded+1)
	}
	s.mu.RLock()
	live, closed := len(s.keys), s.closed
	s.mu.RUnlock()
	if !closed || live > maxPinnedSuperseded+3 || s.faults.Load()&faultBacklog == 0 {
		t.Fatalf("not fail-closed: closed=%v live=%d faults=%b", closed, live, s.faults.Load())
	}
	if _, err := s.prepare([]byte{2}); !errors.Is(err, errClosed) {
		t.Fatalf("prepare after backlog: %v", err)
	}
	// Hung operations still prevent a confirmed drain (Stage D is external).
	ctx, c := r42ctx(30 * time.Millisecond)
	err := s.awaitDrained(ctx)
	c()
	if !errors.Is(err, errDeadline) {
		t.Fatalf("awaitDrained with hung operations: %v", err)
	}
	close(release)
	for i := 0; i <= rot; i++ {
		if err := <-results; !errors.Is(err, errClosed) {
			t.Fatalf("hung prepare %d returned %v", i, err)
		}
	}
	ctx, c = r42ctx(time.Second)
	defer c()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if got := wipes.Load(); got != int64(rot+2) {
		t.Fatalf("wipes=%d want %d (every claimed provider incl. the refused one)", got, rot+2)
	}
	t.Logf("FIX R42-05: rotation %d refused with errBacklog, live generations=%d, all %d providers wiped after release", rot, live, rot+2)
}

// FIX R42-10: after pruning, the backing array beyond len(s.keys) holds no generation.
func TestR42Fix_10_PrunedKeysNotRetained(t *testing.T) {
	// n slow operations pin n generations; n = maxPinnedSuperseded+1 stays below the
	// R42-05 bound and leaves stale tail entries on the unpatched code.
	const n = maxPinnedSuperseded + 1
	release := make(chan struct{})
	mk := func() *slowProc { return &slowProc{started: make(chan struct{}, 1), release: release} }
	cur := mk()
	s, _ := newSession(cur, &r42Wire{}, 10)
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() { _, _ = s.prepare([]byte{1}); done <- struct{}{} }()
		<-cur.started
		next := mk()
		if err := s.rotate(next, 10); err != nil {
			t.Fatal(err)
		}
		cur = next
	}
	close(release)
	for i := 0; i < n; i++ {
		<-done
	}
	ctx, c := r42ctx(time.Second)
	defer c()
	s.mu.RLock()
	keys := append([]*key(nil), s.keys...)
	current, previous := s.k, s.previous
	s.mu.RUnlock()
	for _, k := range keys {
		if k != current && k != previous {
			if err := k.gate.await(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if cap(s.keys) <= len(s.keys) {
		t.Fatalf("scenario did not shrink s.keys: len=%d cap=%d", len(s.keys), cap(s.keys))
	}
	for i, k := range s.keys[len(s.keys):cap(s.keys)] {
		if k != nil {
			t.Fatalf("backing array slot %d still references a pruned generation", len(s.keys)+i)
		}
	}
}
