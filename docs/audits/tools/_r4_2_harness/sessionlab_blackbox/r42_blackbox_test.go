//go:build qazwire_exp

// R4.2 auditor tests for the UNMODIFIED sessionlab at PR #13 HEAD 45984d7
// (session.go blob 0305fa2). Only names that already exist in the package are
// used; session.go is not changed. Every test PASSES when the reported
// behaviour is reproduced and logs a CONFIRMED line.
package sessionlab

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func r42ctx(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

type r42Wire struct{ n atomic.Int64 }

func (w *r42Wire) send(uint64, []byte) error { w.n.Add(1); return nil }

// matProc is a pointer provider whose secret lives behind a pointer, as real
// key material in a locked arena would.
type matProc struct {
	providerClaim
	mat     *[32]byte
	mu      sync.Mutex
	used    [][2]uint64 // (material id, ticket) pairs actually processed
	onWiped atomic.Int64
}

func (p *matProc) process(t uint64, b []byte) ([]byte, error) {
	if p.mat[0] == 0 {
		p.onWiped.Add(1) // operating on wiped material
	}
	p.mu.Lock()
	p.used = append(p.used, [2]uint64{uint64(p.mat[1]), t})
	p.mu.Unlock()
	return append([]byte(nil), b...), nil
}
func (p *matProc) wipe() { clear(p.mat[:]) }

// ---------- R42-01: claim() is per OBJECT, ownership of MATERIAL is not enforced ----------

// (a) Two distinct provider objects over one memory region.
func TestR42_01a_TwoProvidersShareOneMaterial(t *testing.T) {
	var secret [32]byte
	secret[0], secret[1] = 0xA5, 7
	p1 := &matProc{mat: &secret}
	p2 := &matProc{mat: &secret}
	s1, err1 := newSession(p1, &r42Wire{}, 10)
	s2, err2 := newSession(p2, &r42Wire{}, 10)
	if err1 != nil || err2 != nil {
		t.Fatalf("not reproduced: %v %v", err1, err2)
	}
	s1.beginEmergency()
	ctx, c := r42ctx(time.Second)
	defer c()
	if err := s1.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.prepare([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if p2.onWiped.Load() != 1 {
		t.Fatal("not reproduced")
	}
	t.Log("CONFIRMED R42-01a: two provider objects over one material were both claimed; wiping session 1 erased the material still used by live session 2 (process on wiped material)")
}

// (b) A copy made before the first claim() yields a second claimable owner.
// A plain `*p2 = *p1` is reported by `go vet` (copylocks); a reflect copy is not.
func TestR42_01b_CopyBeforeClaimBypassesOneTimeClaim(t *testing.T) {
	var secret [32]byte
	secret[0] = 0xA5
	p1 := &matProc{mat: &secret}
	p2 := new(matProc)
	reflect.ValueOf(p2).Elem().Set(reflect.ValueOf(p1).Elem()) // copies providerClaim too
	if _, err := newSession(p1, &r42Wire{}, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := newSession(p2, &r42Wire{}, 10); err != nil {
		t.Fatalf("not reproduced: %v", err)
	}
	t.Log("CONFIRMED R42-01b: a pre-claim struct copy carries an unclaimed providerClaim; both objects (same material pointer) were accepted")
}

// (c) The provider certifies its own ownership: claim() is provider code.
type selfClaim struct{ wiped atomic.Bool }

func (*selfClaim) claim() bool { return true }
func (p *selfClaim) process(_ uint64, b []byte) ([]byte, error) {
	return append([]byte(nil), b...), nil
}
func (p *selfClaim) wipe() { p.wiped.Store(true) }

func TestR42_01c_SelfCertifiedClaim(t *testing.T) {
	p := &selfClaim{}
	s, err := newSession(p, &r42Wire{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.rotate(p, 10); err != nil {
		t.Fatalf("not reproduced: %v", err)
	}
	if _, err := newSession(p, &r42Wire{}, 10); err != nil {
		t.Fatalf("not reproduced: %v", err)
	}
	t.Log("CONFIRMED R42-01c: claim() is implemented by the provider being checked; a provider returning true is accepted by rotate() on the same session and by a second session (R41-01 bypass)")
}

// ---------- R42-02: the same material in a new generation repeats (material, ticket) ----------

func TestR42_02_SameMaterialNewGenerationRepeatsTickets(t *testing.T) {
	var secret [32]byte
	secret[0], secret[1] = 0xA5, 42 // material id 42
	p1 := &matProc{mat: &secret}
	s, _ := newSession(p1, &r42Wire{}, 10)
	for i := 0; i < 2; i++ {
		if _, err := s.prepare([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// a new provider OBJECT built from the same material (e.g. a key-schedule bug,
	// a replayed derivation input, or copied bytes) is a fresh, claimable owner
	var again [32]byte
	again = secret
	p2 := &matProc{mat: &again}
	if err := s.rotate(p2, 10); err != nil {
		t.Fatalf("not reproduced: %v", err)
	}
	if _, err := s.prepare([]byte{9}); err != nil {
		t.Fatal(err)
	}
	if p1.used[0] != p2.used[0] {
		t.Fatalf("not reproduced: %v vs %v", p1.used, p2.used)
	}
	t.Logf("CONFIRMED R42-02: (material id, ticket) = %v processed in generation 0 and again in generation 1; tickets restart at 0 per generation and nothing binds them to the material or an epoch (nonce reuse class)", p2.used[0])
}

// ---------- R42-03: value-receiver wipe on a POINTER provider (R41-02 residual) ----------

type vrProc struct {
	tok      *atomic.Bool
	material [32]byte
	wipes    *atomic.Int64
}

func (v vrProc) claim() bool                                { return v.tok.CompareAndSwap(false, true) }
func (v vrProc) process(_ uint64, b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }
func (v vrProc) wipe()                                      { clear(v.material[:]); v.wipes.Add(1) }

func TestR42_03_ValueReceiverWipeOnPointerProvider(t *testing.T) {
	var tok atomic.Bool
	var wipes atomic.Int64
	p := &vrProc{tok: &tok, wipes: &wipes}
	p.material[0] = 0xA5
	s, err := newSession(p, &r42Wire{}, 10)
	if err != nil {
		t.Fatalf("pointer provider rejected: %v", err)
	}
	s.beginEmergency()
	ctx, c := r42ctx(time.Second)
	defer c()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	if wipes.Load() != 1 || p.material[0] != 0xA5 {
		t.Fatalf("not reproduced: wipes=%d material=%#x", wipes.Load(), p.material[0])
	}
	t.Log("CONFIRMED R42-03: *vrProc passes validProvider (pointer kind); its value-receiver wipe() cleared a copy; awaitDrained returned nil while p.material is intact (0xa5)")
}

// ---------- R42-04: a panicking sink returns errProviderFault but no fault is latched ----------

type r42PanicWire struct{}

func (r42PanicWire) send(uint64, []byte) error { panic("sink") }

func TestR42_04_SinkPanicNotLatched(t *testing.T) {
	s, _ := newSession(&fakeProcessor{}, &r42PanicWire{}, 10)
	pkt, _ := s.prepare([]byte{1})
	err := s.dispatch(pkt)
	poisoned, failed := s.faultState()
	if !errors.Is(err, errProviderFault) || poisoned || failed {
		t.Fatalf("not reproduced: %v %v %v", err, poisoned, failed)
	}
	t.Log("CONFIRMED R42-04: dispatch returned errProviderFault for a sink panic, but faultState() = (false, false): the fault signal is lost for an orchestrator that polls faultState")
}

// ---------- R42-05: hung operations pin generations without bound ----------

type hangProc struct {
	providerClaim
	started chan struct{}
	release chan struct{}
}

func (p *hangProc) process(_ uint64, b []byte) ([]byte, error) {
	p.started <- struct{}{}
	<-p.release
	return append([]byte(nil), b...), nil
}
func (p *hangProc) wipe() {}

func TestR42_05_HungOperationsPinGenerationsUnbounded(t *testing.T) {
	const n = 64
	release := make(chan struct{})
	mk := func() *hangProc { return &hangProc{started: make(chan struct{}, 1), release: release} }
	p0 := mk()
	s, _ := newSession(p0, &r42Wire{}, 10)
	cur := p0
	for i := 0; i < n; i++ {
		go func() { _, _ = s.prepare([]byte{1}) }() // never returns while release is open
		<-cur.started
		next := mk()
		if err := s.rotate(next, 10); err != nil {
			t.Fatal(err)
		}
		cur = next
	}
	s.mu.RLock()
	live := len(s.keys)
	s.mu.RUnlock()
	if live != n+1 {
		t.Fatalf("not reproduced: live=%d", live)
	}
	s.beginEmergency()
	ctx, c := r42ctx(50 * time.Millisecond)
	err := s.awaitDrained(ctx)
	c()
	close(release)
	t.Logf("CONFIRMED R42-05: %d rotations with one hung operation each keep %d generations (and their providers) alive; no cap exists; emergency cannot finish (%v) -> only external Stage D bounds it", n, live, err)
}

// ---------- R42-10: pruned generations stay reachable through the slice capacity ----------

// slowProc blocks process() until release is closed; started never blocks.
type slowProc struct {
	providerClaim
	started chan struct{}
	release chan struct{}
}

func (p *slowProc) process(_ uint64, b []byte) ([]byte, error) {
	select {
	case p.started <- struct{}{}:
	default:
	}
	<-p.release
	return append([]byte(nil), b...), nil
}
func (p *slowProc) wipe() {}

func TestR42_10_PrunedKeysRetainedInSliceCapacity(t *testing.T) {
	const n = 8
	release := make(chan struct{})
	mk := func() *slowProc { return &slowProc{started: make(chan struct{}, 1), release: release} }
	cur := mk()
	s, _ := newSession(cur, &r42Wire{}, 10)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ { // n slow operations keep n generations alive for a while
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.prepare([]byte{1}) }()
		<-cur.started
		next := mk()
		if err := s.rotate(next, 10); err != nil {
			t.Fatal(err)
		}
		cur = next
	}
	close(release) // the operations finish; their generations are wiped
	wg.Wait()
	ctx, c := r42ctx(time.Second)
	defer c()
	s.mu.RLock()
	keys := append([]*key(nil), s.keys...)
	current, previous := s.k, s.previous // previous may still hold a queued packet
	s.mu.RUnlock()
	for _, k := range keys {
		if k != current && k != previous {
			if err := k.gate.await(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.rotate(&fakeProcessor{}, 10); err != nil { // prunes the finished generations
		t.Fatal(err)
	}
	s.mu.RLock()
	live := map[*key]bool{}
	for _, k := range s.keys {
		live[k] = true
	}
	stale := 0
	for _, k := range s.keys[len(s.keys):cap(s.keys)] {
		if k != nil && !live[k] {
			stale++
		}
	}
	l, cp := len(s.keys), cap(s.keys)
	s.mu.RUnlock()
	if stale == 0 {
		t.Fatalf("not reproduced: len=%d cap=%d", l, cp)
	}
	t.Logf("CONFIRMED R42-10: after pruning len(s.keys)=%d cap=%d; %d pruned (already wiped) generations remain reachable through the backing array, so their providers cannot be collected", l, cp, stale)
}
