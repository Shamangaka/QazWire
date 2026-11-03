//go:build qazwire_exp

// R4.1 auditor tests for the UNMODIFIED sessionlab (PR #11 HEAD f5e078c,
// session.go blob bd3aff6). Only package-internal names that already exist
// in session.go are used; nothing in session.go is changed.
package sessionlab

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dctx(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// ---------- R41-01: one provider object shared by two key generations ----------

type aliasProc struct {
	wiped         atomic.Bool
	usedAfterWipe atomic.Int64
	wipes         atomic.Int64
}

func (p *aliasProc) process(_ uint64, b []byte) ([]byte, error) {
	if p.wiped.Load() {
		p.usedAfterWipe.Add(1)
	}
	return append([]byte(nil), b...), nil
}
func (p *aliasProc) wipe() { p.wiped.Store(true); p.wipes.Add(1) }

type countWire struct {
	n    atomic.Int64
	mu   sync.Mutex
	last []byte
}

func (w *countWire) send(_ uint64, b []byte) error {
	w.n.Add(1)
	w.mu.Lock()
	w.last = append([]byte(nil), b...)
	w.mu.Unlock()
	return nil
}

func TestR41_01_ProviderAliasedAcrossGenerations(t *testing.T) {
	p := &aliasProc{}
	s, _ := newSession(p, &countWire{}, 10)
	if err := s.rotate(p, 10); err != nil { // same provider object for the new generation
		t.Fatalf("rotate rejected aliasing: %v", err)
	}
	ctx, c := dctx(time.Second)
	defer c()
	s.mu.RLock()
	old := s.keys[0]
	s.mu.RUnlock()
	if err := old.gate.await(ctx); err != nil { // old generation wiped asynchronously
		t.Fatal(err)
	}
	if _, err := s.prepare([]byte("after-wipe")); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if p.usedAfterWipe.Load() == 0 {
		t.Fatal("not reproduced")
	}
	t.Logf("CONFIRMED R41-01: rotate(p, …) with the provider of the retired generation is accepted; the retired key's wipe() erased the provider still used by the live key; %d process() call(s) on a wiped provider succeeded", p.usedAfterWipe.Load())
	// cross-session aliasing is accepted as well
	if _, err := newSession(p, &countWire{}, 10); err != nil {
		t.Fatal(err)
	}
	t.Log("CONFIRMED R41-01: the same provider object is also accepted by a second session")
}

// ---------- R41-02: value-type provider: wipe() runs on a copy ----------

type valProc struct {
	material [32]byte
	wipes    *atomic.Int64
}

func (v valProc) process(_ uint64, b []byte) ([]byte, error) {
	return append([]byte{v.material[0]}, b...), nil
}
func (v valProc) wipe() { clear(v.material[:]); v.wipes.Add(1) } // clears the receiver copy

func TestR41_02_ValueProviderWipeIsOnACopy(t *testing.T) {
	var cnt atomic.Int64
	vp := valProc{wipes: &cnt}
	vp.material[0] = 0xA5
	s, err := newSession(vp, &countWire{}, 10)
	if err != nil {
		t.Fatalf("value provider rejected: %v", err)
	}
	s.beginEmergency()
	ctx, c := dctx(time.Second)
	defer c()
	if err := s.awaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	still := s.keys[0].p.(valProc).material[0]
	if cnt.Load() != 1 || still != 0xA5 {
		t.Fatalf("not reproduced: wipes=%d material=%#x", cnt.Load(), still)
	}
	t.Logf("CONFIRMED R41-02: validDependency accepts a non-pointer provider; wipe() ran (count=1) and awaitDrained returned nil, yet the provider state held by the key is intact (material[0]=%#x)", still)
}

// ---------- R41-03: rotation drops an in-flight packet and reports errClosed while the session is open ----------

func TestR41_03_RotationDropsInFlightPacket(t *testing.T) {
	p := &fakeProcessor{started: make(chan struct{}, 1), release: make(chan struct{})}
	s, _ := newSession(p, &countWire{}, 10)
	res := make(chan error, 1)
	go func() { _, err := s.prepare([]byte("in flight")); res <- err }()
	<-p.started
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	close(p.release)
	err := <-res
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if !errors.Is(err, errClosed) || closed {
		t.Fatalf("not reproduced: err=%v closed=%v", err, closed)
	}
	if _, err := s.prepare([]byte("next")); err != nil {
		t.Fatal(err)
	}
	t.Logf("CONFIRMED R41-03: planned rotation discarded an already processed packet and returned %q although the session is open (same error value as session shutdown); next prepare succeeds on the new key", err)
}

// ---------- R41-04: a forgotten packet pins a retired key forever; generations are never pruned ----------

func TestR41_04_LeakedPacketPinsRetiredKey(t *testing.T) {
	old := &fakeProcessor{}
	s, _ := newSession(old, &countWire{}, 10)
	if _, err := s.prepare([]byte("forgotten")); err != nil { // neither dispatched nor discarded
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if err := s.rotate(&fakeProcessor{}, 10); err != nil {
			t.Fatal(err)
		}
	}
	ctx, c := dctx(100 * time.Millisecond)
	defer c()
	err := s.keys[0].gate.await(ctx)
	s.mu.RLock()
	nkeys, npending := len(s.keys), len(s.pending)
	s.mu.RUnlock()
	if !errors.Is(err, errDeadline) || old.wipeCount.Load() != 0 {
		t.Fatalf("not reproduced: %v", err)
	}
	t.Logf("CONFIRMED R41-04: after 1000 rotations the first generation is still NOT wiped (await=%v) because one queued packet pins it; no expiry exists; s.keys holds %d generations, pending=%d", err, nkeys, npending)
}

// ---------- R41-05: failures of a rotated key are silent while the session runs; POISONED not surfaced ----------

func TestR41_05_RotatedKeyWipeFailureIsSilent(t *testing.T) {
	old := &remediationProcessor{action: 3} // wipe panics
	s, _ := newSession(old, &countWire{}, 10)
	if err := s.rotate(&remediationProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	ctx, c := dctx(time.Second)
	defer c()
	if err := s.keys[0].gate.await(ctx); !errors.Is(err, errWipeFailed) {
		t.Fatalf("got %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.prepare([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("CONFIRMED R41-05: WIPE_FAILED of a rotated generation is recorded only in its gate; the session keeps serving (3 more packets prepared) and no caller is notified until a later emergency + awaitDrained")
}

func TestR41_05b_PoisonNotSurfacedByAwaitDrained(t *testing.T) {
	p := &remediationProcessor{action: 1} // process panics
	s, _ := newSession(p, &countWire{}, 10)
	_, err := s.prepare([]byte{1})
	ctx, c := dctx(time.Second)
	defer c()
	aerr := s.awaitDrained(ctx)
	poisoned := s.keys[0].gate.state.Load()&poisonFlag != 0
	if !errors.Is(err, errProviderFault) || aerr != nil || !poisoned {
		t.Fatalf("not reproduced: %v %v %v", err, aerr, poisoned)
	}
	t.Log("CONFIRMED R41-05: poisonFlag is set but never read; awaitDrained returns nil, so an orchestrator cannot distinguish a provider fault from a clean emergency")
}

// ---------- R41-06: one error for 'operations in flight' and 'wipe not confirmed' ----------

func TestR41_06_DeadlineDoesNotDistinguishWipeHang(t *testing.T) {
	// (a) wipe started and hangs: refs = 0, finishedFlag set
	p1 := &fakeProcessor{wipeStarted: make(chan struct{}), wipeRelease: make(chan struct{})}
	s1, _ := newSession(p1, &countWire{}, 10)
	s1.beginEmergency()
	<-p1.wipeStarted
	ctx, c := dctx(20 * time.Millisecond)
	e1 := s1.awaitDrained(ctx)
	st1 := s1.keys[0].gate.state.Load()
	c()
	// (b) operation in flight: refs = 1, finishedFlag clear
	p2 := &fakeProcessor{started: make(chan struct{}, 1), release: make(chan struct{})}
	s2, _ := newSession(p2, &countWire{}, 10)
	go func() { _, _ = s2.prepare([]byte{1}) }()
	<-p2.started
	s2.beginEmergency()
	ctx2, c2 := dctx(20 * time.Millisecond)
	e2 := s2.awaitDrained(ctx2)
	st2 := s2.keys[0].gate.state.Load()
	c2()
	close(p1.wipeRelease)
	close(p2.release)
	if !errors.Is(e1, errDeadline) || !errors.Is(e2, errDeadline) {
		t.Fatalf("got %v / %v", e1, e2)
	}
	t.Logf("CONFIRMED R41-06: same error %q for wipe-hang (state=%#x, refs=%d, finished=%v) and operation-in-flight (state=%#x, refs=%d, finished=%v)",
		e1, st1, st1&referenceMask, st1&finishedFlag != 0, st2, st2&referenceMask, st2&finishedFlag != 0)
}

// ---------- R41-07: buffer ownership ----------

type inplaceProc struct{}

func (inplaceProc) process(_ uint64, b []byte) ([]byte, error) { return b, nil } // in-place "seal"
func (inplaceProc) wipe()                                      {}

func TestR41_07b_InPlaceOutputAliasesCallerBuffer(t *testing.T) {
	w := &countWire{}
	s, _ := newSession(&inplaceProc{}, w, 10)
	buf := []byte("AAAA")
	pkt, err := s.prepare(buf)
	if err != nil {
		t.Fatal(err)
	}
	copy(buf, "BBBB") // caller reuses its buffer (e.g. a pool) before dispatch
	if err := s.dispatch(pkt); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	sent := string(w.last)
	w.mu.Unlock()
	if sent != "BBBB" {
		t.Fatalf("not reproduced: %q", sent)
	}
	// discard/emergency clears the caller's own buffer through the alias
	buf2 := []byte("CCCC")
	pkt2, _ := s.prepare(buf2)
	s.discard(pkt2)
	t.Logf("CONFIRMED R41-07: sealed \"AAAA\" but the wire received %q (pending record aliases the caller buffer); discard() zeroed the caller's buffer: %v", sent, bytes.Equal(buf2, make([]byte, 4)))
}

// The record returned by prepare shares its backing array with the queued copy:
// emergency/discard clear() it after it has been handed to the caller. Note: Go's
// race detector does not report clear() (memclr) accesses -- see racechk in the
// harness -- so -race runs cannot reveal a concurrent use of this buffer.
func TestR41_07a_ReturnedRecordMutatedAfterHandOff(t *testing.T) {
	s, _ := newSession(&fakeProcessor{}, &countWire{}, 10)
	pkt, _ := s.prepare([]byte("returned to caller"))
	before := string(pkt.data)
	s.beginEmergency() // clear(queued.data) on the same backing array
	if bytes.Equal(pkt.data, make([]byte, len(pkt.data))) && before != "" {
		t.Logf("CONFIRMED R41-07: caller's record changed from %q to all-zero bytes after beginEmergency (shared buffer, no ownership transfer)", before)
		return
	}
	t.Fatal("not reproduced")
}

// ---------- stress: invariants under rotation + dispatch/discard + emergency ----------

type stressProc struct {
	gen    uint32
	wiped  atomic.Bool
	active atomic.Int64
	bad    *atomic.Int64
}

func (p *stressProc) process(t uint64, b []byte) ([]byte, error) {
	p.active.Add(1)
	defer p.active.Add(-1)
	if p.wiped.Load() {
		p.bad.Add(1)
	}
	out := make([]byte, 12)
	out[0], out[1], out[2], out[3] = byte(p.gen), byte(p.gen>>8), byte(p.gen>>16), byte(p.gen>>24)
	for i := 0; i < 8; i++ {
		out[4+i] = byte(t >> (8 * i))
	}
	return out, nil
}
func (p *stressProc) wipe() {
	if p.active.Load() != 0 {
		p.bad.Add(1)
	}
	p.wiped.Store(true)
}

type stressWire struct {
	procs  *sync.Map // gen -> *stressProc
	stageA *atomic.Bool
	bad    *atomic.Int64
	seen   sync.Map // (gen,ticket) -> struct{}
	sends  atomic.Int64
}

func (w *stressWire) send(_ uint64, b []byte) error {
	if w.stageA.Load() {
		w.bad.Add(1) // send after awaitDrained confirmed egress drained
	}
	gen := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	if v, ok := w.procs.Load(gen); ok && v.(*stressProc).wiped.Load() {
		w.bad.Add(1) // packet sent after its key was wiped
	}
	if _, dup := w.seen.LoadOrStore(string(b), struct{}{}); dup {
		w.bad.Add(1) // same (generation, ticket) sent twice
	}
	w.sends.Add(1)
	return nil
}

func TestR41_StressInvariants(t *testing.T) {
	rounds := 300
	if testing.Short() {
		rounds = 30
	}
	var bad, totalSends, totalRot atomic.Int64
	for r := 0; r < rounds; r++ {
		procs := &sync.Map{}
		var stageA atomic.Bool
		var gen atomic.Uint32
		mk := func() *stressProc {
			p := &stressProc{gen: gen.Add(1), bad: &bad}
			procs.Store(p.gen, p)
			return p
		}
		w := &stressWire{procs: procs, stageA: &stageA, bad: &bad}
		s, _ := newSession(mk(), w, 1<<20)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				rng := rand.New(rand.NewSource(int64(r*31 + id)))
				for {
					select {
					case <-stop:
						return
					default:
					}
					pkt, err := s.prepare([]byte{1})
					if err != nil {
						continue
					}
					if rng.Intn(4) == 0 {
						s.discard(pkt)
					} else {
						_ = s.dispatch(pkt)
					}
				}
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if s.rotate(mk(), 1<<20) != nil {
					return
				}
				totalRot.Add(1)
			}
		}()
		time.Sleep(time.Duration(r%5) * 200 * time.Microsecond)
		s.beginEmergency()
		ctx, c := dctx(2 * time.Second)
		err := s.awaitDrained(ctx)
		stageA.Store(true)
		close(stop)
		wg.Wait()
		c()
		if err != nil {
			t.Fatalf("round %d: awaitDrained: %v", r, err)
		}
		s.mu.RLock()
		for _, k := range s.keys {
			if k.gate.state.Load()&referenceMask != 0 {
				bad.Add(1)
			}
		}
		if len(s.pending) != 0 {
			bad.Add(1)
		}
		s.mu.RUnlock()
		totalSends.Add(w.sends.Load())
	}
	if bad.Load() != 0 {
		t.Fatalf("%d invariant violations", bad.Load())
	}
	t.Logf("%d rounds, %d sends, %d rotations: 0 sends after drain, 0 sends after own-key wipe, 0 duplicate (generation,ticket), 0 wipes under process, 0 process on wiped provider, all refs 0, pending empty", rounds, totalSends.Load(), totalRot.Load())
}
