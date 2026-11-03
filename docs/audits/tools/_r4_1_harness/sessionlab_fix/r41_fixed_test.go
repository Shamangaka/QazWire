//go:build qazwire_exp

// Tests of the R4.1 MINIMAL FIX (session_r41_minimal_fix.patch). They assert the
// corrected behaviour; run them only against the patched session.go.
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

type valProc struct{ material [32]byte }

func (v valProc) process(_ uint64, b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }
func (v valProc) wipe()                                      { clear(v.material[:]) }

type inplaceProc struct{ x int }

func (*inplaceProc) process(_ uint64, b []byte) ([]byte, error) { return b, nil }
func (*inplaceProc) wipe()                                      {}

func TestFix01_ProviderReuseRejected(t *testing.T) {
	p := &fakeProcessor{}
	s, _ := newSession(p, &countWire{}, 10)
	if err := s.rotate(p, 10); !errors.Is(err, errProviderReuse) {
		t.Fatalf("rotate with same provider: %v", err)
	}
	if _, err := newSession(p, &countWire{}, 10); !errors.Is(err, errProviderReuse) {
		t.Fatalf("second session with same provider: %v", err)
	}
}

func TestFix02_ValueProviderRejected(t *testing.T) {
	if _, err := newSession(valProc{}, &countWire{}, 10); !errors.Is(err, errInvalid) {
		t.Fatalf("value provider: %v", err)
	}
}

func TestFix03_RotationKeepsInFlightPacket(t *testing.T) {
	p := &fakeProcessor{started: make(chan struct{}, 1), release: make(chan struct{})}
	w := &countWire{}
	s, _ := newSession(p, w, 10)
	res := make(chan error, 1)
	var pkt packet
	go func() { var err error; pkt, err = s.prepare([]byte("in flight")); res <- err }()
	<-p.started
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	close(p.release)
	if err := <-res; err != nil {
		t.Fatalf("in-flight packet lost at rotation: %v", err)
	}
	if err := s.dispatch(pkt); err != nil || w.n.Load() != 1 {
		t.Fatalf("dispatch on retired generation: %v", err)
	}
	ctx, c := dctx(time.Second)
	defer c()
	if err := s.keys[0].gate.await(ctx); err != nil || p.wipeCount.Load() != 1 {
		t.Fatalf("retired key not wiped after its last packet: %v", err)
	}
}

func TestFix03b_PrepareRetriesAfterRotationRace(t *testing.T) {
	s, _ := newSession(&fakeProcessor{}, &countWire{}, 10)
	old := s.k
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	// emulate a caller that read the old generation: seal on it is refused,
	// prepare() must retry on the current generation instead of failing
	if _, err := old.seal(nil); !errors.Is(err, errClosed) {
		t.Fatal("old generation still admits")
	}
	if _, err := s.prepare([]byte{1}); err != nil {
		t.Fatal(err)
	}
}

func TestFix04_RetiredKeyLifetimeBounded(t *testing.T) {
	old := &fakeProcessor{}
	s, _ := newSession(old, &countWire{}, 10)
	if _, err := s.prepare([]byte("forgotten")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if err := s.rotate(&fakeProcessor{}, 10); err != nil {
			t.Fatal(err)
		}
	}
	if old.wipeCount.Load() != 1 {
		t.Fatalf("generation 0 still pinned (wipes=%d)", old.wipeCount.Load())
	}
	time.Sleep(10 * time.Millisecond) // finish goroutines of discarded generations
	if err := s.rotate(&fakeProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	n := len(s.keys)
	s.mu.RUnlock()
	if n > 3 {
		t.Fatalf("generations not pruned: %d", n)
	}
}

func TestFix05_RotatedKeyWipeFailureEscalates(t *testing.T) {
	s, _ := newSession(&remediationProcessor{action: 3}, &countWire{}, 10)
	if err := s.rotate(&remediationProcessor{}, 10); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := s.prepare([]byte{1}); errors.Is(err, errClosed) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("wipe failure of a retired generation did not stop the session")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, c := dctx(time.Second)
	defer c()
	if err := s.awaitDrained(ctx); !errors.Is(err, errWipeFailed) {
		t.Fatalf("awaitDrained: %v", err)
	}
	if _, failed := s.faultState(); !failed {
		t.Fatal("faultState does not report wipe failure")
	}
}

func TestFix05b_PoisonVisible(t *testing.T) {
	s, _ := newSession(&remediationProcessor{action: 1}, &countWire{}, 10)
	_, _ = s.prepare([]byte{1})
	ctx, c := dctx(time.Second)
	defer c()
	_ = s.awaitDrained(ctx)
	if poisoned, _ := s.faultState(); !poisoned {
		t.Fatal("poison not visible")
	}
}

func TestFix06_WipeHangDistinct(t *testing.T) {
	p := &fakeProcessor{wipeStarted: make(chan struct{}), wipeRelease: make(chan struct{})}
	s, _ := newSession(p, &countWire{}, 10)
	s.beginEmergency()
	<-p.wipeStarted
	ctx, c := dctx(20 * time.Millisecond)
	defer c()
	err := s.awaitDrained(ctx)
	close(p.wipeRelease)
	if !errors.Is(err, errWipeUnconfirmed) || !errors.Is(err, errDeadline) {
		t.Fatalf("got %v", err)
	}
}

func TestFix07_NoBufferAliasing(t *testing.T) {
	w := &countWire{}
	s, _ := newSession(&inplaceProc{}, w, 10)
	buf := []byte("AAAA")
	pkt, err := s.prepare(buf)
	if err != nil || pkt.data != nil {
		t.Fatalf("caller received queued buffer: %v", err)
	}
	copy(buf, "BBBB")
	if err := s.dispatch(pkt); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	got := w.last
	w.mu.Unlock()
	if !bytes.Equal(got, []byte("AAAA")) {
		t.Fatalf("sent %q", got)
	}
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
