package klm15ref

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mk(t *testing.T, max uint64) *DirectedKey {
	t.Helper()
	var m [32]byte
	m[0] = 0xA5
	k, err := newDirectedKey(&m, max, rand.Uint64())
	if err != nil {
		t.Fatal(err)
	}
	if m != ([32]byte{}) {
		t.Fatal("caller material not consumed")
	}
	return k
}

func dl(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

type pause struct {
	arrived, resume chan struct{}
	once            sync.Once
}

func pauseAt(t *testing.T, point string) *pause {
	p := &pause{arrived: make(chan struct{}), resume: make(chan struct{})}
	f := func(s string) {
		if s == point {
			p.once.Do(func() { close(p.arrived); <-p.resume })
		}
	}
	hookFn.Store(&f)
	t.Cleanup(func() { hookFn.Store(nil) })
	return p
}

// T-KLM-13 (fixes R4-KLM-01): closing between ticket CAS and check -> ticket burnt.
func TestTicketAllocatedAfterClosingIsBurnt(t *testing.T) {
	k := mk(t, 8)
	p := pauseAt(t, "reserve:cas")
	res := make(chan error, 1)
	go func() { _, err := k.Reserve(); res <- err }()
	<-p.arrived
	k.BeginEmergency()
	close(p.resume)
	if err := <-res; !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
	if k.next.Load() != 1 || k.c.active.Load() != 0 {
		t.Fatal("unexpected")
	}
	ctx, c := dl(time.Second)
	defer c()
	if err := k.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
}

// T-KLM-14: tickets are one-time, bound to their key, and Discard returns the lease.
func TestTicketOneTimeAndBound(t *testing.T) {
	k1, k2 := mk(t, 8), mk(t, 8)
	tk, _ := k1.Reserve()
	if _, err := k2.Seal(nil, tk, []byte("x")); !errors.Is(err, ErrTicket) {
		t.Fatal("foreign ticket accepted")
	}
	if _, err := k1.Seal(nil, tk, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := k1.Seal(nil, tk, []byte("x")); !errors.Is(err, ErrTicket) {
		t.Fatal("ticket reused")
	}
	tk2, _ := k1.Reserve()
	tk2.Discard()
	tk2.Discard()
	if k1.st.Load()&refMask != 0 {
		t.Fatalf("lease leaked: %#x", k1.st.Load())
	}
}

// T-KLM-15 (fixes R4-KLM-02): no send starts after stage A completes; in-flight sends are drained.
func TestEgressFence(t *testing.T) {
	d := NewDevice()
	k := mk(t, 8)
	if err := d.Install(k); err != nil {
		t.Fatal(err)
	}
	tk, _ := k.Reserve()
	rec, err := k.Seal(nil, tk, []byte("prepared before emergency"))
	if err != nil {
		t.Fatal(err)
	}
	// sender A is already inside the egress section (syscall in progress)
	if !d.Egress.Enter() {
		t.Fatal("enter")
	}
	stageA := make(chan error, 1)
	go func() { ctx, c := dl(time.Second); defer c(); stageA <- d.Emergency(ctx) }()
	select {
	case <-stageA:
		t.Fatal("stage A completed while a send was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	d.Egress.Exit() // in-flight send finishes
	if err := <-stageA; err != nil {
		t.Fatal(err)
	}
	if d.Egress.Enter() {
		t.Fatal("send admitted after stage A")
	}
	_ = rec // the prepared record can no longer reach the network through this device
}

// T-KLM-16 (R4-KLM-03): hung wipe is reported distinctly.
func TestWipeHangReportedAsUnconfirmed(t *testing.T) {
	k := mk(t, 8)
	k.c.blockWipe = make(chan struct{})
	k.BeginEmergency()
	ctx, c := dl(50 * time.Millisecond)
	defer c()
	if err := k.AwaitDestroyed(ctx); !errors.Is(err, ErrWipeUnconfirmed) {
		t.Fatalf("got %v", err)
	}
	close(k.c.blockWipe)
	ctx2, c2 := dl(time.Second)
	defer c2()
	if err := k.AwaitDestroyed(ctx2); err != nil {
		t.Fatal(err)
	}
}

// T-KLM-17 (R4-KLM-03): wipe panic is contained, recorded, and reported for escalation.
func TestWipePanicContainedAndReported(t *testing.T) {
	k := mk(t, 8)
	k.c.panicWipe = true
	k.BeginEmergency()
	ctx, c := dl(time.Second)
	defer c()
	if err := k.AwaitDestroyed(ctx); !errors.Is(err, ErrWipeFailed) {
		t.Fatalf("got %v", err)
	}
}

// T-KLM-18: provider panic poisons the key; nothing produced is returned.
func TestProviderPanicPoisons(t *testing.T) {
	k := mk(t, 8)
	k.c.panicSeal.Store(true)
	tk, _ := k.Reserve()
	dst := make([]byte, 0, 64)
	out, err := k.Seal(dst, tk, []byte("secret"))
	if !errors.Is(err, ErrProviderFault) || out != nil {
		t.Fatalf("got %v %v", out, err)
	}
	if k.st.Load()&(poisonBit|closingBit|discardBit) != poisonBit|closingBit|discardBit {
		t.Fatalf("not poisoned: %#x", k.st.Load())
	}
	if _, err := k.Reserve(); !errors.Is(err, ErrClosed) {
		t.Fatal("poisoned key admitted work")
	}
	ctx, c := dl(time.Second)
	defer c()
	if err := k.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
}

// T-KLM-19: waits require a deadline; await does not initiate shutdown.
func TestAwaitRequiresDeadline(t *testing.T) {
	k := mk(t, 8)
	if err := k.AwaitDestroyed(context.Background()); !errors.Is(err, ErrNoDeadline) {
		t.Fatal(err)
	}
	ctx, c := dl(time.Second)
	defer c()
	if err := k.AwaitDestroyed(ctx); !errors.Is(err, ErrNotClosing) {
		t.Fatal(err)
	}
}

// T-KLM-20: emergency from inside an operation cannot self-deadlock (bounded wait).
func TestEmergencyFromInsideOperationBounded(t *testing.T) {
	k := mk(t, 8)
	tk, _ := k.Reserve() // holds a lease
	k.BeginEmergency()
	ctx, c := dl(30 * time.Millisecond)
	defer c()
	if err := k.AwaitDestroyed(ctx); !errors.Is(err, ErrDrainPending) {
		t.Fatalf("got %v", err)
	}
	tk.Discard()
	ctx2, c2 := dl(time.Second)
	defer c2()
	if err := k.AwaitDestroyed(ctx2); err != nil {
		t.Fatal(err)
	}
}

// T-KLM-21: rotation after emergency is refused; the refused key is closed.
func TestInstallAfterEmergencyRefused(t *testing.T) {
	d := NewDevice()
	ctx, c := dl(time.Second)
	defer c()
	if err := d.Emergency(ctx); err != nil {
		t.Fatal(err)
	}
	k := mk(t, 8)
	if err := d.Install(k); !errors.Is(err, ErrDeviceClosed) {
		t.Fatal(err)
	}
	if err := k.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
}

// T-KLM-22: unmatched release is fail-stop and does not corrupt flags.
func TestUnmatchedReleaseFailStop(t *testing.T) {
	k := mk(t, 8)
	k.Retire()
	before := k.st.Load()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no panic")
			}
		}()
		k.release()
	}()
	if k.st.Load()&^(wipingBit|wipedBit) != before {
		t.Fatalf("flags corrupted: %#x -> %#x", before, k.st.Load())
	}
}

// T-KLM-23: stress -- rotation, sealing, sending and emergency concurrently.
func TestStressRotationSealSendEmergency(t *testing.T) {
	rounds := 300
	if testing.Short() {
		rounds = 30
	}
	var sends, sealed, refused int64
	for r := 0; r < rounds; r++ {
		d := NewDevice()
		var cur atomic.Pointer[DirectedKey]
		var all sync.Map
		k0 := mk(t, 1<<20)
		_ = d.Install(k0)
		cur.Store(k0)
		all.Store(k0, true)
		var stageA atomic.Bool
		var violation atomic.Int64
		hf := func(p string) {
			if p == "emergency:stageA" {
				stageA.Store(true) // stage A complete: from here on no send may start
			}
		}
		hookFn.Store(&hf)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for w := 0; w < 6; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					k := cur.Load()
					tk, err := k.Reserve()
					if err != nil {
						continue
					}
					out, err := k.Seal(nil, tk, []byte{1, 2, 3})
					if err != nil {
						continue
					}
					atomic.AddInt64(&sealed, 1)
					if !d.Egress.Enter() {
						continue
					}
					if stageA.Load() { // inside the egress section after stage A completed
						violation.Add(1)
					}
					_ = out
					atomic.AddInt64(&sends, 1)
					d.Egress.Exit()
				}
			}()
		}
		wg.Add(1)
		go func() { // rotation
			defer wg.Done()
			for i := 0; i < 50; i++ {
				nk := mk(t, 1<<20)
				all.Store(nk, true)
				if err := d.Install(nk); err != nil {
					atomic.AddInt64(&refused, 1)
					return
				}
				old := cur.Swap(nk)
				old.Retire()
			}
		}()
		time.Sleep(time.Duration(r%5) * 100 * time.Microsecond)
		ctx, c := dl(2 * time.Second)
		err := d.Emergency(ctx)
		hookFn.Store(nil)
		close(stop)
		wg.Wait()
		// all keys must end closed and wiped exactly once, never under an active seal
		all.Range(func(key, _ any) bool {
			k := key.(*DirectedKey)
			k.BeginEmergency() // idempotent for keys outside the snapshot (retired ones)
			if e := k.AwaitDestroyed(ctx); e != nil {
				t.Errorf("round %d: key not destroyed: %v", r, e)
			}
			if k.c.wipes.Load() != 1 || k.c.unsafe.Load() {
				t.Errorf("round %d: wipes=%d unsafe=%v", r, k.c.wipes.Load(), k.c.unsafe.Load())
			}
			return true
		})
		c()
		if err != nil {
			t.Fatalf("round %d: emergency: %v", r, err)
		}
		if v := violation.Load(); v != 0 {
			t.Fatalf("round %d: %d sends after stage A", r, v)
		}
	}
	t.Logf("%d rounds: %d sealed, %d sent, %d rotations refused after emergency; 0 sends after stage A; every key wiped exactly once, never under an active seal", rounds, sealed, sends, refused)
}
