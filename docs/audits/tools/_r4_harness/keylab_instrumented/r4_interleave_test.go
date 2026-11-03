//go:build qazwire_exp

// Deterministic interleavings on an instrumented copy of keylab/slot.go
// (only r4hook calls inserted; see make_instrumented.py).
package keylab

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pausePoint struct {
	name    string
	arrived chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func pauseAt(t *testing.T, name string) *pausePoint {
	pp := &pausePoint{name: name, arrived: make(chan struct{}), resume: make(chan struct{})}
	f := func(point string) {
		if point == pp.name {
			pp.once.Do(func() { close(pp.arrived); <-pp.resume })
		}
	}
	r4hookFn.Store(&f)
	t.Cleanup(func() { r4hookFn.Store(nil) })
	return pp
}

func (pp *pausePoint) wait(t *testing.T) {
	t.Helper()
	select {
	case <-pp.arrived:
	case <-time.After(2 * time.Second):
		t.Fatalf("goroutine never reached %s", pp.name)
	}
}

type recProc struct {
	k             atomic.Pointer[keySlot]
	mu            sync.Mutex
	entries       []string
	wipes, active atomic.Int64
	wipeWhileBusy atomic.Bool
}

func (p *recProc) process(seq uint64, in []byte) ([]byte, error) {
	p.active.Add(1)
	defer p.active.Add(-1)
	closing := p.k.Load().state.Load()&closingBit != 0
	p.mu.Lock()
	p.entries = append(p.entries, map[bool]string{true: "process(seq) entered with closingBit=1", false: "process(seq) entered with closingBit=0"}[closing])
	p.mu.Unlock()
	return append([]byte(nil), in...), nil
}
func (p *recProc) wipe() {
	if p.active.Load() != 0 {
		p.wipeWhileBusy.Store(true)
	}
	p.wipes.Add(1)
}

func newRec(t *testing.T) (*keySlot, *recProc) {
	p := &recProc{}
	k, err := newKeySlot(p, 16)
	if err != nil {
		t.Fatal(err)
	}
	p.k.Store(k)
	return k, p
}

// R4-KLM-01: T1 passes the closing check in reserve(); T2 sets closingBit; T1's CAS succeeds.
func TestR4I_01_TicketIssuedAfterClosing(t *testing.T) {
	k, p := newRec(t)
	pp := pauseAt(t, "reserve:checked")
	res := make(chan error, 1)
	go func() { _, err := k.sealPacket([]byte("a")); res <- err }() // T1
	pp.wait(t)                                                      // T1: acquire ok, closing==0 observed
	k.beginEmergency()                                              // T2: Or(closingBit), refs=1 -> no finalize yet
	if k.state.Load()&closingBit == 0 {
		t.Fatal("closing not set")
	}
	nBefore := k.next.Load()
	close(pp.resume) // T1: next.CAS(0,1) succeeds AFTER closing
	err := <-res
	if k.next.Load() != nBefore+1 {
		t.Fatalf("ticket not issued: next=%d", k.next.Load())
	}
	t.Logf("CONFIRMED R4-KLM-01: ticket %d CAS-allocated after closingBit; %v; sealPacket -> %v (output discarded)", nBefore, p.entries, err)
	if !errors.Is(err, errClosed) {
		t.Fatalf("output not discarded: %v", err)
	}
}

// Admitted work enters the provider after closingBit (independent of the reserve race).
func TestR4I_03_ProcessStartsAfterClosing(t *testing.T) {
	k, p := newRec(t)
	pp := pauseAt(t, "seal:reserved")
	res := make(chan error, 1)
	go func() { _, err := k.sealPacket([]byte("a")); res <- err }()
	pp.wait(t)
	k.beginEmergency()
	close(pp.resume)
	err := <-res
	t.Logf("CONFIRMED: %v after beginEmergency; sealPacket -> %v", p.entries, err)
}

// R4-KLM-02: T1 passes the post-process closing check; T2 closes; T1 still returns a record.
func TestR4I_02_RecordReturnedAfterClosing(t *testing.T) {
	k, p := newRec(t)
	pp := pauseAt(t, "seal:postcheck")
	type out struct {
		r   record
		err error
	}
	res := make(chan out, 1)
	go func() { r, err := k.sealPacket([]byte("payload")); res <- out{r, err} }()
	pp.wait(t)
	k.beginEmergency()
	closedAt := k.state.Load()
	close(pp.resume)
	o := <-res
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := k.awaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
	if o.err != nil || len(o.r.payload) == 0 || closedAt&closingBit == 0 || p.wipes.Load() != 1 {
		t.Fatalf("unexpected: %+v closedAt=%#x wipes=%d", o, closedAt, p.wipes.Load())
	}
	t.Logf("CONFIRMED R4-KLM-02: closingBit set (state=%#x) BEFORE sealPacket returned, yet it returned seq=%d with %d payload bytes and nil error; wipe completed afterwards", closedAt, o.r.sequence, len(o.r.payload))
}

// R4-KLM-03: during the wipe window awaitDestroyed reports 'in-use key' although refs=0.
func TestR4I_04_WipeWindowMisreported(t *testing.T) {
	k, p := newRec(t)
	pp := pauseAt(t, "finalize:claimed")
	k.beginEmergency() // refs=0 -> go finalize()
	pp.wait(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := k.awaitDestroyed(ctx)
	s := k.state.Load()
	t.Logf("CONFIRMED R4-KLM-03: state=%#x (refs=%d, wiping=%v), awaitDestroyed=%v", s, s&refMask, s&wipingBit != 0, err)
	if !errors.Is(err, errDrainWait) || s&refMask != 0 {
		t.Fatal("unexpected")
	}
	close(pp.resume)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := k.awaitDestroyed(ctx2); err != nil || p.wipes.Load() != 1 {
		t.Fatal(err)
	}
}
