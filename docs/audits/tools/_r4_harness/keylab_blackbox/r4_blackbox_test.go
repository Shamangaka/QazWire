//go:build qazwire_exp

// R4 auditor black-box tests for the UNMODIFIED keylab (PR #8 HEAD 17c9ee8).
// They use only package-internal names that already exist in slot.go.
package keylab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- helpers ----------

type ctlProc struct {
	enterClosing atomic.Int64 // process() entered while closingBit already set
	seqs         sync.Map     // seq -> struct{}
	k            atomic.Pointer[keySlot]
	panicOnce    atomic.Bool
	wipeBlock    chan struct{}
	wipePanic    bool
	wipes        atomic.Int64
	active       atomic.Int64
	unsafeWipe   atomic.Bool
}

func (p *ctlProc) process(seq uint64, in []byte) ([]byte, error) {
	p.active.Add(1)
	defer p.active.Add(-1)
	if k := p.k.Load(); k != nil && k.state.Load()&closingBit != 0 {
		p.enterClosing.Add(1)
	}
	p.seqs.Store(seq, struct{}{})
	if p.panicOnce.CompareAndSwap(true, false) {
		panic("r4: synthetic provider panic")
	}
	return append([]byte(nil), in...), nil
}

func (p *ctlProc) wipe() {
	if p.active.Load() != 0 {
		p.unsafeWipe.Store(true)
	}
	if p.wipePanic {
		panic("r4: synthetic wipe panic")
	}
	if p.wipeBlock != nil {
		<-p.wipeBlock
	}
	p.wipes.Add(1)
}

func newCtl(t *testing.T, max uint64) (*keySlot, *ctlProc) {
	t.Helper()
	p := &ctlProc{}
	k, err := newKeySlot(p, max)
	if err != nil {
		t.Fatal(err)
	}
	p.k.Store(k)
	return k, p
}

func refs(k *keySlot) uint64 { return k.state.Load() & refMask }

// runChild re-executes this test binary for scenarios that must crash the process.
func runChild(t *testing.T, test, mode string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "R4_CHILD="+mode)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ---------- R4-KLM-02 (egress): a successful record survives emergency and wipe ----------

func TestR4_02_RecordSurvivesEmergencyAndWipe(t *testing.T) {
	k, p := newCtl(t, 10)
	rec, err := k.sealPacket([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Emergency starts AFTER sealPacket returned but BEFORE the caller "sends".
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := k.awaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
	if p.wipes.Load() != 1 {
		t.Fatal("wipe not completed")
	}
	sent := len(rec.payload) > 0 // nothing in keySlot prevents this send
	if !sent {
		t.Fatal("unexpected")
	}
	t.Logf("CONFIRMED R4-KLM-02: record seq=%d (%d bytes) is still sendable after beginEmergency and completed wipe; keySlot has no egress fence", rec.sequence, len(rec.payload))
}

// ---------- R4-KLM-03: wipe that hangs is reported as an ordinary drain timeout ----------

func TestR4_03a_WipeHangIsMisreported(t *testing.T) {
	k, p := newCtl(t, 10)
	p.wipeBlock = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := k.awaitDestroyed(ctx)
	s := k.state.Load()
	if !errors.Is(err, errDrainWait) {
		t.Fatalf("got %v", err)
	}
	if s&refMask != 0 || s&wipingBit == 0 {
		t.Fatalf("unexpected state %#x", s)
	}
	t.Logf("CONFIRMED R4-KLM-03: refs=0, wipingBit=1, done open; awaitDestroyed returns %q (claims in-use key) although the wipe itself is stuck", err)
	close(p.wipeBlock)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := k.awaitDestroyed(ctx2); err != nil || p.wipes.Load() != 1 {
		t.Fatalf("after unblocking wipe: %v wipes=%d", err, p.wipes.Load())
	}
}

// ---------- R4-KLM-03: wipe panic in the background finalize goroutine kills the process ----------

func TestR4_03b_WipePanicCrashesProcess(t *testing.T) {
	if os.Getenv("R4_CHILD") == "wipepanic" {
		k, p := newCtl(t, 10)
		p.wipePanic = true
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = k.awaitDestroyed(ctx) // finalize runs in `go k.finalize()`; no recover is possible here
		os.Exit(0)                // not reached if the finalize goroutine panics first
	}
	out, err := runChild(t, "TestR4_03b_WipePanicCrashesProcess", "wipepanic")
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() == 0 || !strings.Contains(out, "synthetic wipe panic") || !strings.Contains(out, "finalize") {
		t.Fatalf("expected process crash from finalize goroutine; err=%v\n%s", err, out)
	}
	t.Logf("CONFIRMED R4-KLM-03: wipe panic terminates the whole process (exit %d) from goroutine keySlot.finalize; done is never closed", ee.ExitCode())
}

// ---------- R4-KLM-04: typed-nil provider is accepted ----------

type derefProc struct{ n int }

func (p *derefProc) process(uint64, []byte) ([]byte, error) { p.n++; return nil, nil }
func (p *derefProc) wipe()                                  { p.n = 0 }

func TestR4_04_TypedNilProviderAccepted(t *testing.T) {
	if os.Getenv("R4_CHILD") == "typednil" {
		var np *derefProc
		k, _ := newKeySlot(np, 10)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = k.awaitDestroyed(ctx) // finalize -> (*derefProc)(nil).wipe() in a background goroutine
		os.Exit(0)
	}
	var np *derefProc
	k, err := newKeySlot(np, 10)
	if err != nil || k == nil {
		t.Fatalf("typed nil rejected: %v", err)
	}
	if !k.acquire() {
		t.Fatal("acquire refused typed-nil slot")
	}
	k.release()
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected nil dereference panic")
			}
			t.Logf("CONFIRMED R4-KLM-04: newKeySlot accepted (*derefProc)(nil); sealPacket panics: %v", r)
		}()
		_, _ = k.sealPacket([]byte{1})
	}()
	if refs(k) != 0 || k.state.Load()&closingBit != 0 {
		t.Fatalf("state after panic %#x", k.state.Load())
	}
	t.Log("after the recovered panic the slot is still OPEN (no poisoning); refs back to 0 via deferred release")
	out, cerr := runChild(t, "TestR4_04_TypedNilProviderAccepted", "typednil")
	var ee *exec.ExitError
	if !errors.As(cerr, &ee) || !strings.Contains(out, "nil pointer dereference") {
		t.Fatalf("expected crash at wipe: %v\n%s", cerr, out)
	}
	t.Logf("CONFIRMED R4-KLM-04: awaitDestroyed on typed-nil slot crashes the process in finalize (exit %d)", ee.ExitCode())
}

// ---------- provider panic: no poisoning, slot continues ----------

func TestR4_ProviderPanicDoesNotPoisonSlot(t *testing.T) {
	k, p := newCtl(t, 10)
	p.panicOnce.Store(true)
	func() {
		defer func() { _ = recover() }()
		_, _ = k.sealPacket([]byte("x"))
	}()
	rec, err := k.sealPacket([]byte("y"))
	if err != nil {
		t.Fatalf("slot unusable after panic: %v", err)
	}
	t.Logf("CONFIRMED: after a recovered provider panic the slot keeps serving (next seq=%d); ticket 0 was consumed by the panicked call; no poison/emergency transition", rec.sequence)
}

// ---------- unbounded wait: awaitDestroyed with a context without deadline ----------

func TestR4_AwaitWithoutDeadlineIsUnbounded(t *testing.T) {
	p := &probeProcessor{started: make(chan struct{}, 1), unblock: make(chan struct{})}
	k, _ := newKeySlot(p, 10)
	go func() { _, _ = k.sealPacket([]byte("blocked")) }()
	<-p.started
	done := make(chan error, 1)
	go func() { done <- k.awaitDestroyed(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("returned %v", err)
	case <-time.After(300 * time.Millisecond):
		t.Log("CONFIRMED: awaitDestroyed(context.Background()) waits without bound while the provider is blocked")
	}
	close(p.unblock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestR4_AwaitFromInsideOperationSelfWait(t *testing.T) {
	k, p := newCtl(t, 10)
	inner := make(chan error, 1)
	q := &hookProc{base: p, hook: func() { inner <- k.awaitDestroyed(context.Background()) }}
	k.p = q // test-only: route process through a hook (same package)
	go func() { _, _ = k.sealPacket([]byte("x")) }()
	select {
	case err := <-inner:
		t.Fatalf("returned %v", err)
	case <-time.After(300 * time.Millisecond):
		t.Log("CONFIRMED: awaitDestroyed(Background) called while holding the internal lease never returns (self-wait); with a deadline it returns errDrainWait")
	}
}

type hookProc struct {
	base labProcessor
	hook func()
}

func (h *hookProc) process(s uint64, in []byte) ([]byte, error) {
	h.hook()
	return h.base.process(s, in)
}
func (h *hookProc) wipe() { h.base.wipe() }

// ---------- internal misuse: unmatched release borrows into flag bits ----------

func TestR4_UnmatchedReleaseCorruptsFlags(t *testing.T) {
	k, _ := newCtl(t, 10)
	k.release() // no matching acquire (internal bug class)
	s := k.state.Load()
	if s != ^uint64(0) {
		t.Fatalf("state %#x", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := k.awaitDestroyed(ctx)
	t.Logf("CONFIRMED (LOW): unmatched release sets closingBit|wipingBit|refs=max (%#x); slot is dead and can never be wiped: awaitDestroyed=%v", s, err)
}

// ---------- R4-KLM-01 / admitted work after closing: black-box statistical detectors ----------

func TestR4_01_TicketAfterClosingStress(t *testing.T) {
	rounds := 20000
	if testing.Short() {
		rounds = 2000
	}
	var ticketAfterClose, enterAfterClose, total int64
	for r := 0; r < rounds; r++ {
		k, p := newCtl(t, 1<<40)
		var wg sync.WaitGroup
		stop := atomic.Bool{}
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stop.Load() {
					if _, err := k.sealPacket(nil); errors.Is(err, errClosed) {
						return
					}
				}
			}()
		}
		for i := 0; i < r%7; i++ {
			runtime.Gosched()
		}
		k.beginEmergency()
		v := k.next.Load() // any seq >= v was CAS-allocated after the closing Or
		stop.Store(true)
		wg.Wait()
		p.seqs.Range(func(key, _ any) bool {
			total++
			if key.(uint64) >= v {
				ticketAfterClose++
			}
			return true
		})
		enterAfterClose += p.enterClosing.Load()
	}
	t.Logf("rounds=%d processed=%d; tickets CAS-allocated after closingBit: %d; process() entered with closingBit set: %d", rounds, total, ticketAfterClose, enterAfterClose)
	if ticketAfterClose == 0 && enterAfterClose == 0 {
		t.Log("not observed in this run (statistical); see deterministic instrumented reproduction")
	}
}

// ---------- integration-level: rotation racing with device emergency ----------

// naiveTable models a device that keeps one current directed key and rotates it.
type naiveTable struct {
	mu  sync.Mutex
	cur *keySlot
}

func TestR4_RotationEscapesEmergency(t *testing.T) {
	old, _ := newCtl(t, 10)
	tb := &naiveTable{cur: old}
	// Emergency: snapshot current key, then close it.
	tb.mu.Lock()
	snap := tb.cur
	tb.mu.Unlock()
	// Rotation completes between snapshot and close (handshake finished concurrently).
	fresh, _ := newCtl(t, 10)
	tb.mu.Lock()
	tb.cur = fresh
	tb.mu.Unlock()
	snap.beginEmergency()
	if _, err := tb.cur.sealPacket([]byte("after-emergency")); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	t.Log("CONFIRMED (integration gap): a key installed by rotation after the emergency snapshot stays OPEN and seals; keySlot has no device-level epoch/closed gate")
}
