package klmref

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// observingProvider records ordering violations: a wipe while an operation is
// inside the provider, or an operation entering after the wipe.
type observingProvider struct {
	inside     atomic.Int64
	wiped      atomic.Bool
	wipes      atomic.Int64
	violations atomic.Int64
	block      chan struct{} // if non-nil, seal blocks until closed
	entered    chan struct{}
	enterOnce  sync.Once
}

func (p *observingProvider) seal(dst, pt []byte) []byte {
	p.inside.Add(1)
	defer p.inside.Add(-1)
	if p.wiped.Load() {
		p.violations.Add(1)
	}
	if p.block != nil {
		p.enterOnce.Do(func() { close(p.entered) })
		<-p.block
	}
	if p.wiped.Load() {
		p.violations.Add(1)
	}
	return append(dst, pt...)
}

func (p *observingProvider) wipe() {
	if p.inside.Load() != 0 {
		p.violations.Add(1)
	}
	p.wiped.Store(true)
	p.wipes.Add(1)
}

// Mandatory test requested by the owner: emergency close while Seal is blocked
// inside the provider.
func TestEmergencyCloseWhileSealBlockedInProvider(t *testing.T) {
	p := &observingProvider{block: make(chan struct{}), entered: make(chan struct{})}
	k := newDirectedKey(p)
	res := make(chan error, 1)
	go func() { _, err := k.Seal(nil, []byte("pt")); res <- err }()
	<-p.entered

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := k.Shutdown(ctx); !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("Shutdown = %v, want ErrDrainTimeout", err)
	}
	if p.wiped.Load() {
		t.Fatal("key wiped while Seal is active")
	}
	if _, err := k.Seal(nil, []byte("new")); !errors.Is(err, ErrKeyClosed) {
		t.Fatalf("new Seal after BeginShutdown = %v, want ErrKeyClosed", err)
	}
	close(p.block) // provider unblocks
	if err := <-res; !errors.Is(err, ErrKeyClosed) {
		t.Fatalf("in-flight Seal output must be discarded, got %v", err)
	}
	select {
	case <-k.drained:
	case <-time.After(time.Second):
		t.Fatal("last release did not wipe")
	}
	if p.wipes.Load() != 1 || p.violations.Load() != 0 {
		t.Fatalf("wipes=%d violations=%d", p.wipes.Load(), p.violations.Load())
	}
}

// Shutdown issued from inside an operation must not self-deadlock.
func TestShutdownFromInsideOperationDoesNotDeadlock(t *testing.T) {
	p := &observingProvider{}
	k := newDirectedKey(p)
	if !k.acquire() {
		t.Fatal("acquire")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := k.Shutdown(ctx) // caller still holds a lease
	cancel()
	if !errors.Is(err, ErrDrainTimeout) || p.wiped.Load() {
		t.Fatalf("err=%v wiped=%v", err, p.wiped.Load())
	}
	k.release()
	if !p.wiped.Load() || p.violations.Load() != 0 {
		t.Fatal("wipe after last release expected")
	}
}

func TestStressNoWipeUnderActiveOperation(t *testing.T) {
	var ops atomic.Int64
	rounds := 2000
	if testing.Short() {
		rounds = 100
	}
	for round := 0; round < rounds; round++ {
		p := &observingProvider{}
		k := newDirectedKey(p)
		var wg sync.WaitGroup
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					if _, err := k.Seal(nil, []byte{1}); err != nil {
						return
					}
					ops.Add(1)
				}
			}()
		}
		time.Sleep(time.Duration(round%4) * 50 * time.Microsecond)
		if err := k.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		if p.violations.Load() != 0 || p.wipes.Load() != 1 {
			t.Fatalf("round %d: violations=%d wipes=%d", round, p.violations.Load(), p.wipes.Load())
		}
	}
	t.Logf("%d rounds, %d successful Seal calls, 0 violations, exactly one wipe per key", rounds, ops.Load())
}

type nopProvider struct{}

func (nopProvider) seal(dst, pt []byte) []byte { return append(dst, pt...) }
func (nopProvider) wipe()                      {}

func BenchmarkLeaseParallel(b *testing.B) {
	k := newDirectedKey(nopProvider{})
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if k.acquire() {
				k.release()
			}
		}
	})
}
