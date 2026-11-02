//go:build qazwire_exp

package qazwireexp

import (
	"sync/atomic"
	"testing"
)

// R3-T7: a callback can leak work past its lease (goroutine started inside Use).
// The gate cannot see it, so "Destroy after CloseAndDrain" races with the escaped op.
func TestR3ClosureEscapeBypassesLease(t *testing.T) {
	var g OperationGate
	var destroyed atomic.Bool
	escapedRanAfterDestroy := make(chan bool, 1)
	start := make(chan struct{})
	_ = g.Use(func() error {
		go func() { // escaped "Seal" continuing after the lease is released
			<-start
			escapedRanAfterDestroy <- destroyed.Load()
		}()
		return nil
	})
	g.CloseAndDrain()
	destroyed.Store(true) // owner believes it is now safe to wipe
	close(start)
	if <-escapedRanAfterDestroy {
		t.Log("CONFIRMED: escaped operation observed destroyed key state after drain (lease bypass via closure)")
	} else {
		t.Fatal("unexpected ordering")
	}
}
