//go:build qazwire_exp

package qazwireexp

import (
	"sync/atomic"
	"testing"
)

// Alternative admission word (KLM R2 §5 style): bit63 = closing, low bits = active count.
type atomicGate struct{ w atomic.Uint64 }

const closingBit = uint64(1) << 63

func (g *atomicGate) acquire() bool {
	for {
		v := g.w.Load()
		if v&closingBit != 0 {
			return false
		}
		if g.w.CompareAndSwap(v, v+1) {
			return true
		}
	}
}
func (g *atomicGate) release() { g.w.Add(^uint64(0)) }

func BenchmarkR3MutexGateParallel(b *testing.B) {
	var g OperationGate
	fn := func() error { return nil }
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = g.Use(fn)
		}
	})
}

func BenchmarkR3AtomicGateParallel(b *testing.B) {
	var g atomicGate
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if g.acquire() {
				g.release()
			}
		}
	})
}
