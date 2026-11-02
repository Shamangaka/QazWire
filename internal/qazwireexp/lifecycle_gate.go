//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// Lifecycle coordination ONLY. This code holds and wipes no key material.
package qazwireexp

import (
	"errors"
	"sync"
)

var (
	ErrOperationClosed = errors.New("qazwireexp: operation gate is closing or closed")
	ErrNilOperation    = errors.New("qazwireexp: nil operation")
)

// OperationGate implements the concurrency barrier required before future
// cryptographic key destruction. Use admits a callback only before shutdown;
// CloseAndDrain waits for admitted callbacks to finish and forbids new ones.
//
// This gate DOES NOT encrypt, authenticate, hold, or erase keys. Future users
// must run every operation that accesses a key through Use, and invoke the
// actual provider Destroy only AFTER CloseAndDrain completes. Never call
// CloseAndDrain from a Use callback: that would wait for itself.
//
// The zero value is ready for use. CloseAndDrain is idempotent and safe for
// concurrent callers. Use releases its lease even if a callback panics.
type OperationGate struct {
	mu      sync.Mutex
	active  uint64
	closing bool
	done    chan struct{}
}

// Use runs fn while holding a logical lease. fn runs outside the gate mutex.
func (g *OperationGate) Use(fn func() error) error {
	if fn == nil {
		return ErrNilOperation
	}
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		return ErrOperationClosed
	}
	g.active++
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		g.active--
		if g.closing && g.active == 0 {
			close(g.done)
		}
		g.mu.Unlock()
	}()
	return fn()
}

// CloseAndDrain prevents new Use calls and waits for current callbacks.
// It does not destroy keys or call any user-supplied callback.
func (g *OperationGate) CloseAndDrain() {
	g.mu.Lock()
	if !g.closing {
		g.closing = true
		g.done = make(chan struct{})
		if g.active == 0 {
			close(g.done)
		}
	}
	done := g.done
	g.mu.Unlock()
	<-done
}
