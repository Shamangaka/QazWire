// Package klmref is an AUDITOR REFERENCE MODEL (R3) of the staged emergency
// shutdown that resolves KL-2 vs KL-10. It contains NO cryptography: the
// "provider" is an opaque interface used only to observe ordering. It is not
// production code and is not part of the QazWire module.
package klmref

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

const (
	closingBit = uint64(1) << 63 // stage A: no new Acquire; in-flight outputs are discarded
	wipedBit   = uint64(1) << 62 // stage C: wipe has been claimed (exactly once)
	refMask    = wipedBit - 1    // bits 0..61: in-flight operations
)

var (
	ErrKeyClosed    = errors.New("klmref: key is closing or destroyed")
	ErrDrainTimeout = errors.New("klmref: drain deadline exceeded; key NOT wiped, escalation required")
)

// provider is unexported: only this package can call into key material, and no
// caller-supplied callback ever runs while a lease is held (no reentrancy path).
type provider interface {
	seal(dst, pt []byte) []byte
	wipe()
}

// DirectedKey owns the provider. There is no exported way to reach it.
type DirectedKey struct {
	state   atomic.Uint64
	p       provider
	once    sync.Once
	drained chan struct{}
}

func newDirectedKey(p provider) *DirectedKey {
	return &DirectedKey{p: p, drained: make(chan struct{})}
}

func (k *DirectedKey) acquire() bool {
	for {
		s := k.state.Load()
		if s&closingBit != 0 {
			return false
		}
		if s&refMask == refMask {
			return false // saturation: fail closed
		}
		if k.state.CompareAndSwap(s, s+1) {
			return true
		}
	}
}

func (k *DirectedKey) release() {
	s := k.state.Add(^uint64(0))
	if s&closingBit != 0 && s&refMask == 0 {
		k.tryWipe()
	}
}

// tryWipe runs the wipe exactly once, and only when CLOSING is set and refs==0.
func (k *DirectedKey) tryWipe() {
	for {
		s := k.state.Load()
		if s&wipedBit != 0 || s&closingBit == 0 || s&refMask != 0 {
			return
		}
		if k.state.CompareAndSwap(s, s|wipedBit) {
			k.p.wipe()
			k.once.Do(func() { close(k.drained) })
			return
		}
	}
}

// Seal acquires and releases the lease internally. Output produced after
// shutdown began is discarded (stage A egress cut), never returned.
func (k *DirectedKey) Seal(dst, pt []byte) ([]byte, error) {
	if !k.acquire() {
		return nil, ErrKeyClosed
	}
	defer k.release()
	out := k.p.seal(dst, pt)
	if k.state.Load()&closingBit != 0 {
		clear(out[len(dst):])
		return nil, ErrKeyClosed
	}
	return out, nil
}

// BeginShutdown is stage A: non-blocking, safe from any goroutine (including
// one that is itself inside an operation): it never waits.
func (k *DirectedKey) BeginShutdown() {
	s := k.state.Or(closingBit) | closingBit
	if s&refMask == 0 {
		k.tryWipe()
	}
}

// Shutdown runs stages A-C with a deadline. On timeout the key is NOT wiped
// (never zeroize under an active operation); the last release wipes it later.
// The caller must escalate (stage D: terminate the isolated crypto process).
func (k *DirectedKey) Shutdown(ctx context.Context) error {
	k.BeginShutdown()
	select {
	case <-k.drained:
		return nil
	case <-ctx.Done():
		return ErrDrainTimeout
	}
}
