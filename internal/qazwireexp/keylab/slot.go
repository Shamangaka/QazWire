//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// Package keylab is a non-cryptographic research harness for key lifecycle
// semantics. It exposes no session constructor, provider, or cryptography.
package keylab

import (
	"context"
	"errors"
	"sync/atomic"
)

const (
	closingBit = uint64(1) << 63
	wipingBit  = uint64(1) << 62
	refMask    = wipingBit - 1
)

var (
	errClosed    = errors.New("keylab: key is closing")
	errExhausted = errors.New("keylab: synthetic counter exhausted")
	errInvalid   = errors.New("keylab: invalid synthetic key")
	errDrainWait = errors.New("keylab: drain deadline expired; escalate isolation, do not wipe in-use key")
)

// labProcessor is deliberately unexported and has no production implementation.
// Its implementation may block (to test emergency shutdown) but must not
// panic. The model does not encrypt or authenticate any bytes.
type labProcessor interface {
	process(seq uint64, input []byte) ([]byte, error)
	wipe()
}

type record struct {
	sequence uint64
	payload  []byte
}

// keySlot is a test-only model of one directed key and its unique packet
// ticket sequence. There is no exported constructor or exported provider path.
// The state atomically combines admission and active-reference accounting.
type keySlot struct {
	state       atomic.Uint64
	next        atomic.Uint64
	maxMessages uint64
	p           labProcessor
	done        chan struct{}
}

func newKeySlot(p labProcessor, maxMessages uint64) (*keySlot, error) {
	if p == nil || maxMessages == 0 {
		return nil, errInvalid
	}
	return &keySlot{p: p, maxMessages: maxMessages, done: make(chan struct{})}, nil
}

// acquire prevents any newly admitted operation once closingBit is published.
func (k *keySlot) acquire() bool {
	if k == nil || k.done == nil || k.p == nil {
		return false
	}
	for {
		s := k.state.Load()
		if s&closingBit != 0 || s&refMask == refMask {
			return false
		}
		if k.state.CompareAndSwap(s, s+1) {
			return true
		}
	}
}

func (k *keySlot) release() {
	v := k.state.Add(^uint64(0)) // refs--, with a previous acquire guaranteed
	if v&closingBit != 0 && v&refMask == 0 {
		go k.finalize()
	}
}

// reserve gives a ticket once and never wraps or reuses a ticket.
func (k *keySlot) reserve() (uint64, error) {
	for {
		n := k.next.Load()
		if n >= k.maxMessages {
			return 0, errExhausted
		}
		if k.state.Load()&closingBit != 0 {
			return 0, errClosed
		}
		if k.next.CompareAndSwap(n, n+1) {
			return n, nil
		}
	}
}

// sealPacket runs the synthetic processor while owning an internal lease.
// Callers cannot supply a counter or a callback. A record produced after the
// closing bit is observed will be discarded. There is no egress wiring here:
// a real device must independently stop/drain outbound queues on emergency.
func (k *keySlot) sealPacket(input []byte) (record, error) {
	if !k.acquire() {
		return record{}, errClosed
	}
	defer k.release()

	seq, err := k.reserve()
	if err != nil {
		return record{}, err
	}
	out, err := k.p.process(seq, input)
	if k.state.Load()&closingBit != 0 {
		clear(out)
		return record{}, errClosed
	}
	if err != nil {
		clear(out)
		return record{}, err
	}
	return record{sequence: seq, payload: out}, nil
}

// beginEmergency is always non-blocking with respect to provider operations.
// Stage A: reject future admissions. Active operations may finish and are
// required to drop any post-close result. Stage C follows only after refs=0.
func (k *keySlot) beginEmergency() {
	if k == nil || k.done == nil || k.p == nil {
		return
	}
	s := k.state.Or(closingBit) | closingBit
	if s&refMask == 0 {
		go k.finalize()
	}
}

// finalize claims a single wipe only after the last active operation exits.
// wipingBit is a claim; done is closed after the wipe has finished.
func (k *keySlot) finalize() {
	for {
		s := k.state.Load()
		if s&closingBit == 0 || s&refMask != 0 || s&wipingBit != 0 {
			return
		}
		if k.state.CompareAndSwap(s, s|wipingBit) {
			k.p.wipe()
			close(k.done)
			return
		}
	}
}

// awaitDestroyed must be called by an owner outside packet operations.
// Timeout does not wipe a key in use. The caller must isolate/terminate the
// process if strict emergency timing is needed.
func (k *keySlot) awaitDestroyed(ctx context.Context) error {
	if k == nil || k.done == nil || k.p == nil || ctx == nil {
		return errInvalid
	}
	k.beginEmergency()
	select {
	case <-k.done:
		return nil
	case <-ctx.Done():
		return errDrainWait
	}
}
