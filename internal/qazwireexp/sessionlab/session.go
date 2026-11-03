//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// Package sessionlab is a NON-CRYPTOGRAPHIC research harness. It is not a
// VPN, a cryptographic key manager, or suitable for sending real packets.
package sessionlab

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
)

const (
	closingFlag   = uint64(1) << 63
	finishedFlag  = uint64(1) << 62
	referenceMask = finishedFlag - 1
)

var (
	errClosed    = errors.New("sessionlab: session closing")
	errExhausted = errors.New("sessionlab: synthetic counter exhausted")
	errInvalid   = errors.New("sessionlab: invalid synthetic dependency or limit")
	errDeadline  = errors.New("sessionlab: shutdown not complete; external isolation required")
)

// processor has no exported implementations. Its process method intentionally
// does NOT encrypt or authenticate. wipe only reports a simulated wipe event.
// The process and wipe methods MUST eventually return without panicking for a
// successful bounded drain. Real providers need stronger isolation.
type processor interface {
	process(ticket uint64, payload []byte) ([]byte, error)
	wipe()
}

// wire is a fake test sink, not an actual UDP writer. An actual network I/O
// driver MUST separately implement close/drain and packet-queue cancellation.
type wire interface {
	send(ticket uint64, payload []byte) error
}

type packet struct {
	ticket uint64
	data   []byte
}

// gate combines admission control and reference counting atomically. The
// finishedFlag marks the UNIQUE claim to the close action, NOT its completion.
type gate struct {
	state  atomic.Uint64
	done   chan struct{}
	finish func()
}

func newGate(finish func()) *gate {
	return &gate{done: make(chan struct{}), finish: finish}
}

func (g *gate) enter() bool {
	for {
		state := g.state.Load()
		if state&closingFlag != 0 || state&referenceMask == referenceMask {
			return false
		}
		if g.state.CompareAndSwap(state, state+1) {
			return true
		}
	}
}

func (g *gate) leave() {
	state := g.state.Add(^uint64(0)) // only entered operations may call leave
	if state&closingFlag != 0 && state&referenceMask == 0 {
		g.startFinish()
	}
}

// startFinish never invokes finish synchronously: beginClose must not wait on
// an in-flight or permanently blocked synthetic provider or network writer.
func (g *gate) startFinish() {
	for {
		state := g.state.Load()
		if state&closingFlag == 0 || state&referenceMask != 0 || state&finishedFlag != 0 {
			return
		}
		if g.state.CompareAndSwap(state, state|finishedFlag) {
			go func() {
				g.finish() // panic or hang must NOT be mistaken for completion
				close(g.done)
			}()
			return
		}
	}
}

func (g *gate) beginClose() {
	state := g.state.Or(closingFlag) | closingFlag
	if state&referenceMask == 0 {
		g.startFinish()
	}
}

// key owns one synthetic directed-key lifetime and a bounded monotonic
// sequence. A reserved ticket is never reused, even on processing failure.
type key struct {
	gate *gate
	next atomic.Uint64
	max  uint64
	p    processor
}

func newKey(p processor, max uint64) *key {
	k := &key{max: max, p: p}
	k.gate = newGate(p.wipe)
	return k
}

func (k *key) reserve() (uint64, error) {
	for {
		if k.gate.state.Load()&closingFlag != 0 {
			return 0, errClosed
		}
		n := k.next.Load()
		if n >= k.max {
			return 0, errExhausted
		}
		if k.next.CompareAndSwap(n, n+1) {
			// A concurrent beginClose may occur after the preceding check.
			// In that case this unique ticket is *burned*, never reused.
			if k.gate.state.Load()&closingFlag != 0 {
				return 0, errClosed
			}
			return n, nil
		}
	}
}

func (k *key) seal(payload []byte) (packet, error) {
	if !k.gate.enter() {
		return packet{}, errClosed
	}
	defer k.gate.leave()
	ticket, err := k.reserve()
	if err != nil {
		return packet{}, err
	}
	result, err := k.p.process(ticket, payload)
	if k.gate.state.Load()&closingFlag != 0 {
		clear(result)
		return packet{}, errClosed
	}
	if err != nil {
		clear(result)
		return packet{}, err
	}
	return packet{ticket: ticket, data: result}, nil
}

// egress owns the ONLY synthetic send path. Admission is checked immediately
// before calling the fake send function. Operations admitted BEFORE closing
// may still complete AFTER beginClose; awaitDrained must confirm completion.
// A real VPN must gate actual I/O, not merely this laboratory API.
type egress struct {
	gate *gate
	w    wire
}

func newEgress(w wire) *egress {
	return &egress{gate: newGate(func() {}), w: w}
}

func (e *egress) dispatch(p packet) error {
	if !e.gate.enter() {
		return errClosed
	}
	defer e.gate.leave()
	return e.w.send(p.ticket, p.data)
}

// session is intentionally unexported. No production path can construct it.
type session struct {
	k *key
	e *egress
}

func validDependency(v any) bool {
	if v == nil {
		return false
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !r.IsNil()
	}
	return true
}

func newSession(p processor, w wire, maxTickets uint64) (*session, error) {
	if !validDependency(p) || !validDependency(w) || maxTickets == 0 {
		return nil, errInvalid
	}
	return &session{k: newKey(p, maxTickets), e: newEgress(w)}, nil
}

// prepare creates only synthetic output; it does not authenticate/encrypt.
func (s *session) prepare(payload []byte) (packet, error) {
	return s.k.seal(payload)
}

// dispatch is the only route to the synthetic wire sink.
func (s *session) dispatch(p packet) error {
	return s.e.dispatch(p)
}

// beginEmergency is a nonblocking stage-A gate. Egress closes FIRST; any
// remaining pre-admitted sends are handled by awaitDrained. This cannot
// recall packets already sent or queued outside the modeled egress boundary.
func (s *session) beginEmergency() {
	s.e.gate.beginClose()
	s.k.gate.beginClose()
}

// awaitDrained blocks only until the supplied context expires. A timeout
// NEVER claims secret erasure; the external orchestrator must terminate an
// isolated process/module if a hard emergency deadline is required.
func (s *session) awaitDrained(ctx context.Context) error {
	if ctx == nil {
		return errInvalid
	}
	s.beginEmergency()
	for _, done := range []<-chan struct{}{s.e.gate.done, s.k.gate.done} {
		select {
		case <-done:
		case <-ctx.Done():
			return errDeadline
		}
	}
	return nil
}
