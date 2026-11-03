//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// Package sessionlab is an isolated NON-CRYPTOGRAPHIC concurrency laboratory.
// It must never be wired into a VPN transport or real network send path.
package sessionlab

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)

const (
	closingFlag   = uint64(1) << 63
	finishedFlag  = uint64(1) << 62 // finishing has been CLAIMED, not completed
	poisonFlag    = uint64(1) << 61
	failedFlag    = uint64(1) << 60
	discardFlag   = uint64(1) << 59
	referenceMask = discardFlag - 1
)

var (
	errClosed          = errors.New("sessionlab: session closing")
	errExhausted       = errors.New("sessionlab: synthetic counter exhausted")
	errInvalid         = errors.New("sessionlab: invalid synthetic dependency or limit")
	errDeadline        = errors.New("sessionlab: shutdown not complete; external isolation required")
	errNoDeadline      = errors.New("sessionlab: shutdown wait requires a deadline")
	errProviderFault   = errors.New("sessionlab: synthetic provider fault; key poisoned")
	errWipeFailed      = errors.New("sessionlab: synthetic wipe failed; destruction NOT confirmed")
	errTicket          = errors.New("sessionlab: ticket absent, foreign or already spent")
	errProviderReuse   = errors.New("sessionlab: provider has already been claimed")
	errWipeUnconfirmed = fmt.Errorf("%w: wipe started but is unconfirmed", errDeadline)
)

// Unexported test doubles. Neither process nor wipe provides cryptography.
// Per-provider one-time ownership avoids an immortal process-global map.
type providerClaim struct{ claimed atomic.Bool }
func (c *providerClaim) claim() bool { return c.claimed.CompareAndSwap(false, true) }

// The test-only provider is defined in this package; real providers must be
// concrete and module-private rather than accepting arbitrary interfaces.
type processor interface {
	process(ticket uint64, payload []byte) ([]byte, error)
	wipe()
	claim() bool
}

type wire interface {
	send(ticket uint64, payload []byte) error
}

// packetGuard transfers the key operation reference across the async queue.
// A packet must be dispatched or discarded exactly once. Shutdown discards
// all queued guards before waiting for the key to be wiped.
type packetGuard struct {
	owner *key
	used  atomic.Bool
}

type packet struct {
	ticket uint64
	data   []byte
	guard  *packetGuard
}

// gate combines monotone lifecycle flags with in-flight refs. The completion
// channel is closed only after the finish function has returned or panicked.
// A finish panic records failure; NO actual secret erasure is claimed.
type gate struct {
	state  atomic.Uint64
	done   chan struct{}
	finish func()
	onFail func() // must be non-blocking; installed before publishing gate
}

func newGate(finish func()) *gate { return &gate{done: make(chan struct{}), finish: finish} }

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
	for {
		state := g.state.Load()
		if state&referenceMask == 0 {
			panic("sessionlab: unpaired gate.leave")
		}
		if g.state.CompareAndSwap(state, state-1) {
			if state&closingFlag != 0 && state&referenceMask == 1 {
				g.startFinish()
			}
			return
		}
	}
}

// startFinish must not wait on providers or writers in the calling goroutine.
func (g *gate) startFinish() {
	for {
		state := g.state.Load()
		if state&closingFlag == 0 || state&referenceMask != 0 || state&finishedFlag != 0 {
			return
		}
		if g.state.CompareAndSwap(state, state|finishedFlag) {
			go func() {
				defer close(g.done)
				defer func() {
					if recover() != nil {
						g.state.Or(failedFlag)
						if g.onFail != nil {
							g.onFail()
						}
					}
				}()
				g.finish()
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

func (g *gate) poison() {
	state := g.state.Or(closingFlag|discardFlag|poisonFlag) | closingFlag | discardFlag | poisonFlag
	if state&referenceMask == 0 {
		g.startFinish()
	}
}

// beginDiscard closes admissions and discards in-progress outputs.
// Used for emergencies and superseded key generations.
func (g *gate) beginDiscard() {
	state := g.state.Or(closingFlag|discardFlag) | closingFlag | discardFlag
	if state&referenceMask == 0 {
		g.startFinish()
	}
}

// await only OBSERVES a previously initiated close; it never triggers one.
func (g *gate) await(ctx context.Context) error {
	if ctx == nil {
		return errInvalid
	}
	if _, ok := ctx.Deadline(); !ok {
		return errNoDeadline
	}
	select {
	case <-g.done:
		if g.state.Load()&failedFlag != 0 {
			return errWipeFailed
		}
		return nil
	case <-ctx.Done():
		if g.state.Load()&finishedFlag != 0 {
			return errWipeUnconfirmed
		}
		return errDeadline
	}
}

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
			// A close racing with CAS burns the ticket, never reuses it.
			if k.gate.state.Load()&closingFlag != 0 {
				return 0, errClosed
			}
			return n, nil
		}
	}
}

// seal owns its lease and turns any panic from the fake provider into a
// POISONED key. Output on error/after close is never released by this API.
func (k *key) seal(payload []byte) (out packet, err error) {
	if !k.gate.enter() {
		return packet{}, errClosed
	}
	transferred := false
	defer func() {
		if !transferred {
			k.gate.leave()
		}
	}()
	defer func() {
		if recover() != nil {
			k.gate.poison()
			out = packet{}
			err = errProviderFault
		}
	}()
	ticket, err := k.reserve()
	if err != nil {
		return packet{}, err
	}
	result, err := k.p.process(ticket, payload)
	if err != nil {
		// Never clear provider output of unknown ownership: it may alias input.
		k.gate.poison()
		return packet{}, errProviderFault
	}
	// Always copy, including partial overlaps and subslices.
	owned := append([]byte(nil), result...)
	if k.gate.state.Load()&discardFlag != 0 {
		clear(owned)
		return packet{}, errClosed
	}
	// Keep the existing lease until dispatch or Discard. If it was released
	// here, rotation could wipe this key while its packet remains queued.
	transferred = true
	return packet{ticket: ticket, data: owned, guard: &packetGuard{owner: k}}, nil
}

type egress struct {
	gate *gate
	w    wire
}

func newEgress(w wire) *egress { return &egress{gate: newGate(func() {}), w: w} }

// session serializes rotation with the emergency key snapshot.
type session struct {
	mu      sync.RWMutex
	closed  bool
	k       *key
	previous *key
	faults atomic.Uint64 // monotone fault latch survives old-generation pruning
	keys    []*key                  // all generations must be drained on shutdown
	pending map[*packetGuard]packet // queued records owning leases
	e       *egress
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

func validProvider(p processor) bool {
	if p == nil {
		return false
	}
	v := reflect.ValueOf(p)
	return v.Kind() == reflect.Pointer && !v.IsNil()
}

const (
	faultPoisoned = uint64(1) << 0
	faultWipeFailed = uint64(1) << 1
)

func (s *session) newKeyOwned(p processor, max uint64) *key {
	k := newKey(p, max)
	k.gate.onFail = func() {
		// Record fault synchronously BEFORE the done channel is closed.
		// Async shutdown cannot erase fault evidence if generations are pruned.
		s.faults.Or(faultWipeFailed)
		go s.beginEmergency()
	}
	return k
}
func (s *session) faultState() (poisoned, wipeFailed bool) {
	f := s.faults.Load()
	return f&faultPoisoned != 0, f&faultWipeFailed != 0
}

func newSession(p processor, w wire, maxTickets uint64) (*session, error) {
	if !validProvider(p) || !validDependency(w) || maxTickets == 0 {
		return nil, errInvalid
	}
	if !p.claim() {
		return nil, errProviderReuse
	}
	s := &session{pending: make(map[*packetGuard]packet), e: newEgress(w)}
	k := s.newKeyOwned(p, maxTickets)
	s.k, s.keys = k, []*key{k}
	return s, nil
}

func (s *session) prepare(payload []byte) (packet, error) {
	var k *key
	var pkt packet
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		s.mu.RLock()
		if s.closed || s.faults.Load()&faultWipeFailed != 0 {
			s.mu.RUnlock()
			return packet{}, errClosed
		}
		k = s.k
		s.mu.RUnlock()
		pkt, err = k.seal(payload)
		if !errors.Is(err, errClosed) {
			break
		}
	}
	if err != nil {
		if errors.Is(err, errProviderFault) {
			s.faults.Or(faultPoisoned)
			s.beginEmergency()
		}
		return packet{}, err
	}
	s.mu.Lock()
	// An old in-flight operation can outlive TWO rotations: never admit
	// output from a generation older than the immediately previous one.
	if s.closed || (k != s.k && k != s.previous) || k.gate.state.Load()&discardFlag != 0 {
		s.mu.Unlock()
		pkt.guard.used.Store(true)
		k.gate.leave()
		clear(pkt.data)
		return packet{}, errClosed
	}
	s.pending[pkt.guard] = pkt
	s.mu.Unlock()
	pkt.data = nil // the queue (not its caller) owns the output buffer
	return pkt, nil
}

// discard releases a queued synthetic packet without sending it. It is safe
// to call more than once; only the first winning call releases the lease.
func (s *session) discard(p packet) {
	if p.guard == nil {
		return
	}
	s.mu.Lock()
	stored, exists := s.pending[p.guard]
	if exists && p.guard.used.CompareAndSwap(false, true) {
		delete(s.pending, p.guard)
		clear(stored.data)
		p.guard.owner.gate.leave()
	}
	s.mu.Unlock()
}

// dispatch is the only route to the synthetic wire sink.
func (s *session) dispatch(p packet) (err error) {
	// A panicking test sink is a fatal session fault; do not accidentally
	// resume dispatch with the same key after catching the panic.
	defer func() {
		if recover() != nil {
			s.beginEmergency()
			err = errProviderFault
		}
	}()
	// The independent egress gate is entered before ticket consumption.
	// A blocked gate cannot consume a ticket that should be discarded.
	if !s.e.gate.enter() {
		return errClosed
	}
	defer s.e.gate.leave()
	if p.guard == nil {
		return errTicket
	}
	s.mu.Lock()
	stored, exists := s.pending[p.guard]
	if !exists || !p.guard.used.CompareAndSwap(false, true) {
		s.mu.Unlock()
		return errTicket
	}
	delete(s.pending, p.guard)
	s.mu.Unlock()
	defer p.guard.owner.gate.leave() // exactly once, even if sink panics
	return s.e.w.send(stored.ticket, stored.data)
}

// rotate serializes publishing a new generation with the emergency snapshot.
// No new key can be installed once s.closed was set under the same mutex.
func (s *session) rotate(p processor, maxTickets uint64) error {
	if !validProvider(p) || maxTickets == 0 {
		return errInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.faults.Load()&faultWipeFailed != 0 {
		return errClosed
	}
	if !p.claim() {
		return errProviderReuse
	}
	old := s.k
	// Older-than-previous generations must be unable to enqueue an output
	// even if their process() was admitted before this rotation.
	for _, retired := range s.keys {
		if retired != old {
			retired.gate.beginDiscard()
		}
	}
	for guard, queued := range s.pending {
		if guard.owner != old && guard.used.CompareAndSwap(false, true) {
			delete(s.pending, guard)
			clear(queued.data)
			guard.owner.gate.leave()
		}
	}
	live := s.keys[:0]
	for _, existing := range s.keys {
		select {
		case <-existing.gate.done:
			// A completed wipe was confirmed; its fault remains latched.
		default:
			live = append(live, existing)
		}
	}
	fresh := s.newKeyOwned(p, maxTickets)
	s.previous = old
	s.k = fresh
	s.keys = append(live, fresh)
	old.gate.beginClose()
	return nil
}

// beginEmergency first closes egress admission, then serializes the emergency
// flag and key-snapshot with rotate. It never waits on an operation.
func (s *session) beginEmergency() {
	s.e.gate.beginClose()
	s.mu.Lock()
	s.closed = true
	// Cancel all queued synthetic records and release their key leases.
	for guard, queued := range s.pending {
		if guard.used.CompareAndSwap(false, true) {
			clear(queued.data)
			guard.owner.gate.leave()
		}
		delete(s.pending, guard)
	}
	for _, k := range s.keys {
		k.gate.beginDiscard()
	}
	s.mu.Unlock()
}

func (s *session) awaitDrained(ctx context.Context) error {
	if ctx == nil {
		return errInvalid
	}
	if _, ok := ctx.Deadline(); !ok {
		return errNoDeadline
	}
	s.mu.RLock()
	if !s.closed {
		s.mu.RUnlock()
		return errInvalid
	}
	keys := append([]*key(nil), s.keys...)
	s.mu.RUnlock()
	if err := s.e.gate.await(ctx); err != nil {
		return err
	}
	for _, k := range keys {
		if err := k.gate.await(ctx); err != nil {
			return err
		}
	}
	if s.faults.Load()&faultWipeFailed != 0 {
		return errWipeFailed
	}
	return nil
}
