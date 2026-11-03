//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// Package klm16 is a SYNTHETIC key-ownership laboratory, not cryptography.
// No type or output in this package may be used for real network encryption.
package klm16

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
)

var (
	ErrInvalid          = errors.New("klm16: invalid limits")
	ErrClosed           = errors.New("klm16: session stopped")
	ErrPoisoned         = errors.New("klm16: laboratory operation panicked")
	ErrBacklog          = errors.New("klm16: pinned retired generation budget exceeded")
	ErrTicket           = errors.New("klm16: ticket absent, foreign, or already consumed")
	ErrTicketExhausted  = errors.New("klm16: generation ticket counter exhausted")
	ErrEpochExhausted   = errors.New("klm16: epoch counter exhausted")
	ErrBudget           = errors.New("klm16: queued byte budget exceeded")
	ErrRotated          = errors.New("klm16: key generation superseded during prepare")
	ErrDeadlineRequired = errors.New("klm16: deadline required")
	ErrDeadline         = errors.New("klm16: destruction not confirmed before deadline")
	ErrNotStopped       = errors.New("klm16: stop must precede await")
)

// A process-local monotonic domain. Across process restarts this is NOT a
// globally unique identity. A real transport requires a handshake-derived,
// authenticated per-direction key/nonce domain and restart guarantees.
var nextSessionID atomic.Uint64
var nextMaterialID atomic.Uint64

func nextID(counter *atomic.Uint64) (uint64, error) {
	for {
		n := counter.Load()
		if n == math.MaxUint64 {
			return 0, ErrEpochExhausted
		}
		if counter.CompareAndSwap(n, n+1) {
			return n + 1, nil
		}
	}
}

// syntheticMaterial is allocated and erased only inside this package.
// It is deliberately NOT a cryptographic key, and its bytes are never used
// to encrypt, authenticate or derive anything. No caller-supplied provider
// interface, claim(), wipe() or backing key slice enters the constructor.
type syntheticMaterial struct {
	id    uint64
	bytes [32]byte
	wiped bool
}

func makeMaterial() (*syntheticMaterial, error) {
	id, err := nextID(&nextMaterialID)
	if err != nil {
		return nil, err
	}
	m := &syntheticMaterial{id: id}
	for i := range m.bytes {
		m.bytes[i] = byte((id >> (uint(i%8) * 8)) ^ uint64(i+1))
	}
	return m, nil
}

// wipe is intentionally a POINTER-receiver method on the only private
// material type. Go clear is best-effort only; no secure erasure claim.
func (m *syntheticMaterial) wipe() {
	if m.wiped {
		panic("klm16: double synthetic wipe")
	}
	clear(m.bytes[:])
	m.wiped = true
}

type generation struct {
	epoch    uint64
	material *syntheticMaterial
	next     uint64
	max      uint64
	refs     uint64
	retiring bool
	discard  bool
	wiped    bool
	done     chan struct{}
}

type ticketState struct {
	session *labSession
	gen     *generation
	seq     uint64
	data    []byte
}

// Ticket is an opaque, copyable capability. All copies reference the SAME
// private state: consuming one copy invalidates every other copy.
type Ticket struct {
	state *ticketState
}

// LabRecord contains PLAINTEXT and synthetic metadata. It is NOT a VPN
// datagram, a nonce, an authenticated header, or encrypted output.
type LabRecord struct {
	SessionID  uint64
	Epoch      uint64
	MaterialID uint64
	Sequence   uint64
	Data       []byte
}

// Stats is a consistent, point-in-time snapshot of the synthetic session.
type Stats struct {
	SessionID    uint64
	CurrentEpoch uint64
	LiveKeys     int
	Pending      int
	PendingBytes uint64
	Closed       bool
	Faulted      bool
}

// Session is a sealed PUBLIC CAPABILITY, not a copyable concrete owner.
// External packages cannot copy the private owner or supply a provider.
type Session interface {
	Prepare([]byte) (Ticket, error)
	Consume(Ticket) (LabRecord, error)
	Discard(Ticket) error
	Rotate() error
	Stop()
	AwaitDestroyed(context.Context) error
	Fault() error
	Snapshot() Stats
	sessionMarker()
}

// labSession owns all material and tickets; mu protects its fields.
// No foreign callback executes while mu is held.
type labSession struct {
	mu           sync.Mutex
	id           uint64
	current      *generation
	previous     *generation
	generations  []*generation
	pending      map[*ticketState]struct{}
	pendingBytes uint64
	maxBytes     uint64
	maxPinned    int
	closed       bool
	fault        error

	// Test-only scheduler hook. It is configured before concurrent use,
	// invoked WITHOUT mu, and never exported to callers.
	beforeQueue func()
}

// NewLabSession creates all synthetic material INSIDE the KLM package.
// The only inputs are resource limits, never secret material or a provider.
// The guarantee of unique IDs applies only to this process lifetime.
func NewLabSession(maxTickets, maxQueuedBytes uint64, maxPinned int) (Session, error) {
	if maxTickets == 0 || maxQueuedBytes == 0 || maxPinned < 1 {
		return nil, ErrInvalid
	}
	id, err := nextID(&nextSessionID)
	if err != nil {
		return nil, err
	}
	material, err := makeMaterial()
	if err != nil {
		return nil, err
	}
	g := &generation{
		epoch:    1,
		material: material,
		max:      maxTickets,
		done:     make(chan struct{}),
	}
	return &labSession{
		id:          id,
		current:     g,
		generations: []*generation{g},
		pending:     make(map[*ticketState]struct{}),
		maxBytes:    maxQueuedBytes,
		maxPinned:   maxPinned,
	}, nil
}

func (*labSession) sessionMarker() {}

func (s *labSession) stopErrorLocked() error {
	if s.fault != nil {
		return s.fault
	}
	return ErrClosed
}

// releaseLocked is called exactly once for each acquired generation lease.
func (s *labSession) releaseLocked(g *generation) {
	if g.refs == 0 {
		panic("klm16: unpaired generation release")
	}
	g.refs--
	s.finishLocked(g)
}

func (s *labSession) finishLocked(g *generation) {
	if !g.retiring || g.refs != 0 || g.wiped {
		return
	}
	g.material.wipe()
	g.wiped = true
	close(g.done)
}

// Compact by allocating NEW backing storage, avoiding stale references in
// the hidden capacity of an in-place filtered []generation slice (R42-10).
func (s *labSession) pruneLocked() {
	next := make([]*generation, 0, len(s.generations))
	for _, g := range s.generations {
		if !g.wiped || g == s.current || g == s.previous {
			next = append(next, g)
		}
	}
	s.generations = next
}

func (s *labSession) removeTicketLocked(state *ticketState) {
	if _, found := s.pending[state]; !found {
		return
	}
	delete(s.pending, state)
	s.pendingBytes -= uint64(len(state.data))
	g := state.gen
	clear(state.data)
	state.data = nil
	// External copies of Ticket still hold *ticketState. Sever every
	// reference from a spent token to the owner and key generation.
	state.gen = nil
	state.session = nil
	s.releaseLocked(g)
}

func (s *labSession) stopLocked(cause error) {
	if cause != nil && s.fault == nil {
		s.fault = cause
	}
	if s.closed {
		return
	}
	s.closed = true
	for state := range s.pending {
		s.removeTicketLocked(state)
	}
	for _, g := range s.generations {
		g.retiring = true
		g.discard = true
		s.finishLocked(g)
	}
}

// Stop rejects new operations, destroys all queued synthetic buffers and
// starts erasure of every generation whose outstanding references are zero.
// A stalled worker cannot be forcibly interrupted by Go.
func (s *labSession) Stop() {
	s.mu.Lock()
	s.stopLocked(nil)
	s.mu.Unlock()
}

// Prepare reserves a one-shot ticket and transfers ownership of a PRIVATE
// payload copy to the queue. A concurrent caller MUST NOT modify the input
// slice until Prepare returns (ordinary Go slice ownership rule).
//
// A rotation can reject the operation before admission. Up to three bounded
// retries are allowed; no ticket is ever reused after a retry.
func (s *labSession) Prepare(payload []byte) (ticket Ticket, err error) {
	var leased *generation
	var private []byte
	defer func() {
		if recover() != nil {
			s.mu.Lock()
			if leased != nil {
				s.releaseLocked(leased)
			}
			s.stopLocked(ErrPoisoned)
			s.mu.Unlock()
			clear(private)
			ticket = Ticket{}
			err = ErrPoisoned
		}
	}()
	for attempt := 0; attempt < 3; attempt++ {
		s.mu.Lock()
		if s.closed {
			err = s.stopErrorLocked()
			s.mu.Unlock()
			return Ticket{}, err
		}
		if uint64(len(payload)) > s.maxBytes {
			s.mu.Unlock()
			return Ticket{}, ErrBudget
		}
		g := s.current
		if g.next >= g.max {
			s.mu.Unlock()
			return Ticket{}, ErrTicketExhausted
		}
		seq := g.next
		g.next++
		g.refs++
		leased = g
		hook := s.beforeQueue
		s.mu.Unlock()

		private = append([]byte(nil), payload...)
		if hook != nil {
			hook() // test scheduler only; never under session.mu
		}

		s.mu.Lock()
		acceptable := !s.closed && !g.discard &&
			(g == s.current || g == s.previous)
		if !acceptable {
			open := !s.closed
			s.releaseLocked(g)
			// An in-flight lease may be the LAST reference to a grandparent
			// that was discarded by two rotations. Remove its wiped slot now,
			// not only upon a future Rotate/Consume.
			s.pruneLocked()
			leased = nil
			s.mu.Unlock()
			clear(private)
			private = nil
			if open {
				continue
			}
			s.mu.Lock()
			err = s.stopErrorLocked()
			s.mu.Unlock()
			return Ticket{}, err
		}
		amount := uint64(len(private))
		if amount > s.maxBytes-s.pendingBytes {
			s.releaseLocked(g)
			leased = nil
			s.mu.Unlock()
			clear(private)
			private = nil
			return Ticket{}, ErrBudget
		}
		state := &ticketState{session: s, gen: g, seq: seq, data: private}
		s.pending[state] = struct{}{}
		s.pendingBytes += amount
		leased = nil
		private = nil
		s.mu.Unlock()
		return Ticket{state: state}, nil
	}
	return Ticket{}, ErrRotated
}

// Consume simulates completion of egress; it DOES NOT send to a network.
// The returned plaintext record must never be used as a VPN packet.
func (s *labSession) Consume(t Ticket) (LabRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return LabRecord{}, s.stopErrorLocked()
	}
	state := t.state
	if state == nil || state.session != s {
		return LabRecord{}, ErrTicket
	}
	if _, found := s.pending[state]; !found {
		return LabRecord{}, ErrTicket
	}
	if state.gen.discard {
		s.removeTicketLocked(state)
		return LabRecord{}, ErrRotated
	}
	record := LabRecord{
		SessionID:  s.id,
		Epoch:      state.gen.epoch,
		MaterialID: state.gen.material.id,
		Sequence:   state.seq,
		Data:       append([]byte(nil), state.data...),
	}
	s.removeTicketLocked(state)
	s.pruneLocked()
	return record, nil
}

// Discard consumes a queued ticket without emitting a record.
func (s *labSession) Discard(t Ticket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.state == nil || t.state.session != s {
		return ErrTicket
	}
	if _, found := s.pending[t.state]; !found {
		return ErrTicket
	}
	s.removeTicketLocked(t.state)
	s.pruneLocked()
	return nil
}

// Rotate installs a new privately created material object and epoch. The
// immediately previous generation may complete already acquired work;
// older generations are discarded. A pinned-generation overflow causes a
// fail-closed stop rather than uncontrolled growth of old process leases.
func (s *labSession) Rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.stopErrorLocked()
	}
	if s.current.epoch == math.MaxUint64 {
		s.stopLocked(ErrEpochExhausted)
		return ErrEpochExhausted
	}
	old := s.current
	pinned := 0
	for _, g := range s.generations {
		if g != old && g.refs > 0 {
			pinned++
		}
	}
	if pinned >= s.maxPinned {
		s.stopLocked(ErrBacklog)
		return ErrBacklog
	}
	mat, err := makeMaterial()
	if err != nil {
		s.stopLocked(err)
		return err
	}
	// Discard all earlier generations and queued tickets before publishing.
	for _, g := range s.generations {
		if g != old {
			g.retiring = true
			g.discard = true
		}
	}
	for state := range s.pending {
		if state.gen != old {
			s.removeTicketLocked(state)
		}
	}
	old.retiring = true
	s.finishLocked(old)
	fresh := &generation{
		epoch:    old.epoch + 1,
		material: mat,
		max:      old.max,
		done:     make(chan struct{}),
	}
	s.previous = old
	s.current = fresh
	s.generations = append(s.generations, fresh)
	s.pruneLocked()
	return nil
}

// AwaitDestroyed observes a previous Stop; it never initiates Stop.
// Completion is only confirmation that the SYNTHETIC wipe function returned.
func (s *labSession) AwaitDestroyed(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrDeadlineRequired
	}
	s.mu.Lock()
	if !s.closed {
		s.mu.Unlock()
		return ErrNotStopped
	}
	keys := append([]*generation(nil), s.generations...)
	s.mu.Unlock()
	for _, g := range keys {
		select {
		case <-g.done:
		case <-ctx.Done():
			return ErrDeadline
		}
	}
	return nil
}

func (s *labSession) Fault() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fault
}

func (s *labSession) Snapshot() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := 0
	for _, g := range s.generations {
		if !g.wiped {
			live++
		}
	}
	return Stats{
		SessionID:    s.id,
		CurrentEpoch: s.current.epoch,
		LiveKeys:     live,
		Pending:      len(s.pending),
		PendingBytes: s.pendingBytes,
		Closed:       s.closed,
		Faulted:      s.fault != nil,
	}
}
