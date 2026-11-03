// SPDX-License-Identifier: MIT
// Package klm15ref is an AUDITOR REFERENCE MODEL (R4) of the M1.5 key-lifecycle
// architecture proposed in QAZWIRE_AUDIT_R4.md section 6. It contains NO
// cryptography: labCipher is a synthetic stand-in whose "seal" is a byte copy.
// It is not production code and is not part of the QazWire module.
package klm15ref

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// ----- state word of a directed key (one atomic uint64, all transitions linearizable)
const (
	closingBit  = uint64(1) << 63 // no new admission (planned retire or emergency)
	discardBit  = uint64(1) << 62 // emergency: in-flight outputs are discarded
	poisonBit   = uint64(1) << 61 // provider fault observed (implies closing|discard)
	wipingBit   = uint64(1) << 60 // wipe claimed (exactly one claimer)
	wipedBit    = uint64(1) << 59 // wipe returned normally
	wipeFailBit = uint64(1) << 58 // wipe panicked: material state unknown -> escalate
	refMask     = uint64(1)<<58 - 1
)

var (
	ErrClosed          = errors.New("klm15ref: key closed")
	ErrExhausted       = errors.New("klm15ref: counter exhausted")
	ErrTicket          = errors.New("klm15ref: invalid, foreign or reused ticket")
	ErrProviderFault   = errors.New("klm15ref: provider fault; key poisoned")
	ErrNoDeadline      = errors.New("klm15ref: context without deadline")
	ErrNotClosing      = errors.New("klm15ref: await before retire/emergency")
	ErrDrainPending    = errors.New("klm15ref: deadline: operations still in flight; key NOT wiped")
	ErrWipeUnconfirmed = errors.New("klm15ref: deadline: wipe started but not confirmed")
	ErrWipeFailed      = errors.New("klm15ref: wipe failed; material state unknown; escalate")
	ErrDeviceClosed    = errors.New("klm15ref: device in emergency; key refused")
	errInvalid         = errors.New("klm15ref: invalid argument")
)

// test hook points (reference model only; a production build has none)
var hookFn atomic.Pointer[func(string)]

func hook(p string) {
	if f := hookFn.Load(); f != nil {
		(*f)(p)
	}
}

// labCipher is a CONCRETE unexported type: no interface is accepted from callers,
// so a typed-nil provider cannot be constructed (R4-KLM-04).
type labCipher struct {
	material [32]byte
	active   atomic.Int64
	unsafe   atomic.Bool // wipe observed an active seal
	wipes    atomic.Int64
	// fault injection (tests in this package only)
	blockSeal chan struct{}
	panicSeal atomic.Bool
	blockWipe chan struct{}
	panicWipe bool
}

func (c *labCipher) seal(dst []byte, seq uint64, pt []byte) []byte {
	c.active.Add(1)
	defer c.active.Add(-1)
	if c.blockSeal != nil {
		<-c.blockSeal
	}
	if c.panicSeal.CompareAndSwap(true, false) {
		panic("synthetic provider fault")
	}
	_ = seq
	return append(dst, pt...) // NOT encryption
}

func (c *labCipher) wipe() {
	if c.active.Load() != 0 {
		c.unsafe.Store(true)
	}
	if c.panicWipe {
		panic("synthetic wipe fault")
	}
	if c.blockWipe != nil {
		<-c.blockWipe
	}
	clear(c.material[:])
	c.wipes.Add(1)
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// DirectedKey owns the material; it is the only path to labCipher.
type DirectedKey struct {
	_    noCopy
	st   atomic.Uint64
	next atomic.Uint64
	max  uint64
	gen  uint64
	c    *labCipher
	done chan struct{}
}

// newDirectedKey consumes (zeroes) the caller's material.
func newDirectedKey(material *[32]byte, maxMessages, gen uint64) (*DirectedKey, error) {
	if material == nil || maxMessages == 0 {
		return nil, errInvalid
	}
	k := &DirectedKey{max: maxMessages, gen: gen, c: &labCipher{}, done: make(chan struct{})}
	k.c.material = *material
	clear(material[:])
	return k, nil
}

func (k *DirectedKey) acquire() bool {
	for {
		s := k.st.Load()
		if s&closingBit != 0 || s&refMask == refMask {
			return false
		}
		if k.st.CompareAndSwap(s, s+1) {
			return true
		}
	}
}

// release never borrows into flag bits: an unmatched release is a fail-stop bug.
func (k *DirectedKey) release() {
	for {
		s := k.st.Load()
		if s&refMask == 0 {
			panic("klm15ref: unmatched release")
		}
		if k.st.CompareAndSwap(s, s-1) {
			if (s-1)&closingBit != 0 && (s-1)&refMask == 0 {
				go k.finalize()
			}
			return
		}
	}
}

// reserve: CAS first, then check the MONOTONIC closing bit. If closing is clear
// after the CAS it was clear at the CAS, so every valid ticket was allocated
// strictly before closing (R4-KLM-01). A ticket allocated after closing is burnt.
func (k *DirectedKey) reserve() (uint64, error) {
	for {
		n := k.next.Load()
		if n >= k.max {
			return 0, ErrExhausted
		}
		if k.next.CompareAndSwap(n, n+1) {
			hook("reserve:cas")
			if k.st.Load()&closingBit != 0 {
				return 0, ErrClosed // burnt, never reissued
			}
			return n, nil
		}
	}
}

// Ticket is one-time and holds one lease reference until Seal or Discard.
type Ticket struct {
	k    *DirectedKey
	seq  uint64
	used atomic.Bool
}

func (t *Ticket) Seq() uint64 { return t.seq }

func (k *DirectedKey) Reserve() (*Ticket, error) {
	if !k.acquire() {
		return nil, ErrClosed
	}
	seq, err := k.reserve()
	if err != nil {
		k.release()
		return nil, err
	}
	return &Ticket{k: k, seq: seq}, nil
}

// Discard releases an unused ticket (every drop path of a queued packet must call it).
func (t *Ticket) Discard() {
	if t != nil && t.used.CompareAndSwap(false, true) {
		t.k.release()
	}
}

// Seal consumes the ticket. Provider panic poisons the key and never escapes.
func (k *DirectedKey) Seal(dst []byte, t *Ticket, pt []byte) (out []byte, err error) {
	if t == nil || t.k != k || !t.used.CompareAndSwap(false, true) {
		return nil, ErrTicket
	}
	defer k.release()
	if k.st.Load()&discardBit != 0 {
		return nil, ErrClosed
	}
	defer func() {
		if r := recover(); r != nil {
			k.poison()
			clear(dst[len(dst):cap(dst)]) // provider may have written into spare capacity
			out, err = nil, ErrProviderFault
		}
	}()
	out = k.c.seal(dst, t.seq, pt)
	hook("seal:post")
	if k.st.Load()&discardBit != 0 {
		clear(out[len(dst):])
		return nil, ErrClosed
	}
	return out, nil
}

func (k *DirectedKey) setFlags(f uint64) {
	s := k.st.Or(f) | f
	if s&refMask == 0 {
		go k.finalize()
	}
}

func (k *DirectedKey) Retire()         { k.setFlags(closingBit) }
func (k *DirectedKey) BeginEmergency() { k.setFlags(closingBit | discardBit) }
func (k *DirectedKey) poison()         { k.setFlags(closingBit | discardBit | poisonBit) }

func (k *DirectedKey) finalize() {
	for {
		s := k.st.Load()
		if s&closingBit == 0 || s&refMask != 0 || s&wipingBit != 0 {
			return
		}
		if k.st.CompareAndSwap(s, s|wipingBit) {
			ok := func() (ok bool) {
				defer func() {
					if recover() != nil {
						ok = false
					}
				}()
				k.c.wipe()
				return true
			}()
			if ok {
				k.st.Or(wipedBit)
			} else {
				k.st.Or(wipeFailBit)
			}
			close(k.done)
			return
		}
	}
}

// AwaitDestroyed never initiates shutdown and never waits without a deadline.
func (k *DirectedKey) AwaitDestroyed(ctx context.Context) error {
	if ctx == nil {
		return ErrNoDeadline
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrNoDeadline
	}
	if k.st.Load()&closingBit == 0 {
		return ErrNotClosing
	}
	select {
	case <-k.done:
		if k.st.Load()&wipeFailBit != 0 {
			return ErrWipeFailed
		}
		return nil
	case <-ctx.Done():
		if k.st.Load()&wipingBit != 0 {
			return ErrWipeUnconfirmed
		}
		return ErrDrainPending
	}
}

// ----- egress gate: independent of keys; guards the hand-off to the kernel
const egBlocked = uint64(1) << 63

type EgressGate struct {
	st   atomic.Uint64
	once sync.Once
	idle chan struct{}
}

func NewEgressGate() *EgressGate { return &EgressGate{idle: make(chan struct{})} }

func (g *EgressGate) Enter() bool {
	for {
		s := g.st.Load()
		if s&egBlocked != 0 {
			return false
		}
		if g.st.CompareAndSwap(s, s+1) {
			return true
		}
	}
}

func (g *EgressGate) Exit() {
	for {
		s := g.st.Load()
		if s&^egBlocked == 0 {
			panic("klm15ref: unmatched egress exit")
		}
		if g.st.CompareAndSwap(s, s-1) {
			if (s - 1) == egBlocked {
				g.once.Do(func() { close(g.idle) })
			}
			return
		}
	}
}

func (g *EgressGate) Block() {
	if g.st.Or(egBlocked)&^egBlocked == 0 {
		g.once.Do(func() { close(g.idle) })
	}
}

func (g *EgressGate) AwaitIdle(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrNoDeadline
	}
	select {
	case <-g.idle:
		return nil
	case <-ctx.Done():
		return ErrDrainPending
	}
}

// ----- device: rotation and emergency are serialized by one control-plane mutex
type Device struct {
	mu        sync.Mutex
	emergency bool
	keys      map[uint64]*DirectedKey
	Egress    *EgressGate
}

func NewDevice() *Device { return &Device{keys: map[uint64]*DirectedKey{}, Egress: NewEgressGate()} }

// Install publishes a new key unless emergency has started (then the key is closed).
func (d *Device) Install(k *DirectedKey) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.emergency {
		k.BeginEmergency()
		return ErrDeviceClosed
	}
	d.keys[k.gen] = k
	return nil
}

// Emergency: stage A (egress fence, no new keys, no admission, drain in-flight
// sends), then stages B/C (drain operations, wipe). Every wait is bounded by ctx;
// an error means stage D (process / module termination) is required.
func (d *Device) Emergency(ctx context.Context) error {
	d.Egress.Block()
	d.mu.Lock()
	d.emergency = true
	ks := make([]*DirectedKey, 0, len(d.keys))
	for _, k := range d.keys {
		ks = append(ks, k)
	}
	d.mu.Unlock()
	for _, k := range ks {
		k.BeginEmergency()
	}
	if err := d.Egress.AwaitIdle(ctx); err != nil {
		return err
	}
	hook("emergency:stageA")
	for _, k := range ks {
		if err := k.AwaitDestroyed(ctx); err != nil {
			return err
		}
	}
	return nil
}
