//go:build qazwire_exp

package qazwireexp

import (
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// R3-T1: reentrant CloseAndDrain from inside Use never returns (documented deadlock).
func TestR3ReentrantCloseDeadlocks(t *testing.T) {
	var g OperationGate
	done := make(chan struct{})
	go func() {
		_ = g.Use(func() error { g.CloseAndDrain(); return nil })
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("reentrant CloseAndDrain returned; expected self-deadlock")
	case <-time.After(500 * time.Millisecond):
		t.Log("CONFIRMED: Use{CloseAndDrain} blocks forever (goroutine leaked by design of this test)")
	}
}

// R3-T2: CloseAndDrain blocks indefinitely while a provider call is blocked; there is no deadline/cancel.
func TestR3CloseBlocksOnStuckOperation(t *testing.T) {
	var g OperationGate
	entered, release := make(chan struct{}), make(chan struct{})
	go func() { _ = g.Use(func() error { close(entered); <-release; return nil }) }()
	<-entered
	closed := make(chan struct{})
	go func() { g.CloseAndDrain(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("drain completed while operation still blocked")
	case <-time.After(300 * time.Millisecond):
		t.Log("CONFIRMED: no bounded-time emergency path; drain waits for stuck provider")
	}
	close(release)
	<-closed
}

// R3-T3: core safety property under stress: no callback starts after CloseAndDrain returns,
// and every admitted callback finished before CloseAndDrain returned.
func TestR3StressNoOperationAfterDrain(t *testing.T) {
	var totalOps atomic.Int64
	for round := 0; round < 3000; round++ {
		var g OperationGate
		var destroyed atomic.Bool
		var violations atomic.Int64
		var wg sync.WaitGroup
		stop := make(chan struct{})
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					err := g.Use(func() error {
						totalOps.Add(1)
						if destroyed.Load() {
							violations.Add(1)
						}
						runtime.Gosched()
						if destroyed.Load() {
							violations.Add(1)
						}
						return nil
					})
					if errors.Is(err, ErrOperationClosed) {
						return
					}
				}
			}()
		}
		time.Sleep(time.Duration(round%5) * 100 * time.Microsecond)
		g.CloseAndDrain()
		destroyed.Store(true) // models provider.Destroy() after drain
		close(stop)
		wg.Wait()
		if v := violations.Load(); v != 0 {
			t.Fatalf("round %d: %d operations observed destroyed state", round, v)
		}
	}
	t.Logf("3000 rounds, %d admitted operations, 0 violations", totalOps.Load())
}


// R3-T5: exhaustive parser decision for every configured profile and the zero-value parser.
func TestR3ExhaustiveParser(t *testing.T) {
	parsers := map[string]*PrefixParser{"zero-value": {}}
	for _, id := range []ProfileID{1, 2} {
		p, err := NewPrefixParser(id)
		if err != nil {
			t.Fatal(err)
		}
		parsers[string(rune('0'+id))] = p
	}
	reserved := [][2]byte{{0, 0}, {1, 0}, {0, 1}, {0xff, 0xff}}
	for name, p := range parsers {
		accepted := 0
		for b0 := 0; b0 < 256; b0++ {
			for b1 := 0; b1 < 256; b1++ {
				for _, r := range reserved {
					pkt := []byte{byte(b0), byte(b1), r[0], r[1]}
					got, err := p.Parse(pkt)
					want := b0 >= 0x11 && b0 <= 0x14 && p.expected != 0 && ProfileID(b1) == p.expected && r == [2]byte{}
					if want != (err == nil) {
						t.Fatalf("%s: mismatch %x err=%v", name, pkt, err)
					}
					if err != nil && got != (UnauthenticatedPrefix{}) {
						t.Fatalf("%s: partial result", name)
					}
					if err == nil {
						accepted++
					}
				}
			}
		}
		t.Logf("parser %s: accepted %d of %d", name, accepted, 256*256*4)
	}
	for typ := uint32(1); typ <= 4; typ++ {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], typ)
		for _, p := range parsers {
			if _, err := p.Parse(b[:]); err == nil {
				t.Fatal("WG header accepted")
			}
		}
	}
}

// R3-T6: header-chosen counter: the draft TransportProtector API lets the caller supply any
// counter inside Header; two Seal calls with the same Header would reuse the CTR nonce.
// (Type-level observation; no implementation exists.)
func TestR3HeaderCarriesCallerCounter(t *testing.T) {
	var h Header
	binary.LittleEndian.PutUint64(h[8:], 42)
	if binary.LittleEndian.Uint64(h[8:]) != 42 {
		t.Fatal("unexpected")
	}
	t.Log("TransportProtector.Seal(dst, header Header, pt): counter is caller-controlled (no ticket)")
}
