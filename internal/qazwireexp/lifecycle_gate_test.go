//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package qazwireexp

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestOperationGateZeroValueAndIdempotentClose(t *testing.T) {
	var g OperationGate
	if err := g.Use(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	g.CloseAndDrain()
	g.CloseAndDrain()
	if err := g.Use(func() error { t.Fatal("closed gate executed op"); return nil }); !errors.Is(err, ErrOperationClosed) {
		t.Fatalf("closed operation error = %v", err)
	}
	if err := g.Use(nil); !errors.Is(err, ErrNilOperation) {
		t.Fatalf("nil fn error = %v", err)
	}
}

func TestOperationGatePassesError(t *testing.T) {
	g := new(OperationGate)
	want := errors.New("sentinel")
	if err := g.Use(func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("operation error = %v", err)
	}
	g.CloseAndDrain()
}

func TestOperationGateWaitsBeforeKeyDestruction(t *testing.T) {
	var g OperationGate
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	goDone := make(chan struct{})
	go func() {
		defer close(goDone)
		_ = g.Use(func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("operation not entered")
	}
	go func() { g.CloseAndDrain(); close(finished) }()

	deadline := time.After(2 * time.Second)
	for {
		g.mu.Lock()
		closing := g.closing
		g.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-deadline:
			t.Fatal("close not entered")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := g.Use(func() error { t.Fatal("entered after close"); return nil }); !errors.Is(err, ErrOperationClosed) {
		t.Fatalf("concurrent close incorrectly admitted operation: %v", err)
	}
	select {
	case <-finished:
		t.Fatal("close finished while an operation was still active")
	default:
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not drain")
	}
	<-goDone
}

func TestOperationGateConcurrentClose(t *testing.T) {
	var g OperationGate
	const closers = 64
	var wg sync.WaitGroup
	for i := 0; i < closers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.CloseAndDrain() }()
	}
	wg.Wait()
	if err := g.Use(func() error { return nil }); !errors.Is(err, ErrOperationClosed) {
		t.Fatalf("operation admitted after concurrent close: %v", err)
	}
}

func TestOperationGatePanicDoesNotLeakLease(t *testing.T) {
	var g OperationGate
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected test panic")
			}
		}()
		_ = g.Use(func() error { panic("synthetic test panic") })
	}()
	g.CloseAndDrain() // would hang if defer failed to release lease
}
