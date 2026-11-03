// Package racechk documents a limitation of Go's race detector relevant to the
// R4.1 evidence: writes performed by the clear() builtin (memclr), and loops that
// the compiler rewrites into memclr, are NOT reported as data races.
package racechk

import (
	"os"
	"testing"
	"time"
)

func reader(b []byte, done chan struct{}) {
	defer close(done)
	time.Sleep(10 * time.Millisecond)
	_ = b[0] + b[1]
}

// Expected under -race: PASS (the race on b is real but not reported).
func TestClearRaceNotReported(t *testing.T) {
	b := []byte("hello")
	done := make(chan struct{})
	go reader(b, done)
	clear(b)
	<-done
}

// Expected under -race with RACECHK_CONTROL=1: "WARNING: DATA RACE" (control).
func TestIndexedWriteRaceReported(t *testing.T) {
	if os.Getenv("RACECHK_CONTROL") != "1" {
		t.Skip("control case; set RACECHK_CONTROL=1")
	}
	b := []byte("hello")
	done := make(chan struct{})
	go reader(b, done)
	b[0] = 0
	<-done
}
