//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// R5 auditor tests from an EXTERNAL package (klm16_test): only the public
// API plus the standard library "reflect" package; no unsafe, no linkname.
package klm16_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/internal/qazwireexp/klm16"
)

func materialBytes(t *testing.T, s klm16.Session) []byte {
	t.Helper()
	gen := reflect.ValueOf(s).Elem().FieldByName("current").Elem()
	arr := gen.FieldByName("material").Elem().FieldByName("bytes")
	out := make([]byte, arr.Len())
	for i := range out {
		out[i] = byte(arr.Index(i).Uint()) // reading unexported fields is allowed
	}
	return out
}

// R5-02a: the sealed owner does not hide material from other code in the
// same process; reflect reads it and the copy outlives AwaitDestroyed.
func TestR5_02a_ReflectReadsSealedMaterial(t *testing.T) {
	s, err := klm16.NewLabSession(4, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	stolen := materialBytes(t, s)
	s.Stop()
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	if err := s.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
	nonzero := false
	for _, b := range stolen {
		nonzero = nonzero || b != 0
	}
	if !nonzero {
		t.Fatal("not reproduced")
	}
	t.Logf("CONFIRMED R5-02a: an external package read %d material bytes through reflect (no unsafe); the copy survives a successful AwaitDestroyed", len(stolen))
}

// R5-02b: reflect.Value.Set clones the private *labSession into a second
// live owner that shares generations and material but has its own mutex.
func TestR5_02b_ReflectClonesOwner(t *testing.T) {
	s, err := klm16.NewLabSession(4, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	orig := reflect.ValueOf(s).Elem()
	cp := reflect.New(orig.Type())
	cp.Elem().Set(orig) // allowed: orig was not obtained through an unexported field
	clone, ok := cp.Interface().(klm16.Session)
	if !ok {
		t.Fatal("clone does not satisfy Session")
	}
	clone.Stop()
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	if err := clone.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
	// The clone has "confirmed destruction" of the shared generation, yet the
	// original owner is still open and keeps issuing records.
	if s.Snapshot().Closed {
		t.Fatal("not reproduced: original closed")
	}
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	tok, err := s.Prepare([]byte("after clone destroyed"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.Consume(tok)
	if err != nil {
		t.Fatal(err)
	}
	s.Stop()
	if err := s.AwaitDestroyed(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("CONFIRMED R5-02b: reflect cloned the sealed owner; clone.AwaitDestroyed()=nil while the original stayed open and produced record epoch=%d material=%d", rec.Epoch, rec.MaterialID)
}
