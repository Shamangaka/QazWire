//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package qazwireexp

import (
	"errors"
	"testing"
)

func TestDraftProfilesAreReadOnlyAndProvisional(t *testing.T) {
	for _, tc := range []struct {
		id   ProfileID
		name string
		tag  int
	}{
		{1, "QWX1-Q256EM-DRAFT", 32},
		{2, "QWX1-Q128CM-DRAFT", 16},
	} {
		p, err := DraftProfile(tc.id)
		if err != nil || p.ID() != tc.id || p.Name() != tc.name || p.TagBytes() != tc.tag {
			t.Fatalf("DraftProfile(%v) = %+v, %v", tc.id, p, err)
		}
		p.tagBytes = 1 // mutate local copy, never global registry metadata
		p2, err := DraftProfile(tc.id)
		if err != nil || p2.TagBytes() != tc.tag {
			t.Fatalf("profile metadata mutated through returned copy: %+v, %v", p2, err)
		}
	}
}

func TestNoCryptoProviderCanBeResolved(t *testing.T) {
	for i := 0; i <= 255; i++ {
		id := ProfileID(i)
		p, err := ResolveCryptoProvider(id)
		if p != nil || err == nil {
			t.Fatalf("profile %d unexpectedly resolved provider: %T, %v", i, p, err)
		}
		switch id {
		case 0:
			if !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("zero id: %v", err)
			}
		case 1, 2:
			if !errors.Is(err, ErrNoApprovedSuite) {
				t.Fatalf("candidate %d: %v", id, err)
			}
		default:
			if !errors.Is(err, ErrUnknownProfile) {
				t.Fatalf("unknown %d: %v", id, err)
			}
		}
	}
}

func TestProviderContractRequiresUnimplementedInterfaces(t *testing.T) {
	// Assert interface typechecking without enabling a concrete implementation.
	var provider CryptoProvider
	var protector TransportProtector
	if provider != nil || protector != nil {
		t.Fatal("unexpected provider implementation")
	}
	if len(Header{}) != 16 {
		t.Fatal("unexpected experimental header length")
	}
}
