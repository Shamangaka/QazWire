//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package qazwireexp

import (
	"errors"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	cases := []struct {
		name     string
		packet   []byte
		expected ProfileID
		want     error
	}{
		{"valid transport prefix (syntax only)", []byte{0x14, 0x01, 0, 0}, 1, nil},
		{"valid other profile (syntax only)", []byte{0x14, 0x02, 0, 0}, 2, nil},
		{"short", []byte{0x14, 0x01, 0}, 1, ErrShortPrefix},
		{"standard initiation", []byte{0x01, 0, 0, 0}, 1, ErrLegacyProtocol},
		{"standard transport", []byte{0x04, 0, 0, 0}, 1, ErrLegacyProtocol},
		{"unknown experimental", []byte{0x15, 0x01, 0, 0}, 1, ErrUnknownType},
		{"zero expected profile", []byte{0x14, 0x01, 0, 0}, 0, ErrInvalidProfile},
		{"zero wire profile", []byte{0x14, 0x00, 0, 0}, 1, ErrInvalidProfile},
		{"wrong profile", []byte{0x14, 0x02, 0, 0}, 1, ErrProfileMismatch},
		{"unknown expected profile", []byte{0x14, 0x80, 0, 0}, 0x80, ErrUnknownProfile},
		{"reserved byte 2", []byte{0x14, 0x01, 0x01, 0}, 1, ErrReservedNonzero},
		{"reserved byte 3", []byte{0x14, 0x01, 0, 0xff}, 1, ErrReservedNonzero},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePrefix(tc.packet, tc.expected)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParsePrefix(...) error %v, want %v", err, tc.want)
			}
			if tc.want == nil && (got.Type != MessageType(tc.packet[0]) || got.Profile != tc.expected) {
				t.Fatalf("got prefix %+v, want type %d profile %d", got, tc.packet[0], tc.expected)
			}
			if tc.want != nil && got != (Prefix{}) {
				t.Fatalf("error must not expose a partly parsed prefix: %+v", got)
			}
		})
	}
}

func TestProfilesCannotEnableCrypto(t *testing.T) {
	for _, p := range []ProfileID{0, 1, 2, 0x80, 0xff} {
		if !errors.Is(RequireApprovedSuite(p), ErrNoApprovedSuite) {
			t.Fatalf("profile %d unexpectedly became operational", p)
		}
	}
}

func FuzzParsePrefix(f *testing.F) {
	for _, data := range [][]byte{
		{}, {1, 0, 0, 0}, {0x14, 1, 0, 0}, {0x14, 1, 1, 0}, {0x14, 2, 0, 0},
	} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParsePrefix(b, 1)
		if err == nil {
			if len(b) < 4 || b[0] < 0x11 || b[0] > 0x14 || b[1] != 1 || b[2] != 0 || b[3] != 0 {
				t.Fatalf("accepted invalid experimental prefix: %x", b)
			}
			if p.Profile != 1 || p.Type != MessageType(b[0]) {
				t.Fatalf("inconsistent parsed data: %+v, %x", p, b)
			}
		}
	})
}
