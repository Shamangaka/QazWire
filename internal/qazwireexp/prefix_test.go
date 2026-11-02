//go:build qazwire_exp

// SPDX-License-Identifier: MIT
package qazwireexp

import (
	"errors"
	"testing"
)

func TestPrefixParserRejectsInvalidConfig(t *testing.T) {
	for _, id := range []ProfileID{0, 3, 255} {
		parser, err := NewPrefixParser(id)
		if parser != nil || err == nil {
			t.Fatalf("invalid config %d admitted: %v, %v", id, parser, err)
		}
	}
	var nilParser *PrefixParser
	if got, err := nilParser.Parse([]byte{0x14, 1, 0, 0}); !errors.Is(err, ErrInvalidProfile) || got != (UnauthenticatedPrefix{}) {
		t.Fatalf("nil parser: %+v, %v", got, err)
	}
}

func TestPrefixParserValidAndCrossProfile(t *testing.T) {
	for _, id := range []ProfileID{1, 2} {
		parser, err := NewPrefixParser(id)
		if err != nil {
			t.Fatal(err)
		}
		other, err := NewPrefixParser(3 - id)
		if err != nil {
			t.Fatal(err)
		}
		for kind := MessageInitiation; kind <= MessageTransport; kind++ {
			packet := []byte{byte(kind), byte(id), 0, 0}
			got, err := parser.Parse(packet)
			if err != nil || got.Type() != kind || got.Profile() != id {
				t.Fatalf("expected valid (%d,%d): %+v, %v", id, kind, got, err)
			}
			if got, err := other.Parse(packet); !errors.Is(err, ErrProfileMismatch) || got != (UnauthenticatedPrefix{}) {
				t.Fatalf("cross-profile accepted (%d,%d): %+v, %v", id, kind, got, err)
			}
		}
	}
}

func TestPrefixParserRejectsMalformed(t *testing.T) {
	parser, _ := NewPrefixParser(1)
	cases := []struct {
		name   string
		packet []byte
		want   error
	}{
		{"truncated", []byte{0x14, 1, 0}, ErrShortPrefix},
		{"legacy initiation", []byte{1, 0, 0, 0}, ErrLegacyProtocol},
		{"legacy transport", []byte{4, 0, 0, 0}, ErrLegacyProtocol},
		{"unknown type", []byte{0x15, 1, 0, 0}, ErrUnknownType},
		{"zero wire profile", []byte{0x14, 0, 0, 0}, ErrInvalidProfile},
		{"wrong wire profile", []byte{0x14, 2, 0, 0}, ErrProfileMismatch},
		{"reserved byte 2", []byte{0x14, 1, 1, 0}, ErrReservedNonzero},
		{"reserved byte 3", []byte{0x14, 1, 0, 1}, ErrReservedNonzero},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parser.Parse(tc.packet)
			if !errors.Is(err, tc.want) || got != (UnauthenticatedPrefix{}) {
				t.Fatalf("Parse(%x): result %+v error %v, wanted %v", tc.packet, got, err, tc.want)
			}
		})
	}
}

func TestProfilesCannotEnableCrypto(t *testing.T) {
	for id := 0; id < 256; id++ {
		if !errors.Is(RequireApprovedSuite(ProfileID(id)), ErrNoApprovedSuite) {
			t.Fatalf("profile %d unexpectedly became operational", id)
		}
	}
}

func FuzzParsePrefix(f *testing.F) {
	for _, packet := range [][]byte{
		{}, {1, 0, 0, 0}, {4, 0, 0, 0}, {0x14, 1, 0, 0}, {0x14, 1, 1, 0}, {0x14, 2, 0, 0},
	} {
		f.Add(packet, uint8(1))
	}
	f.Add([]byte{0x14, 2, 0, 0}, uint8(2))
	f.Fuzz(func(t *testing.T, packet []byte, inputProfile uint8) {
		profile := ProfileID(1 + inputProfile%2)
		parser, err := NewPrefixParser(profile)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parser.Parse(packet)
		if err == nil {
			if len(packet) < 4 || packet[0] < 0x11 || packet[0] > 0x14 ||
				packet[1] != byte(profile) || packet[2] != 0 || packet[3] != 0 {
				t.Fatalf("accepted malformed prefix %x, configured %d", packet, profile)
			}
			if got.Type() != MessageType(packet[0]) || got.Profile() != profile {
				t.Fatalf("inconsistent parsed result: %+v", got)
			}
		} else if got != (UnauthenticatedPrefix{}) {
			t.Fatalf("partial data returned on error: %+v", got)
		}
	})
}
