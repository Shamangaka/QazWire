//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// Package qazwireexp contains a draft protocol-boundary parser. This package
// does not implement cryptography or create usable VPN sessions.
package qazwireexp

import "errors"

// MessageType values are PROVISIONAL and may change after independent review.
// They deliberately differ from standard WireGuard message types (1 through 4).
type MessageType uint8

const (
	MessageInitiation  MessageType = 0x11
	MessageResponse    MessageType = 0x12
	MessageCookieReply MessageType = 0x13
	MessageTransport   MessageType = 0x14
)

// ProfileID selects a draft protocol profile. Zero is reserved.
// There is currently no enabled cryptographic profile.
type ProfileID uint8

// Prefix represents only the first four bytes of an experimental packet.
// Successful parsing does NOT authenticate, decrypt, or accept a packet.
type Prefix struct {
	Type    MessageType
	Profile ProfileID
}

var (
	ErrShortPrefix     = errors.New("qazwireexp: truncated protocol prefix")
	ErrLegacyProtocol  = errors.New("qazwireexp: standard WireGuard message is not an experimental message")
	ErrUnknownType     = errors.New("qazwireexp: unknown experimental message type")
	ErrInvalidProfile  = errors.New("qazwireexp: zero profile is prohibited")
	ErrProfileMismatch = errors.New("qazwireexp: wrong profile")
	ErrUnknownProfile  = errors.New("qazwireexp: unassigned profile")
	ErrReservedNonzero = errors.New("qazwireexp: reserved prefix bytes are nonzero")
	ErrNoApprovedSuite = errors.New("qazwireexp: no reviewed transport suite is available")
)

// ParsePrefix performs only public-field syntax validation.
// The protocol constants are a draft; do not wire this function into a
// production packet path before a complete suite and security review exist.
func ParsePrefix(packet []byte, expected ProfileID) (Prefix, error) {
	if len(packet) < 4 {
		return Prefix{}, ErrShortPrefix
	}

	kind := MessageType(packet[0])
	switch kind {
	case 0x01, 0x02, 0x03, 0x04:
		return Prefix{}, ErrLegacyProtocol
	case MessageInitiation, MessageResponse, MessageCookieReply, MessageTransport:
		// These codes are provisional. Only syntax is checked below.
	default:
		return Prefix{}, ErrUnknownType
	}

	if expected == 0 || packet[1] == 0 {
		return Prefix{}, ErrInvalidProfile
	}
	// Only draft profile IDs 1 and 2 are recognized; neither is operational.
	if expected != 1 && expected != 2 {
		return Prefix{}, ErrUnknownProfile
	}
	if ProfileID(packet[1]) != expected {
		return Prefix{}, ErrProfileMismatch
	}
	if packet[2] != 0 || packet[3] != 0 {
		return Prefix{}, ErrReservedNonzero
	}

	return Prefix{Type: kind, Profile: expected}, nil
}

// RequireApprovedSuite is an explicit fail-closed gate. Until a real,
// independently reviewed transport implementation is integrated, it MUST
// refuse every profile, including those for which ParsePrefix succeeds.
func RequireApprovedSuite(_ ProfileID) error { return ErrNoApprovedSuite }
