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

// PrefixParser binds the expected draft profile at construction time.
// Future device integration MUST construct it ONCE from trusted configuration,
// not recreate it using the profile ID from an untrusted network packet.
type PrefixParser struct {
	expected ProfileID
}

// NewPrefixParser validates trusted configuration before parsing any packets.
// A known draft profile is NOT permission to enable cryptography.
func NewPrefixParser(profile ProfileID) (*PrefixParser, error) {
	if _, err := DraftProfile(profile); err != nil {
		return nil, err
	}
	return &PrefixParser{expected: profile}, nil
}

// UnauthenticatedPrefix is ONLY a syntax-checked four-byte prefix.
// Its unexported fields distinguish it from any future authenticated
// transport packet; only the future audited crypto Open may authenticate.
type UnauthenticatedPrefix struct {
	messageType MessageType
	profile ProfileID
}

func (p UnauthenticatedPrefix) Type() MessageType { return p.messageType }
func (p UnauthenticatedPrefix) Profile() ProfileID { return p.profile }

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

// Parse checks only public prefix syntax, NOT full packet length, MAC or
// encryption. Errors must never be reflected to remote peers as an oracle.
func (p *PrefixParser) Parse(packet []byte) (UnauthenticatedPrefix, error) {
	if p == nil {
		return UnauthenticatedPrefix{}, ErrInvalidProfile
	}
	if len(packet) < 4 {
		return UnauthenticatedPrefix{}, ErrShortPrefix
	}

	kind := MessageType(packet[0])
	switch kind {
	case 0x01, 0x02, 0x03, 0x04:
		return UnauthenticatedPrefix{}, ErrLegacyProtocol
	case MessageInitiation, MessageResponse, MessageCookieReply, MessageTransport:
		// These codes are provisional. Only syntax is checked below.
	default:
		return UnauthenticatedPrefix{}, ErrUnknownType
	}

	if packet[1] == 0 {
		return UnauthenticatedPrefix{}, ErrInvalidProfile
	}
	if ProfileID(packet[1]) != p.expected {
		return UnauthenticatedPrefix{}, ErrProfileMismatch
	}
	if packet[2] != 0 || packet[3] != 0 {
		return UnauthenticatedPrefix{}, ErrReservedNonzero
	}

	return UnauthenticatedPrefix{messageType: kind, profile: p.expected}, nil
}

// RequireApprovedSuite is a legacy research scaffold check, not a security
// boundary. Only ResolveCryptoProvider can resolve a transport provider,
// and currently it refuses every candidate; no provider is registered.
func RequireApprovedSuite(_ ProfileID) error { return ErrNoApprovedSuite }
