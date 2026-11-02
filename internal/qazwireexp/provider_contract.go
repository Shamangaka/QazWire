//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// This file defines a REVIEW-ONLY contract; it implements no cryptography.
package qazwireexp

// Header is the 16-byte DRAFT transport header. The field layout and size
// are provisional pending protocol R2 review. It is NOT authenticated here.
type Header [16]byte

// Direction describes one direction of an authenticated session.
// Direction is public protocol metadata, never a source of randomness.
type Direction uint8

const (
	InitiatorToResponder Direction = 1
	ResponderToInitiator Direction = 2
)

// TransportProtector specifies the proposed packet API after authenticated
// session keys have been derived by a separately reviewed key schedule.
// There are NO implementations of this interface in QazWire M1.2.
//
// Contract for future implementations (NOT enforced by this interface):
//   - Seal must authenticate the entire header and plaintext.
//   - Open must authenticate the entire header and ciphertext/tag BEFORE
//     releasing or writing any plaintext; on failure return nil, error.
//   - The packet counter must come from the authenticated header, never from
//     an independently supplied nonce.
//   - Destroy is permitted only once all in-flight operations have drained;
//     its actual key wiping guarantees require separate review.
//   - Implementations must provide explicit errors, no fallback algorithms.
type TransportProtector interface {
	Seal(dst []byte, header Header, plaintext []byte) ([]byte, error)
	Open(dst []byte, header Header, ciphertextAndTag []byte) ([]byte, error)
	Destroy() error
}

// CryptoProvider represents a cryptographic implementation. It has no
// key-derivation or constructor method yet: secret ownership, key lengths,
// transcript binding and lifetime must be specified and audited first.
// This is intentionally insufficient to create a transport session.
type CryptoProvider interface {
	Profile() ProfileID
	SelfTest() error
}

// ProfileInfo describes a draft suite by value, with private fields so that
// callers cannot alter the registry's metadata. It grants no permission to
// instantiate cryptography or use a profile for traffic.
type ProfileInfo struct {
	id       ProfileID
	name     string
	tagBytes uint8
}

func (i ProfileInfo) ID() ProfileID { return i.id }
func (i ProfileInfo) Name() string  { return i.name }
func (i ProfileInfo) TagBytes() int { return int(i.tagBytes) }

const (
	ProfileDraftQ256EM ProfileID = 1
	ProfileDraftQ128CM ProfileID = 2
)

// DraftProfile is an immutable read-only metadata lookup. These parameters
// are candidate architecture values, not approved cryptographic suites.
func DraftProfile(id ProfileID) (ProfileInfo, error) {
	switch id {
	case 0:
		return ProfileInfo{}, ErrInvalidProfile
	case ProfileDraftQ256EM:
		return ProfileInfo{id: id, name: "QWX1-Q256EM-DRAFT", tagBytes: 32}, nil
	case ProfileDraftQ128CM:
		return ProfileInfo{id: id, name: "QWX1-Q128CM-DRAFT", tagBytes: 16}, nil
	default:
		return ProfileInfo{}, ErrUnknownProfile
	}
}

// ResolveCryptoProvider rejects all profiles. The M1.2 build has NO
// registration API, NO built-in provider and NO fallback to standard
// WireGuard. Only a future reviewed revision may add an explicit registry.
func ResolveCryptoProvider(id ProfileID) (CryptoProvider, error) {
	if _, err := DraftProfile(id); err != nil {
		return nil, err
	}
	return nil, ErrNoApprovedSuite
}
