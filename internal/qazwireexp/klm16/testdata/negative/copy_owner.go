//go:build qazwire_exp

// SPDX-License-Identifier: MIT
// This file MUST NOT compile. CI verifies the concrete key owner cannot be
// copied or reconstructed from outside the klm16 package.
package negative

import "golang.zx2c4.com/wireguard/internal/qazwireexp/klm16"

func copyOwner() {
	owner, _ := klm16.NewLabSession(10, 1024, 2)
	_ = *owner // invalid: the public type is a sealed interface, not *owner
}

func forgeTicket() {
	_ = klm16.Ticket{state: nil} // invalid: private ticket state
}
