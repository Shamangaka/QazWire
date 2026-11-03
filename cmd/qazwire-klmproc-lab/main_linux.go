//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
// A laboratory-only process owner for synthetic KLM state.
// DO NOT USE with real keys, encryption, WireGuard or production traffic.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.zx2c4.com/wireguard/internal/qazwireexp/klmproc17"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: qazwire-klmproc-lab <absolute-socket-path-in-private-dir>")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := klmproc17.ServeSynthetic(ctx, os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "synthetic worker failed: %v\n", err)
		os.Exit(1)
	}
}
