//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
package main

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This child stays alive until the parent test kills it. It has no key,
// transport, cgroup controller or additional privileges.
func TestM171_PidfdChildHelper(t *testing.T) {
	if os.Getenv("QAZWIRE_M171_PIDFD_HELPER") != "1" {
		return
	}
	time.Sleep(15 * time.Second)
}

func TestM171_PidfdTracksExactProcessExit(t *testing.T) {
	c := exec.Command(os.Args[0], "-test.run=^TestM171_PidfdChildHelper$")
	c.Env = append(os.Environ(), "QAZWIRE_M171_PIDFD_HELPER=1")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = c.Process.Kill()
		_ = c.Wait()
	}()
	fd, err := unix.PidfdOpen(c.Process.Pid, 0)
	if err != nil {
		t.Fatalf("kernel must support pidfd_open in this lab: %v", err)
	}
	defer unix.Close(fd)
	ended, err := processExited(fd)
	if err != nil || ended {
		t.Fatalf("fresh live child unexpectedly terminated: exited=%t err=%v", ended, err)
	}
	if err := c.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	// Poll may become ready even before the parent calls Wait().
	deadline := time.Now().Add(3 * time.Second)
	for {
		ended, err = processExited(fd)
		if err != nil {
			t.Fatal(err)
		}
		if ended {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("pidfd did not observe child termination")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestM171_InvalidPidfdDoesNotClaimSuccess(t *testing.T) {
	ended, err := processExited(-1)
	if err == nil || ended {
		t.Fatalf("invalid pidfd falsely marked exited: exited=%t err=%v", ended, err)
	}
}
