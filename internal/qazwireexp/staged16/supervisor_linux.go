//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT

// Package staged16 demonstrates a Linux OUT-OF-PROCESS Stage-D watchdog
// using a synthetic child. It has no real keys, network or crypto.
// It is not a sandbox or a production secret-erasure mechanism.
package staged16

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

var (
	ErrInvalid          = errors.New("staged16: invalid synthetic child")
	ErrDeadlineRequired = errors.New("staged16: finite deadline required")
	ErrChildFailed      = errors.New("staged16: child exited unsuccessfully")
	ErrReapUnconfirmed  = errors.New("staged16: child could not be reaped after kill")
)

type Status string

const (
	Completed Status = "completed"
	Nonzero   Status = "nonzero-exit"
	Killed    Status = "deadline-killed"
	StartFail Status = "start-failed"
	Unreaped  Status = "reap-unconfirmed"
)

// Result records what the PROCESS SUPERVISOR observed. GroupKillAttempted
// proves only that an OS signal was issued, NOT that all descendants or
// kernel/network buffers are gone, and NOT that bytes were physically erased.
type Result struct {
	Status             Status
	ExitCode           int
	GroupKillAttempted bool
	Reaped             bool
	Elapsed            time.Duration
}

// RunSyntheticChild launches one trusted executable without a shell in its
// own Linux process group. This LAB API accepts only a caller-selected test
// binary; do not use it to execute arbitrary untrusted files or real KLMs.
// Context must have a finite deadline. No stdout/stderr is captured to avoid
// retaining any child data in the supervisor process.
func RunSyntheticChild(ctx context.Context, path string, args []string, extraEnv []string) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalid
	}
	if _, ok := ctx.Deadline(); !ok {
		return Result{}, ErrDeadlineRequired
	}
	if path == "" {
		return Result{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Result{Status: Killed}, err
	}
	begin := time.Now()
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	// Setpgid isolates our synthetic child from the supervisor's own group.
	// Pdeathsig handles direct-child death if the supervisor process exits.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return Result{Status: StartFail, Elapsed: time.Since(begin)}, err
	}
	reaped := make(chan error, 1)
	go func() { reaped <- cmd.Wait() }()
	select {
	case err := <-reaped:
		// A group member could have left descendants behind. Best-effort
		// group cleanup even when the direct child exits on its own.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		result := Result{Status: Completed, Reaped: true, ExitCode: 0, Elapsed: time.Since(begin)}
		if err != nil {
			result.Status = Nonzero
			result.ExitCode = cmd.ProcessState.ExitCode()
			return result, errors.Join(ErrChildFailed, err)
		}
		return result, nil
	case <-ctx.Done():
		// External Stage D: no request to the hung child is required.
		// SIGKILL a dedicated group; then reap the direct child.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill() // fallback for missing process group
		result := Result{Status: Killed, GroupKillAttempted: true, Elapsed: time.Since(begin)}
		select {
		case <-reaped:
			result.Reaped = true
			result.Elapsed = time.Since(begin)
			return result, ctx.Err()
		case <-time.After(3 * time.Second):
			result.Status = Unreaped
			result.Elapsed = time.Since(begin)
			return result, errors.Join(ErrReapUnconfirmed, ctx.Err())
		}
	}
}
