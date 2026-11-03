//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
package staged16

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestStageDHelperProcess(t *testing.T) {
	if os.Getenv("QAZWIRE_STAGE_D_CHILD") == "" {
		return
	}
	switch os.Getenv("QAZWIRE_STAGE_D_CHILD") {
	case "hang":
		// Running only as the synthetic CHILD of another Go test.
		for {
			time.Sleep(time.Hour)
		}
	case "exit":
		os.Exit(0)
	case "fail":
		os.Exit(7)
	default:
		os.Exit(9)
	}
}

func childArgs() []string {
	return []string{"-test.run=^TestStageDHelperProcess$", "-test.v=false"}
}

func TestM161_StageDRejectsMissingDeadline(t *testing.T) {
	if _, err := RunSyntheticChild(context.Background(), os.Args[0], childArgs(), nil); !errors.Is(err, ErrDeadlineRequired) {
		t.Fatalf("unbounded supervisor wait accepted: %v", err)
	}
	if _, err := RunSyntheticChild(nil, os.Args[0], childArgs(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil context accepted: %v", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := RunSyntheticChild(ctx, os.Args[0], childArgs(), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline started a child: %v", err)
	}
}

func TestM161_StageDIndependentWatchdogKillsHungChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := RunSyntheticChild(ctx, os.Args[0], childArgs(), []string{"QAZWIRE_STAGE_D_CHILD=hang"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("supervisor accepted hung child: result=%+v, error=%v", res, err)
	}
	if res.Status != Killed || !res.Reaped || !res.GroupKillAttempted {
		t.Fatalf("missing process-group kill / reap evidence: %+v", res)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatalf("external cancellation was excessively delayed: %v", elapsed)
	}
}

func TestM161_StageDNormalChildExitAndError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pass, err := RunSyntheticChild(ctx, os.Args[0], childArgs(), []string{"QAZWIRE_STAGE_D_CHILD=exit"})
	if err != nil || pass.Status != Completed || pass.ExitCode != 0 || !pass.Reaped {
		t.Fatalf("normal child: %+v, %v", pass, err)
	}
	failed, err := RunSyntheticChild(ctx, os.Args[0], childArgs(), []string{"QAZWIRE_STAGE_D_CHILD=fail"})
	if !errors.Is(err, ErrChildFailed) || failed.Status != Nonzero || failed.ExitCode != 7 || !failed.Reaped {
		t.Fatalf("failed child classification: %+v, %v", failed, err)
	}
}
