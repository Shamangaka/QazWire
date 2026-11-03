//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
// R5 fix tests: run ONLY on the copy patched with staged16_r5_fix.patch.
package staged16

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestR5Fix_03_NormalExitIsCompletedPromptly(t *testing.T) {
	dir := t.TempDir()
	gpid := filepath.Join(dir, "grandchild")
	// A -race child sleeps ~1s at exit (GORACE atexit_sleep_ms); the deadline
	// is far above that, so only a pipe-induced wait could reach it.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	start := time.Now()
	res, err := RunSyntheticChild(ctx, os.Args[0], r5HelperArgs(),
		[]string{"R5_STAGED_MODE=spawn-then-exit", "R5_GRANDCHILD_PID=" + gpid})
	elapsed := time.Since(start)
	pid := waitPID(t, gpid)
	time.Sleep(100 * time.Millisecond)
	if err != nil || res.Status != Completed || !res.Reaped || elapsed > 3*time.Second || alive(pid) {
		t.Fatalf("res=%+v err=%v elapsed=%v grandchild alive=%v", res, err, elapsed, alive(pid))
	}
}

func TestR5Fix_04_EscapedDescendantKilled(t *testing.T) {
	dir := t.TempDir()
	gpid, cpid := filepath.Join(dir, "grandchild"), filepath.Join(dir, "child")
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	res, _ := RunSyntheticChild(ctx, os.Args[0], r5HelperArgs(),
		[]string{"R5_STAGED_MODE=spawn-escaped-then-hang", "R5_GRANDCHILD_PID=" + gpid, "R5_CHILD_PID=" + cpid})
	grand, child := waitPID(t, gpid), waitPID(t, cpid)
	time.Sleep(200 * time.Millisecond)
	if alive(grand) || alive(child) || res.Status != Killed || !res.Reaped {
		t.Fatalf("grand alive=%v child alive=%v res=%+v", alive(grand), alive(child), res)
	}
}

func TestR5Fix_07_SupervisorDeathKillsDescendants(t *testing.T) {
	dir := t.TempDir()
	spid, cpid, gpid := filepath.Join(dir, "sup"), filepath.Join(dir, "child"), filepath.Join(dir, "grand")
	sup := exec.Command(os.Args[0], r5HelperArgs()...)
	sup.Env = append(os.Environ(), "R5_STAGED_MODE=supervisor", "R5_SUPERVISOR_PID="+spid,
		"R5_CHILD_PID="+cpid, "R5_GRANDCHILD_PID="+gpid)
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Process.Kill(); _ = sup.Wait() })
	waitPID(t, spid)
	child, grand := waitPID(t, cpid), waitPID(t, gpid)
	_ = sup.Process.Signal(syscall.SIGKILL)
	_ = sup.Wait()
	time.Sleep(500 * time.Millisecond)
	if alive(child) || alive(grand) {
		t.Fatalf("child alive=%v grandchild alive=%v", alive(child), alive(grand))
	}
}

func TestR5Fix_08_SupervisorEnvironmentNotInherited(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("R5_SUPERVISOR_SECRET", "token-of-the-supervisor")
	report := filepath.Join(dir, "report")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := RunSyntheticChild(ctx, os.Args[0], r5HelperArgs(),
		[]string{"R5_STAGED_MODE=report", "R5_REPORT=" + report}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `env-secret ""`) {
		t.Fatalf("supervisor environment leaked:\n%s", b)
	}
}
