//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
// R5 auditor tests for the UNMODIFIED staged16 at aa27727
// (supervisor_linux.go blob 372b93a). Each test PASSES when the reported
// behaviour is reproduced and logs a CONFIRMED line. Every process the tests
// create is killed in t.Cleanup.
package staged16

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func r5HelperArgs() []string { return []string{"-test.run=^TestR5StagedHelper$", "-test.v=false"} }

// TestR5StagedHelper is a no-op unless R5_STAGED_MODE is set (child processes).
func TestR5StagedHelper(t *testing.T) {
	mode := os.Getenv("R5_STAGED_MODE")
	if mode == "" {
		return
	}
	spawn := func(child string, setsid bool) {
		cmd := exec.Command(os.Args[0], r5HelperArgs()...)
		cmd.Env = append(os.Environ(), "R5_STAGED_MODE="+child)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // inherit the supervisor's pipes
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: setsid}
		if err := cmd.Start(); err != nil {
			os.Exit(20)
		}
	}
	writePID := func(env string) {
		if p := os.Getenv(env); p != "" {
			// /proc/self resolves in the pid namespace of the mounted procfs,
			// i.e. it yields the host PID even inside a new PID namespace.
			self, err := os.Readlink("/proc/self")
			if err != nil {
				self = strconv.Itoa(os.Getpid())
			}
			_ = os.WriteFile(p+".tmp", []byte(self), 0o600)
			_ = os.Rename(p+".tmp", p)
		}
	}
	hang := func() {
		for {
			time.Sleep(time.Hour)
		}
	}
	switch mode {
	case "grandchild-sleep":
		writePID("R5_GRANDCHILD_PID")
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case "spawn-then-exit":
		writePID("R5_CHILD_PID")
		spawn("grandchild-sleep", false)
		os.Exit(0)
	case "spawn-escaped-then-hang":
		writePID("R5_CHILD_PID")
		spawn("grandchild-sleep", true)
		hang()
	case "spawn-samegroup-then-hang":
		writePID("R5_CHILD_PID")
		spawn("grandchild-sleep", false)
		hang()
	case "supervisor":
		writePID("R5_SUPERVISOR_PID")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = RunSyntheticChild(ctx, os.Args[0], r5HelperArgs(), []string{"R5_STAGED_MODE=spawn-samegroup-then-hang",
			"R5_CHILD_PID=" + os.Getenv("R5_CHILD_PID"), "R5_GRANDCHILD_PID=" + os.Getenv("R5_GRANDCHILD_PID")})
		os.Exit(0)
	case "report":
		var b strings.Builder
		ents, _ := os.ReadDir("/proc/self/fd")
		for _, e := range ents {
			target, _ := os.Readlink("/proc/self/fd/" + e.Name())
			fmt.Fprintf(&b, "fd %s %s\n", e.Name(), target)
		}
		var rl syscall.Rlimit
		_ = syscall.Getrlimit(syscall.RLIMIT_CORE, &rl)
		fmt.Fprintf(&b, "core %d %d\n", rl.Cur, rl.Max)
		dumpable, _, _ := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
		fmt.Fprintf(&b, "dumpable %d\n", dumpable)
		fmt.Fprintf(&b, "env-secret %q\n", os.Getenv("R5_SUPERVISOR_SECRET"))
		_ = os.WriteFile(os.Getenv("R5_REPORT"), []byte(b.String()), 0o600)
		os.Exit(0)
	}
	os.Exit(9)
}

// alive reports whether pid exists and is not a zombie.
func alive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i >= 0 && i+2 < len(s) && s[i+2] != 'Z'
}

func waitPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(string(b)); err == nil {
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid file %s never appeared", path)
	return 0
}

// R5-03: Stdout/Stderr = io.Discard makes os/exec create pipes; a descendant
// that inherits them keeps cmd.Wait() blocked after the direct child exited.
// A child that finished successfully is reported as deadline-killed.
func TestR5_03_InheritedPipeTurnsCompletionIntoKill(t *testing.T) {
	dir := t.TempDir()
	gpid := filepath.Join(dir, "grandchild")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := RunSyntheticChild(ctx, os.Args[0], r5HelperArgs(),
		[]string{"R5_STAGED_MODE=spawn-then-exit", "R5_GRANDCHILD_PID=" + gpid})
	elapsed := time.Since(start)
	pid := waitPID(t, gpid)
	if res.Status != Killed || !errors.Is(err, context.DeadlineExceeded) || elapsed < time.Second {
		t.Fatalf("not reproduced: %+v %v after %v", res, err, elapsed)
	}
	t.Logf("CONFIRMED R5-03: the direct child exited with status 0 at once, but RunSyntheticChild waited %v for the pipe held by grandchild %d and returned Status=%q, err=%v", elapsed.Round(time.Millisecond), pid, res.Status, err)
}

// R5-04: a descendant that leaves the process group (setsid) survives the
// Stage-D group SIGKILL; because it also holds the stdout pipe, the direct
// child is misreported as unreaped and a goroutine stays blocked in Wait.
func TestR5_04_EscapedDescendantSurvivesStageD(t *testing.T) {
	dir := t.TempDir()
	gpid := filepath.Join(dir, "grandchild")
	cpid := filepath.Join(dir, "child")
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	res, err := RunSyntheticChild(ctx, os.Args[0], r5HelperArgs(),
		[]string{"R5_STAGED_MODE=spawn-escaped-then-hang", "R5_GRANDCHILD_PID=" + gpid, "R5_CHILD_PID=" + cpid})
	grand := waitPID(t, gpid)
	child := waitPID(t, cpid)
	time.Sleep(200 * time.Millisecond)
	if !alive(grand) || alive(child) || res.Status != Unreaped || !errors.Is(err, ErrReapUnconfirmed) {
		t.Fatalf("not reproduced: grand alive=%v child alive=%v res=%+v err=%v", alive(grand), alive(child), res, err)
	}
	t.Logf("CONFIRMED R5-04: after the Stage-D group SIGKILL the escaped grandchild %d is still running; the killed direct child %d was reported as Status=%q (err=%v)", grand, child, res.Status, err)
}

// R5-07: Pdeathsig covers only the direct child. When the supervisor itself
// dies, group members (not even escaped ones) survive: no independent watchdog.
func TestR5_07_SupervisorDeathLeavesDescendants(t *testing.T) {
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
	child := waitPID(t, cpid)
	grand := waitPID(t, gpid)
	_ = sup.Process.Signal(syscall.SIGKILL) // supervisor crash
	_ = sup.Wait()
	time.Sleep(500 * time.Millisecond)
	if alive(child) || !alive(grand) {
		t.Fatalf("not reproduced: child alive=%v grandchild alive=%v", alive(child), alive(grand))
	}
	t.Logf("CONFIRMED R5-07: supervisor SIGKILL -> direct child %d died (Pdeathsig), grandchild %d in the same process group keeps running", child, grand)
}

// R5-08: the child inherits non-CLOEXEC descriptors, the full supervisor
// environment and the supervisor's core-dump / dumpable settings.
func TestR5_08_InheritedDescriptorsEnvAndLimits(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "supervisor-only")
	if err := os.WriteFile(secretFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(secretFile, syscall.O_RDONLY, 0) // no O_CLOEXEC, as C/cgo code may do
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
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
	r := string(b)
	leaked := strings.Contains(r, " "+secretFile+"\n")
	envLeak := strings.Contains(r, `env-secret "token-of-the-supervisor"`)
	if !leaked || !envLeak {
		t.Fatalf("not reproduced:\n%s", r)
	}
	t.Logf("CONFIRMED R5-08: child inherited supervisor fd %d (%s) and the supervisor environment; no limits are set by the supervisor:\n%s", fd, secretFile, r)
}
