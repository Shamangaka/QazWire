//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
// A SYNTHETIC cgroup-v2 termination laboratory. No real secret, VPN,
// Qalqan primitive, key worker, encryption or production watchdog.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	cgroupRoot  = "/sys/fs/cgroup"
	cgroup2Type = 0x63677270 // Linux CGROUP2_SUPER_MAGIC
	waitKill    = 5 * time.Second
)

var unitFormat = regexp.MustCompile(`^qazwire-m171-[0-9a-f]{16}\.service$`)

func die(err error) {
	fmt.Fprintln(os.Stderr, "M1.7.1 FAIL:", err)
	os.Exit(1)
}

func parsePopulated(content string) (bool, error) {
	found := false
	populated := false
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != "populated" {
			continue
		}
		if found || len(fields) != 2 || (fields[1] != "0" && fields[1] != "1") {
			return false, errors.New("malformed or duplicate populated field")
		}
		found = true
		populated = fields[1] == "1"
	}
	if !found {
		return false, errors.New("missing populated field")
	}
	return populated, nil
}

// validateUnitPath restricts destructive cgroup.kill to one freshly named
// transient service inside the current unprivileged user's systemd subtree.
// It cannot be used to target a parent scope, root cgroup or foreign UID.
func validateUnitPath(uid int, unit, cg string) error {
	if uid <= 0 || !unitFormat.MatchString(unit) {
		return errors.New("unapproved user or transient unit name")
	}
	if cg == "" || filepath.Clean(cg) != cg || strings.Contains(cg, "//") {
		return errors.New("invalid cgroup path")
	}
	prefix := fmt.Sprintf("/user.slice/user-%d.slice/user@%d.service/", uid, uid)
	if !strings.HasPrefix(cg, prefix) || !strings.HasSuffix(cg, "/"+unit) {
		return errors.New("cgroup not under invoking user's matching service")
	}
	for _, part := range strings.Split(cg, "/") {
		if part == "." || part == ".." {
			return errors.New("path traversal")
		}
	}
	return nil
}

func readSmallFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) > 4096 {
		return "", errors.New("unexpectedly large cgroup field")
	}
	return strings.TrimSpace(string(b)), nil
}

func verifyProcessInCgroup(pid int, cg string) error {
	if pid <= 1 {
		return errors.New("invalid systemd MainPID")
	}
	data, err := readSmallFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return fmt.Errorf("cannot verify MainPID membership: %w", err)
	}
	for _, line := range strings.Split(data, "\n") {
		if line == "0::"+cg {
			return nil
		}
	}
	return errors.New("MainPID not in the claimed cgroup")
}

func verifyLimit(path, expected string) error {
	actual, err := readSmallFile(path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%s: have %q, require %q", path, actual, expected)
	}
	return nil
}

func validateCgroupV2Root() error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(cgroupRoot, &st); err != nil {
		return err
	}
	if st.Type != cgroup2Type {
		return errors.New("expected unified cgroup v2 filesystem")
	}
	return nil
}

// killVerified is intentionally not exported. A trusted lab wrapper supplies
// a unique unit name, expected systemd MainPID and exact resource limits.
// A process running as root is rejected (no privileged kill in this lab).
func killVerified(cg, unit string, mainPID int, memoryBytes uint64, taskLimit uint64) error {
	if err := validateUnitPath(os.Getuid(), unit, cg); err != nil {
		return err
	}
	if memoryBytes != 128*1024*1024 || taskLimit != 32 {
		return errors.New("unexpected lab memory/pids limit")
	}
	if err := validateCgroupV2Root(); err != nil {
		return err
	}
	if err := verifyProcessInCgroup(mainPID, cg); err != nil {
		return err
	}
	path := cgroupRoot + cg
	if err := verifyLimit(filepath.Join(path, "memory.max"), "134217728"); err != nil {
		return err
	}
	if err := verifyLimit(filepath.Join(path, "pids.max"), "32"); err != nil {
		return err
	}

	// Keep cgroup.events OPEN before issuing the destructive operation.
	// This limits systemd's unit-cleanup race: the cgroup path may disappear
	// as soon as the last task exits. Read failure is NOT_CONFIRMED, not PASS.
	events, err := os.Open(filepath.Join(path, "cgroup.events"))
	if err != nil {
		return fmt.Errorf("events unavailable: %w", err)
	}
	defer events.Close()
	check := func() (bool, error) {
		if _, err := events.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		data, err := io.ReadAll(io.LimitReader(events, 4096))
		if err != nil {
			return false, err
		}
		return parsePopulated(string(data))
	}
	before, err := check()
	if err != nil || !before {
		return fmt.Errorf("NOT_CONFIRMED: cgroup not populated before kill: populated=%t err=%v", before, err)
	}
	killFile, err := os.OpenFile(filepath.Join(path, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cgroup.kill is inaccessible: %w", err)
	}
	defer killFile.Close()
	if _, err := killFile.Write([]byte("1")); err != nil {
		return fmt.Errorf("cgroup.kill write failed: %w", err)
	}
	deadline := time.Now().Add(waitKill)
	for {
		populated, err := check()
		if err != nil {
			return fmt.Errorf("NOT_CONFIRMED: cannot read events after kill: %w", err)
		}
		if !populated {
			fmt.Println("M1.7.1 PASS: cgroup.kill issued; cgroup.events populated=0")
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("NOT_CONFIRMED: cgroup.events populated=1 after deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func checkPrivateDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("marker directory must be absolute")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("marker directory not private")
	}
	info, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(info.Uid) != os.Getuid() {
		return errors.New("marker directory not owned by worker")
	}
	return nil
}

func workAsParent(dir string) error {
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	child := exec.Command(exe, "escaped")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer devnull.Close()
	child.Stdout, child.Stderr = devnull, devnull
	if err := child.Start(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "parent.pid"), []byte(fmt.Sprint(os.Getpid())), 0600); err != nil {
		_ = child.Process.Kill()
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "escaped.pid"), []byte(fmt.Sprint(child.Process.Pid)), 0600); err != nil {
		_ = child.Process.Kill()
		return err
	}
	// Intentionally no Pdeathsig for child: a detached setsid descendant
	// must be killed by the cgroup mechanism, NOT via parent-death signal.
	for {
		time.Sleep(time.Second)
	}
}

func main() {
	if os.Getuid() == 0 {
		die(errors.New("root is forbidden for this unprivileged synthetic test"))
	}
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "escaped":
			for {
				time.Sleep(time.Second)
			}
		case "parent":
			if len(os.Args) != 3 {
				die(errors.New("usage: parent <private-marker-dir>"))
			}
			if err := workAsParent(os.Args[2]); err != nil {
				die(err)
			}
			return
		case "kill":
			if len(os.Args) != 7 {
				die(errors.New("usage: kill <cgroup> <unit> <mainpid> <memory-bytes> <task-limit>"))
			}
			pid, err := strconv.Atoi(os.Args[4])
			if err != nil {
				die(err)
			}
			memory, err := strconv.ParseUint(os.Args[5], 10, 64)
			if err != nil {
				die(err)
			}
			tasks, err := strconv.ParseUint(os.Args[6], 10, 64)
			if err != nil {
				die(err)
			}
			// Do not use a context to cancel this cleanup on caller request.
			// A timeout always returns NOT_CONFIRMED and cleanup is left to
			// the independent user systemd manager / wrapper EXIT trap.
			if err := killVerified(os.Args[2], os.Args[3], pid, memory, tasks); err != nil {
				die(err)
			}
			return
		}
	}
	die(errors.New("usage: <parent|escaped|kill>; SYNTHETIC / RESEARCH ONLY"))
}

