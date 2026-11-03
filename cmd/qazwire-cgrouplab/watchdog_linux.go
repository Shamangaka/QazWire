//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
// M1.7.2a: separate-PROCESS synthetic watchdog and application-level egress
// gate. NOT an nftables/kernel A0 fence, a security sandbox, or a real KLM.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	pulseMaxAge  = 1100 * time.Millisecond
	watchTick    = 25 * time.Millisecond
	watchTimeout = 6 * time.Second
)

type syntheticGate struct {
	mu      sync.Mutex
	armed   bool
	fenced  bool
	granted uint64
}

func (g *syntheticGate) arm() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fenced {
		return errors.New("A0 already permanently fenced")
	}
	g.armed = true
	return nil
}

func (g *syntheticGate) fence() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fenced = true
	g.armed = false
}

func (g *syntheticGate) request() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.armed || g.fenced {
		return false
	}
	g.granted++
	return true
}

func (g *syntheticGate) count() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.granted
}

// The Unix socket is a synthetic application-level proxy, NOT an OS egress
// policy: a misbehaving process may bypass it and send directly. The proxy
// returns ALLOW only while the watchdog process is healthy, and any socket
// failure/EOF must be treated as DENY by every lab caller.
func serveGate(ln *net.UnixListener, gate *syntheticGate, stop <-chan struct{}) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		if err := ln.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return
		}
		conn, err := ln.AcceptUnix()
		if err != nil {
			select {
			case <-stop:
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
		wg.Add(1)
		go func(c *net.UnixConn) {
			defer wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(250 * time.Millisecond))
			uid, err := peerUIDGate(c)
			if err != nil || uid != uint32(os.Getuid()) {
				return
			}
			var op [1]byte
			if _, err := io.ReadFull(c, op[:]); err != nil || op[0] != 'S' {
				return
			}
			if gate.request() {
				_, _ = io.WriteString(c, "ALLOW\n")
				return
			}
			_, _ = io.WriteString(c, "DENY\n")
		}(conn)
	}
}

func peerUIDGate(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var creds *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		creds, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil || creds == nil {
		return 0, errors.New("SO_PEERCRED denied")
	}
	return creds.Uid, nil
}

// gateRequest cannot grant synthetic egress on any error. In particular, if
// the watchdog process dies, the orphan socket cannot return ALLOW.
func gateRequest(socket string) (bool, error) {
	c, err := net.DialTimeout("unix", socket, 200*time.Millisecond)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(350 * time.Millisecond)); err != nil {
		return false, err
	}
	if _, err := c.Write([]byte{'S'}); err != nil {
		return false, err
	}
	var b [6]byte
	n, err := io.ReadFull(c, b[:])
	if err != nil {
		return false, err
	}
	if n != 6 {
		return false, errors.New("invalid synthetic gate response")
	}
	if string(b[:]) == "ALLOW\n" {
		return true, nil
	}
	if string(b[:5]) == "DENY\n" {
		return false, nil
	}
	return false, errors.New("unrecognized synthetic gate response")
}

// All paths are under a launcher-created, 0700 private directory.
// Evidence is a lab event log, not a tamper-proof audit trail.
func appendEvent(dir, event string) error {
	path := filepath.Join(dir, "watch.trace")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, event); err != nil {
		return err
	}
	return f.Sync()
}

func freshPulse(dir string) bool {
	st, err := os.Lstat(filepath.Join(dir, "pulse"))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return false
	}
	age := time.Since(st.ModTime())
	return age >= 0 && age <= pulseMaxAge
}

func observeCgroupGone(path string, parentFD, childFD int) (bool, string, error) {
	parentExited, err := processExited(parentFD)
	if err != nil {
		return false, "", err
	}
	childExited, err := processExited(childFD)
	if err != nil {
		return false, "", err
	}
	if !parentExited || !childExited {
		return false, "", nil
	}
	content, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
	if err == nil {
		alive, parseErr := parsePopulated(string(content))
		if parseErr != nil {
			return false, "", parseErr
		}
		if !alive {
			return true, "POPULATED_ZERO_PLUS_PIDFDS", nil
		}
		return false, "", nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if _, stErr := os.Stat(path); errors.Is(stErr, os.ErrNotExist) {
			return true, "CGROUP_REMOVED_PLUS_PIDFDS", nil
		}
	}
	return false, "", fmt.Errorf("cgroup verification incomplete: %w", err)
}

func runWatch(cg, unit string, mainPID, childPID int, dir string) error {
	if os.Getuid() == 0 {
		return errors.New("watchdog lab refuses root")
	}
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	if err := validateUnitPath(os.Getuid(), unit, cg); err != nil {
		return err
	}
	if err := validateCgroupV2Root(); err != nil {
		return err
	}
	if mainPID <= 1 || childPID <= 1 || mainPID == childPID {
		return errors.New("invalid worker/descendant pair")
	}
	me, err := readSmallFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	if strings.Contains(me, "0::"+cg+"\n") || strings.TrimSpace(me) == "0::"+cg {
		return errors.New("watchdog must not be in worker cgroup")
	}
	for _, pid := range []int{mainPID, childPID} {
		if err := verifyProcessInCgroup(pid, cg); err != nil {
			return err
		}
	}
	path := cgroupRoot + cg
	if err := verifyLimit(filepath.Join(path, "memory.max"), "134217728"); err != nil {
		return err
	}
	if err := verifyLimit(filepath.Join(path, "pids.max"), "32"); err != nil {
		return err
	}
	parentFD, err := unix.PidfdOpen(mainPID, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	childFD, err := unix.PidfdOpen(childPID, 0)
	if err != nil {
		return err
	}
	defer unix.Close(childFD)
	for _, pid := range []int{mainPID, childPID} {
		if err := verifyProcessInCgroup(pid, cg); err != nil {
			return err
		}
	}
	if !freshPulse(dir) {
		return errors.New("worker pulse not fresh at watchdog startup")
	}
	killer, err := os.OpenFile(filepath.Join(path, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer killer.Close()

	socket := filepath.Join(dir, "watch-gate.sock")
	if _, err := os.Lstat(socket); err == nil {
		return errors.New("gate socket already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	stopGate := make(chan struct{})
	gate := new(syntheticGate)
	gateDone := make(chan struct{})
	go func() {
		defer close(gateDone)
		serveGate(ln, gate, stopGate)
	}()
	defer func() {
		gate.fence()
		close(stopGate)
		ln.Close()
		<-gateDone
	}()
	if err := gate.arm(); err != nil {
		return err
	}
	if err := appendEvent(dir, "WATCH_READY_GATE_ARMED"); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "watch.ready"), []byte("READY\n"), 0600); err != nil {
		return err
	}

	// Liveness monitoring and synthetic egress gate run in a distinct
	// systemd transient service from the worker (checked by wrapper).
	// A hung or crashed worker triggers A0_SOFT_DENY before cgroup.kill.
	var reason string
	for {
		workerExited, err := processExited(parentFD)
		if err != nil {
			return err
		}
		if workerExited {
			reason = "WORKER_EXIT"
			break
		}
		if !freshPulse(dir) {
			reason = "PULSE_TIMEOUT"
			break
		}
		time.Sleep(watchTick)
	}
	gate.fence()
	if err := appendEvent(dir, "A0_SOFT_DENY_BEFORE_KILL reason="+reason); err != nil {
		return err
	}
	_, killErr := killer.Write([]byte("1"))
	if killErr != nil && !errors.Is(killErr, syscall.ENODEV) && !errors.Is(killErr, os.ErrNotExist) {
		_ = appendEvent(dir, "KILL_WRITE_FAILED")
		return fmt.Errorf("NOT_CONFIRMED: cgroup.kill: %w", killErr)
	}
	if err := appendEvent(dir, "CGROUP_KILL_ATTEMPTED"); err != nil {
		return err
	}
	deadline := time.Now().Add(watchTimeout)
	for time.Now().Before(deadline) {
		ok, proof, err := observeCgroupGone(path, parentFD, childFD)
		if ok {
			_ = appendEvent(dir, "KILL_CONFIRMED "+proof)
			fmt.Println("M1.7.2a LAB PASS: A0 synthetic fence before cgroup termination; " + proof)
			return nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = appendEvent(dir, "NOT_CONFIRMED "+err.Error())
			return fmt.Errorf("NOT_CONFIRMED: %w", err)
		}
		time.Sleep(watchTick)
	}
	_ = appendEvent(dir, "NOT_CONFIRMED timeout")
	return errors.New("NOT_CONFIRMED: worker cgroup has not been proven empty/removed")
}
