//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestM172_SyntheticGateStartsDeniedAndNeverRearms(t *testing.T) {
	var gate syntheticGate
	if gate.request() {
		t.Fatal("default-open gate")
	}
	if err := gate.arm(); err != nil || !gate.request() {
		t.Fatalf("first arm failure: %v", err)
	}
	gate.fence()
	for i := 0; i < 20; i++ {
		if gate.request() {
			t.Fatal("fenced gate allowed another operation")
		}
	}
	if err := gate.arm(); err == nil {
		t.Fatal("fenced gate was rearmed")
	}
	if got := gate.count(); got != 1 {
		t.Fatalf("only one request should have passed, got=%d", got)
	}
}

func TestM172_SyntheticGateConcurrentFence(t *testing.T) {
	var gate syntheticGate
	if err := gate.arm(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				_ = gate.request()
			}
		}()
	}
	gate.fence()
	wg.Wait()
	for i := 0; i < 100; i++ {
		if gate.request() {
			t.Fatal("concurrent fence was bypassed")
		}
	}
}

func TestM172_WatchdogUnixGateFailClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "gate.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	var gate syntheticGate
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveGate(ln, &gate, stop)
	}()
	defer func() {
		close(stop)
		_ = ln.Close()
		<-done
	}()
	if ok, err := gateRequest(socket); err != nil || ok {
		t.Fatalf("gate allowed before arm: allowed=%t err=%v", ok, err)
	}
	if err := gate.arm(); err != nil {
		t.Fatal(err)
	}
	if ok, err := gateRequest(socket); err != nil || !ok {
		t.Fatalf("healthy gate rejected: allowed=%t err=%v", ok, err)
	}
	gate.fence()
	if ok, err := gateRequest(socket); err != nil || ok {
		t.Fatalf("gate allowed after fence: allowed=%t err=%v", ok, err)
	}
	_ = ln.Close()
	<-done
	if ok, err := gateRequest(socket); ok || err == nil {
		t.Fatalf("dead watchdog allowed synthetic egress: allowed=%t err=%v", ok, err)
	}
}

func TestM172_PulseStaleOrUnsafeFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if freshPulse(dir) {
		t.Fatal("missing pulse considered live")
	}
	pulse := filepath.Join(dir, "pulse")
	if err := os.WriteFile(pulse, []byte("alive"), 0600); err != nil {
		t.Fatal(err)
	}
	if !freshPulse(dir) {
		t.Fatal("fresh pulse rejected")
	}
	old := time.Now().Add(-3 * pulseMaxAge)
	if err := os.Chtimes(pulse, old, old); err != nil {
		t.Fatal(err)
	}
	if freshPulse(dir) {
		t.Fatal("stale pulse considered live")
	}
	if err := os.Chmod(pulse, 0644); err != nil {
		t.Fatal(err)
	}
	if freshPulse(dir) {
		t.Fatal("world-readable pulse accepted")
	}
}

func TestM172_DeniedOnClosedSocket(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if granted, err := gateRequest(filepath.Join(dir, "no-watchdog.sock")); granted || err == nil {
		t.Fatalf("missing watchdog failed open: %t %v", granted, err)
	}
}

func TestM172_CgroupObserverRejectsAbsentPidfds(t *testing.T) {
	if _, _, err := observeCgroupGone("/nonexistent", -1, -1); err == nil {
		t.Fatal("invalid pidfds must never report successful cgroup kill")
	}
}

func TestM172_AppendEventTraceOrdering(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := appendEvent(dir, "A0_SOFT_DENY_BEFORE_KILL"); err != nil {
		t.Fatal(err)
	}
	if err := appendEvent(dir, "CGROUP_KILL_ATTEMPTED"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "watch.trace"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "A0_SOFT_DENY_BEFORE_KILL\nCGROUP_KILL_ATTEMPTED\n" {
		t.Fatal(errors.New("order changed: " + string(b)))
	}
}
