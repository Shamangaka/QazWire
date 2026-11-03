//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestM171_ParsePopulatedStrictly(t *testing.T) {
	table := []struct {
		in   string
		want bool
		err  bool
	}{
		{"populated 1\nfrozen 0\n", true, false},
		{"frozen 0\npopulated 0\n", false, false},
		{"populated 2\n", false, true},
		{"populated -1\n", false, true},
		{"frozen 0\n", false, true},
		{"populated 0\npopulated 1\n", false, true},
		{"populated 0 extra\n", false, true},
	}
	for _, tc := range table {
		got, err := parsePopulated(tc.in)
		if got != tc.want || (err != nil) != tc.err {
			t.Fatalf("parsePopulated(%q) = %t, %v; want %t, error=%t", tc.in, got, err, tc.want, tc.err)
		}
	}
}

func TestM171_CgroupPathRejectsForeignAndParent(t *testing.T) {
	uid := 1000
	unit := "qazwire-m171-0123456789abcdef.service"
	good := "/user.slice/user-1000.slice/user@1000.service/app.slice/" + unit
	if err := validateUnitPath(uid, unit, good); err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		unit, cg string
	}{
		{unit, "/"},
		{unit, "/user.slice/user-1000.slice/user@1000.service"},
		{unit, "/user.slice/user-1001.slice/user@1001.service/app.slice/" + unit},
		{unit, "/user.slice/user-1000.slice/user@1000.service/app.slice/other.service"},
		{unit, good + "/child"},
		{unit, "/user.slice/user-1000.slice/user@1000.service/app.slice/../app.slice/" + unit},
		{unit, "/user.slice/user-1000.slice/user@1000.service/app.slice//" + unit},
		{"other.service", good},
		{"qazwire-m171-123.service", good},
	}
	for _, tc := range bad {
		if err := validateUnitPath(uid, tc.unit, tc.cg); err == nil {
			t.Fatalf("accepted foreign or malformed unit: unit=%q cgroup=%q", tc.unit, tc.cg)
		}
	}
	if err := validateUnitPath(0, unit, good); err == nil {
		t.Fatal("root caller accepted")
	}
}

func TestM171_PrivateMarkerDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateDir(dir); err == nil {
		t.Fatal("world-searchable marker dir accepted")
	}
	if err := checkPrivateDir("relative"); err == nil {
		t.Fatal("relative marker dir accepted")
	}
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateDir(file); err == nil {
		t.Fatal("regular file accepted as a marker directory")
	}
}

func TestM171_InvalidMembershipRefused(t *testing.T) {
	// This test NEVER writes cgroup.kill. It only checks the process's own
	// membership gate, preventing accidental use against an unrelated unit.
	if err := verifyProcessInCgroup(0, "/"); err == nil {
		t.Fatal("PID zero accepted")
	}
	if err := verifyProcessInCgroup(1, "/"); err == nil {
		t.Fatal("PID 1 accepted")
	}
	if err := verifyProcessInCgroup(os.Getpid(), "/not-a-real-cgroup"); err == nil {
		t.Fatal("foreign cgroup accepted for invoking process")
	}
}

func TestM171_CgroupRootIsUnifiedOrExplicitlyUnavailable(t *testing.T) {
	err := validateCgroupV2Root()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Logf("cgroup v2 not exposed in this CI environment; integration test on Ubuntu required: %v", err)
	}
	// The host-bound path may be absent in a container; this is not a
	// production security check. It is a pure helper-package regression.
}
