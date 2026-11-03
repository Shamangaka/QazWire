//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
package klmproc17

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The helper runs in ANOTHER OS PROCESS; all klm16 material is allocated
// inside this child, never in the parent process running the test.
func TestM17_WorkerProcessHelper(t *testing.T) {
	if os.Getenv("QW_M17_HELPER") != "1" {
		return
	}
	if err := ServeSynthetic(context.Background(), os.Getenv("QW_M17_SOCK")); err != nil {
		t.Fatalf("synthetic worker process: %v", err)
	}
}

func requestWithTimeout(sock string, op Opcode, id uint32) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	return Request(ctx, sock, op, id)
}

func TestM17_RealChildProcessUsesVersionedUnixIPC(t *testing.T) {
	dir := t.TempDir()
	// Go testing.TempDir subdirectories may use 0755; explicit 0700 is
	// required by the worker endpoint policy, not inferred from t.TempDir.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "klmproc.sock")
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestM17_WorkerProcessHelper$")
	child.Env = append(os.Environ(), "QW_M17_HELPER=1", "QW_M17_SOCK="+sock)
	child.Stdout, child.Stderr = null, null
	child.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	defer func() { _ = child.Process.Kill() }() // test cleanup; NOT Stage-D containment

	var pid uint64
	started := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-done:
			t.Fatalf("child exited before IPC handshake: %v", err)
		default:
		}
		pid, err = requestWithTimeout(sock, OpPing, 1)
		if err == nil {
			started = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		t.Fatalf("worker socket never became ready: %v", err)
	}
	if pid == uint64(os.Getpid()) || pid != uint64(child.Process.Pid) {
		t.Fatalf("worker must have a distinct OS PID: parent=%d worker=%d child=%d",
			os.Getpid(), pid, child.Process.Pid)
	}
	info, err := os.Stat(sock)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("Unix socket permissions not private: %v %v", info, err)
	}
	if epoch, err := requestWithTimeout(sock, OpStatus, 2); err != nil || epoch != 1 {
		t.Fatalf("initial synthetic epoch: %d %v", epoch, err)
	}
	if _, err := requestWithTimeout(sock, Opcode(99), 3); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown command not denied: %v", err)
	}
	if epoch, err := requestWithTimeout(sock, OpStatus, 4); err != nil || epoch != 1 {
		t.Fatalf("unknown command modified state: %d %v", epoch, err)
	}
	if epoch, err := requestWithTimeout(sock, OpRotate, 5); err != nil || epoch != 2 {
		t.Fatalf("rotation was not local to worker: %d %v", epoch, err)
	}
	if _, err := requestWithTimeout(sock, OpStop, 6); err != nil {
		t.Fatalf("stop was not acknowledged: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("worker exit after stop: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not exit after stop")
	}
	if _, err := requestWithTimeout(sock, OpStatus, 7); err == nil {
		t.Fatal("stopped worker still accepting new IPC")
	}
}

func TestM17_SocketDirectoryOwnershipAndPrivacy(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0700) }()
	if err := ServeSynthetic(context.Background(), filepath.Join(dir, "worker.sock")); !errors.Is(err, ErrUnsafeDirectory) {
		t.Fatalf("world-searchable socket directory accepted: %v", err)
	}
	if err := ServeSynthetic(context.Background(), "relative.sock"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative endpoint accepted: %v", err)
	}
	privateDir := t.TempDir()
	if err := os.Chmod(privateDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(privateDir, "existing.sock")
	if err := os.WriteFile(target, []byte("do not replace"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ServeSynthetic(context.Background(), target); !errors.Is(err, ErrInvalid) {
		t.Fatalf("existing file was not protected: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "do not replace" {
		t.Fatalf("socket startup replaced existing file: %v", err)
	}
}

func TestM17_ProtocolFramingIsFixedSizeAndStrict(t *testing.T) {
	var b bytes.Buffer
	if err := writeFrame(&b, frame{op: OpPing, id: 0x11223344}); err != nil {
		t.Fatal(err)
	}
	if b.Len() != frameLen {
		t.Fatalf("frame size=%d", b.Len())
	}
	p, err := readFrame(&b)
	if err != nil || p.op != OpPing || p.id != 0x11223344 || p.value != 0 {
		t.Fatalf("round trip: %+v %v", p, err)
	}
	bad := make([]byte, frameLen)
	if _, err := readFrame(bytes.NewReader(bad)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("invalid magic accepted: %v", err)
	}
	if _, err := readFrame(bytes.NewReader([]byte{1})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame accepted: %v", err)
	}
}

func TestM17_ClientRequiresDeadlineAndRejectsForgedReply(t *testing.T) {
	if _, err := Request(context.Background(), "/nonexistent", OpStatus, 1); !errors.Is(err, ErrDeadlineRequired) {
		t.Fatalf("deadline not required: %v", err)
	}
	if _, err := Request(nil, "/nonexistent", OpStatus, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil context accepted: %v", err)
	}
	socket := filepath.Join(t.TempDir(), "fake.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptUnix()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		req, err := readFrame(conn)
		if err == nil {
			err = writeFrame(conn, frame{op: req.op | 0x80, id: req.id + 1})
		}
		served <- err
	}()
	_, err = requestWithTimeout(socket, OpStatus, 10)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("forged request ID accepted: %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fake server did not finish")
	}
}
