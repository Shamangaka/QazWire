//go:build qazwire_exp && linux

// SPDX-License-Identifier: MIT
// Package klmproc17 is a synthetic Linux OUT-OF-PROCESS IPC laboratory.
// It is NOT a security sandbox, cryptographic KLM, VPN or secure-erasure proof.
package klmproc17

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/internal/qazwireexp/klm16"
)

var (
	ErrInvalid          = errors.New("klmproc17: invalid input")
	ErrDeadlineRequired = errors.New("klmproc17: finite deadline required")
	ErrUnsafeDirectory  = errors.New("klmproc17: socket directory must be private and owned by worker")
	ErrProtocol         = errors.New("klmproc17: invalid wire frame")
	ErrUnsupported      = errors.New("klmproc17: operation not supported")
	ErrRemote           = errors.New("klmproc17: synthetic worker rejected operation")
	ErrPeer             = errors.New("klmproc17: unexpected peer uid")
)

type Opcode uint8

const (
	OpPing   Opcode = 1
	OpStatus Opcode = 2
	OpRotate Opcode = 3
	OpStop   Opcode = 4
)

const (
	wireVersion   = 1
	frameLen      = 20
	maxConcurrent = 8
	ioTimeout     = time.Second
	statusOK      = 0
	statusNoOp    = 1
	statusFailed  = 2
)

var wireMagic = [4]byte{'Q', 'K', '1', '7'}

// The fixed-size 20-byte frame contains NO secret bytes or payload field.
// wire: magic[4] version[1] opcode[1] status[1] reserved[1]
//
//	request_id[4] value[8], all multibyte fields big-endian.
//
// A response sets opcode's high bit. Request fields status/value must be 0.
type frame struct {
	op     Opcode
	status byte
	id     uint32
	value  uint64
}

func readFrame(r io.Reader) (frame, error) {
	var buf [frameLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return frame{}, err
	}
	if !bytes.Equal(buf[0:4], wireMagic[:]) || buf[4] != wireVersion || buf[7] != 0 {
		return frame{}, ErrProtocol
	}
	return frame{
		op: Opcode(buf[5]), status: buf[6],
		id:    binary.BigEndian.Uint32(buf[8:12]),
		value: binary.BigEndian.Uint64(buf[12:20]),
	}, nil
}

func writeFrame(w io.Writer, f frame) error {
	var buf [frameLen]byte
	copy(buf[0:4], wireMagic[:])
	buf[4] = wireVersion
	buf[5] = byte(f.op)
	buf[6] = f.status
	binary.BigEndian.PutUint32(buf[8:12], f.id)
	binary.BigEndian.PutUint64(buf[12:20], f.value)
	for remaining := buf[:]; len(remaining) != 0; {
		n, err := w.Write(remaining)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		remaining = remaining[n:]
	}
	return nil
}

func privateSocketDirectory(path string) error {
	if !filepath.IsAbs(path) || len(path) == 0 {
		return ErrInvalid
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%w: parent mode=%#o", ErrUnsafeDirectory, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: missing Linux stat metadata", ErrUnsafeDirectory)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%w: owner=%d worker_uid=%d", ErrUnsafeDirectory, st.Uid, os.Getuid())
	}
	// The socket itself must not replace any existing file or symlink.
	if _, err := os.Lstat(path); err == nil {
		return ErrInvalid
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil || cred == nil {
		return 0, ErrPeer
	}
	return cred.Uid, nil
}

// ServeSynthetic is called by the TEST WORKER process, never by a real VPN.
// Peer UID is checked against the worker's own UID for this same-UID lab;
// a future production launcher MUST provide distinct UIDs and MAC controls.
// No key material, networking, data-plane or payload is exposed by this API.
func ServeSynthetic(ctx context.Context, socket string) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := privateSocketDirectory(socket); err != nil {
		return err
	}
	session, err := klm16.NewLabSession(64, 4096, 2)
	if err != nil {
		return err
	}
	defer session.Stop()

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}

	stop := make(chan struct{})
	var stopOnce sync.Once
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
		case <-done:
		}
		_ = ln.Close()
	}()
	defer close(done)

	slots := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			case <-stop:
				wg.Wait()
				return nil
			default:
				wg.Wait()
				return err
			}
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				defer c.Close()
				if uid, err := peerUID(c); err != nil || uid != uint32(os.Getuid()) {
					return
				}
				_ = c.SetDeadline(time.Now().Add(ioTimeout))
				request, err := readFrame(c)
				if err != nil || request.status != 0 || request.value != 0 || byte(request.op)&0x80 != 0 {
					return
				}
				reply := frame{op: request.op | 0x80, id: request.id}
				switch request.op {
				case OpPing:
					reply.value = uint64(os.Getpid())
				case OpStatus:
					reply.value = session.Snapshot().CurrentEpoch
				case OpRotate:
					if err := session.Rotate(); err != nil {
						reply.status = statusFailed
					} else {
						reply.value = session.Snapshot().CurrentEpoch
					}
				case OpStop:
					session.Stop()
					defer stopOnce.Do(func() { close(stop) })
				default:
					reply.status = statusNoOp
				}
				_ = writeFrame(c, reply)
			}()
		default:
			// Saturation denies new requests rather than spawning unbounded goroutines.
			_ = c.Close()
		}
	}
}

// Request performs exactly one bounded round trip. All exported responses
// contain only a PID or a synthetic epoch: never key material or plaintext.
// The caller must set an explicit deadline; it is not inferred.
func Request(ctx context.Context, socket string, op Opcode, requestID uint32) (uint64, error) {
	if ctx == nil || socket == "" || op == 0 || byte(op)&0x80 != 0 {
		return 0, ErrInvalid
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, ErrDeadlineRequired
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	if err := writeFrame(conn, frame{op: op, id: requestID}); err != nil {
		return 0, err
	}
	reply, err := readFrame(conn)
	if err != nil {
		return 0, err
	}
	if reply.op != op|0x80 || reply.id != requestID {
		return 0, ErrProtocol
	}
	switch reply.status {
	case statusOK:
		return reply.value, nil
	case statusNoOp:
		return 0, ErrUnsupported
	case statusFailed:
		return 0, ErrRemote
	default:
		return 0, fmt.Errorf("%w: invalid status %d", ErrProtocol, reply.status)
	}
}
