/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"

	"golang.org/x/sys/unix"
)

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	err = rc.Control(func(fd uintptr) {
		_, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		txOffload = errSyscall == nil
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		rxOffload = errSyscall == nil && opt == 1
	})
	if err != nil {
		return false, false
	}
	return txOffload, rxOffload
}

// enableUDPGRO attempts to enable UDP_GRO on conn and reports whether it is on.
func enableUDPGRO(conn *net.UDPConn) bool {
	// Kernels below 5.12 are missing 98184612aca0 ("net:
	// udp: Add support for getsockopt(..., ..., UDP_GRO,
	// ..., ...);"), which means we can't read this back
	// later. We could pipe the return value through to
	// the rest of the code, but UDP_GRO is kind of buggy
	// anyway, so just gate this here.
	major, minor := kernelVersion()
	if major < 5 || (major == 5 && minor < 12) {
		return false
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	err = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	})
	if err != nil {
		return false
	}
	_, rxOffload := supportsUDPOffload(conn)
	return rxOffload
}
