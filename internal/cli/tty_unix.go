//go:build darwin || linux || freebsd || netbsd || openbsd

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether f is a terminal: the terminal-attributes ioctl
// succeeds only on one. A character device such as /dev/null is not one.
func isTerminal(f *os.File) bool {
	var attrs syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), ioctlGetTermios, uintptr(unsafe.Pointer(&attrs)))
	return errno == 0
}
