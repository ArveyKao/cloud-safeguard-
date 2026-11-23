//go:build !darwin && !linux && !freebsd && !netbsd && !openbsd

package cli

import "os"

// isTerminal is false where it cannot be checked: csg then asks for --code
// instead of prompting.
func isTerminal(*os.File) bool { return false }
