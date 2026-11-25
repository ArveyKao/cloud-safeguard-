package cli

import (
	"strings"
	"testing"
)

// QA_BRIEF A (first half) gap coverage for the CLI. Login 0600 / never-printed
// and access outcomes are already proved by TestE2EAgentSignInAccessAndExec and
// TestSignInHardening; this file covers the removed top-level commands that
// TestUsageExitCodes only partially lists.

func TestQARemovedCommandsAreUnknown(t *testing.T) {
	for _, cmd := range []string{"providers", "agents", "caps", "policy", "audit", "request"} {
		t.Run(cmd, func(t *testing.T) {
			ta := newTestApp(t)
			code := ta.run(cmd)
			if code != ExitUsage {
				t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitUsage, ta.errOut())
			}
			if !strings.Contains(ta.errOut(), "unknown command") {
				t.Fatalf("stderr = %q, want unknown command", ta.errOut())
			}
		})
	}
}
