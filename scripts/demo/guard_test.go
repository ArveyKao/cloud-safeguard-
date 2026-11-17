package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scripts/demo.sh deletes its data directory before each run. It must never
// delete anything but a directory inside this repository's .demo/: not a
// real instance that happens to hold only its own files, not the target of
// a symlink, not a path reached through "..".
func TestDemoScriptRefusesToDeleteOtherDirectories(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "demo.sh")
	// A directory that looks exactly like an instance.
	real := filepath.Join(t.TempDir(), "real-instance")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"master.key": "key", "csg.db": "recognisable"} {
		if err := os.WriteFile(filepath.Join(real, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	demoHome := filepath.Join(root, ".demo")
	if err := os.MkdirAll(demoHome, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(demoHome, "guard-test-link")
	_ = os.Remove(link)
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks are not available")
	}
	t.Cleanup(func() { _ = os.Remove(link) })

	// Every target resolves to the throwaway directory above, so a guard
	// that regressed could only delete that.
	through := filepath.Join(filepath.Dir(real), "x", "..", "real-instance")
	if err := os.MkdirAll(filepath.Join(filepath.Dir(real), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	targets := []string{
		real, real + "/", real + "//", through,
		link, link + "/", ".demo/guard-test-link", ".demo/guard-test-link/",
	}
	for _, target := range targets {
		cmd := exec.Command("bash", script, "--port", "18799", "--data-dir", target)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("--data-dir %s: the demo ran instead of refusing", target)
		}
		if !strings.Contains(string(out), "refusing to delete") {
			t.Errorf("--data-dir %s: no refusal: %s", target, out)
		}
		if strings.Contains(string(out), "removing existing") || strings.Contains(string(out), "== build ==") {
			t.Errorf("--data-dir %s: the demo got past the guard: %s", target, out)
		}
	}
	if data, err := os.ReadFile(filepath.Join(real, "csg.db")); err != nil || string(data) != "recognisable" {
		t.Fatalf("the instance directory was touched: %q, %v", data, err)
	}
}
