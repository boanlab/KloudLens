// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package e2e drives end-to-end tests against the kloudlens binary.
//
// Tests in this package compile the daemon, spawn it (with sudo where
// eBPF is required), drive deterministic syscalls in a child process,
// then assert that the JSONL output stream contains the expected
// IntentEvents. Unlike the unit tests under internal/ and pkg/, these
// tests exercise the real BPF loader, the real ringbuf consumer,
// and the real intent aggregator — everything from kernel hook to
// JSONL line.
//
// Tier layout:
// - smoke (always runs): --no-ebpf wiring check, no kernel involvement.
// - bpf (best-effort): real eBPF; the test fails fast when the kernel
// rejects the BPF object or sudo is unavailable.
//
// Drive the suite with:
//
//	go test ./tests/e2e/... -count=1 -v
//
// Set KLOUDLENS_E2E_BIN to point at a pre-built binary; otherwise the
// runner builds /tmp/kloudlens-e2e from ./cmd/kloudlens on demand.
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// binPath returns the path to a kloudlens binary suitable for e2e use.
// Honors $KLOUDLENS_E2E_BIN; otherwise builds once into /tmp and caches the
// path between subtests via sync.Once. Build failures fail the test rather
// than skip — the e2e suite assumes the codebase compiles.
var (
	binOnce sync.Once
	binFile string
	binErr  error
)

func binPath(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		if envBin := os.Getenv("KLOUDLENS_E2E_BIN"); envBin != "" {
			binFile = envBin
			return
		}
		repoRoot, err := findRepoRoot()
		if err != nil {
			binErr = err
			return
		}
		out := filepath.Join(os.TempDir(), "kloudlens-e2e")
		// #nosec G204 -- "go" and "./cmd/kloudlens" are constants; out is a tempdir path under the runner's control.
		cmd := exec.Command("go", "build", "-o", out, "./cmd/kloudlens")
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		buf, berr := cmd.CombinedOutput()
		if berr != nil {
			binErr = fmt.Errorf("go build: %w\n%s", berr, buf)
			return
		}
		binFile = out
	})
	if binErr != nil {
		t.Fatalf("kloudlens build failed: %v", binErr)
	}
	return binFile
}

// findRepoRoot walks up from this test file until it finds go.mod with the
// kloudlens module path. We don't trust os.Getwd because `go test` may
// chdir into the package directory.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 8; i++ {
		gomod := filepath.Join(dir, "go.mod")
		// #nosec G304 -- walking up from os.Getwd() to locate the repo's go.mod; no external input.
		if data, rerr := os.ReadFile(gomod); rerr == nil &&
			strings.Contains(string(data), "module github.com/boanlab/kloudlens") {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("could not locate kloudlens repo root (no go.mod with module path found)")
}

// requireLinux skips the test when the host kernel can't load the eBPF
// programs. eBPF tests need Linux + sudo; the smoke tier only needs Linux
// because --no-ebpf still talks to /proc.
func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("e2e tests target Linux; goos=%s", runtime.GOOS)
	}
}

// requireSudo verifies that `sudo -n` works (passwordless). Skips with a
// clear, actionable hint when it doesn't — the eBPF tier needs this.
func requireSudo(t *testing.T) {
	t.Helper()
	requireLinux(t)
	cmd := exec.Command("sudo", "-n", "true")
	if err := cmd.Run(); err != nil {
		t.Skipf("passwordless sudo unavailable; run: sudo -v && go test (err=%v)", err)
	}
}

// agent wraps a running kloudlens process plus the artifacts the test will
// inspect after shutdown.
type agent struct {
	cmd       *exec.Cmd
	outFile   string
	stderrBuf *strings.Builder
	cancel    context.CancelFunc
}

// agentOpts tunes how the runner launches kloudlens.
type agentOpts struct {
	// Args are appended after the runner's defaults (--output, --duration).
	Args []string
	// UseSudo wraps the command in `sudo -n` so the tracer can attach BPF.
	// Smoke tests with --no-ebpf set this to false.
	UseSudo bool
	// Duration replaces the runner default --duration. eBPF tests need
	// at least 10s — BPF attach takes ~1.5s and the aggregator's idle
	// flush window is on a similar scale, so shorter windows produce
	// flaky zero-event runs even when the kernel observes plenty.
	Duration time.Duration
}

// defaultBPFSkip is the set of BPF programs the runner unconditionally
// drops from the spec before NewCollection. Currently empty; kept as a
// hook so a kernel-version-specific incompatibility can land here without
// re-plumbing the runner.
var defaultBPFSkip = ""

// startAgent launches kloudlens and returns when stderr signals readiness
// (or the context expires). The caller is responsible for invoking wait.
func startAgent(t *testing.T, opts agentOpts) *agent {
	t.Helper()
	requireLinux(t)
	bin := binPath(t)

	if opts.UseSudo {
		requireSudo(t)
	}
	if opts.Duration == 0 {
		opts.Duration = 8 * time.Second
	}

	outFile := filepath.Join(t.TempDir(), "intents.jsonl")
	args := []string{
		"--output=" + outFile,
		fmt.Sprintf("--duration=%s", opts.Duration),
		"--stats-every=0",
	}
	if opts.UseSudo && defaultBPFSkip != "" {
		// eBPF tier: drop kernel-version-specific verifier-rejected
		// programs so the rest of the spec attaches. defaultBPFSkip is
		// empty in normal operation; populate it when a new kernel
		// regression appears.
		args = append(args, "--skip-bpf-programs="+defaultBPFSkip)
	}
	args = append(args, opts.Args...)

	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), opts.Duration+30*time.Second)
	if opts.UseSudo {
		// -E preserves env for $PATH lookup; -n makes a missing sudoers entry
		// fail fast instead of prompting.
		full := append([]string{"-n", "-E", bin}, args...)
		// #nosec G204 -- "sudo" is a constant; bin/args are runner-controlled (test code).
		cmd = exec.CommandContext(ctx, "sudo", full...)
	} else {
		// #nosec G204 -- bin/args are runner-controlled (test code).
		cmd = exec.CommandContext(ctx, bin, args...)
	}

	stderr := &strings.Builder{}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatalf("stderr pipe: %v", err)
	}
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start kloudlens: %v", err)
	}

	// Stream stderr into the buffer so a failure surfaces with full context.
	// We watch for the "running" marker before returning so trigger commands
	// in the test body can't race the BPF attach.
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		// Stderr lines from kloudlens are short; default buffer is fine.
		readyClosed := false
		for scanner.Scan() {
			line := scanner.Text()
			stderr.WriteString(line)
			stderr.WriteString("\n")
			if !readyClosed && strings.Contains(line, "kloudlens: running") {
				close(ready)
				readyClosed = true
			}
		}
		if !readyClosed {
			close(ready)
		}
	}()

	a := &agent{cmd: cmd, outFile: outFile, stderrBuf: stderr, cancel: cancel}

	select {
	case <-ready:
	case <-time.After(opts.Duration + 5*time.Second):
		_ = a.kill
		t.Fatalf("kloudlens never became ready within %v\n--- stderr ---\n%s", opts.Duration, stderr.String())
	}
	return a
}

// wait blocks until kloudlens finishes (auto-stop via --duration). Returns
// the parsed intents and the captured stderr for diagnostic dumps.
//
// Any non-zero exit is a hard failure with the verbatim stderr. BPF load
// failures get an extra hint pointing at --skip-bpf-programs so the
// operator can isolate the offending program; the test still fails so
// kernel-side regressions are visible rather than silently skipped.
func (a *agent) wait(t *testing.T) ([]types.IntentEvent, string) {
	t.Helper()
	defer a.cancel()
	err := a.cmd.Wait()
	stderr := a.stderrBuf.String()
	if err != nil {
		hint := ""
		if containsBPFLoadFailure(stderr) {
			hint = "\nhint: a specific program failed the verifier; use --skip-bpf-programs=<name> to drop it from the spec while you investigate."
		}
		t.Fatalf("kloudlens exited with error: %v%s\n--- stderr ---\n%s", err, hint, stderr)
	}
	intents, perr := readIntents(a.outFile)
	if perr != nil {
		t.Fatalf("read intents: %v\n--- stderr ---\n%s", perr, stderr)
	}
	return intents, stderr
}

// kill best-effort terminates a running agent. Used by the runner on
// startup-time failure paths; happy-path callers should use wait.
func (a *agent) kill() error {
	if a.cmd.Process == nil {
		return nil
	}
	a.cancel()
	return a.cmd.Process.Kill()
}

// readIntents parses a JSONL file of IntentEvents. We tolerate empty
// trailing lines and skip them silently — a partial flush from kloudlens
// would otherwise fail the parse.
func readIntents(path string) ([]types.IntentEvent, error) {
	// File may be root-owned (sudo case). Make it readable so tests running
	// as the user can parse it; failure to chmod isn't fatal — the open
	// will surface a more specific error.
	// #nosec G204 -- sudo/chmod/0644 are constants; path is the runner-controlled tempfile.
	_ = exec.Command("sudo", "-n", "chmod", "0644", path).Run()

	f, err := os.Open(path) // #nosec G304 -- runner-controlled tempfile
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []types.IntentEvent
	dec := bufio.NewScanner(f)
	dec.Buffer(make([]byte, 64<<10), 1<<20)
	for dec.Scan() {
		line := dec.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev types.IntentEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("parse line %q: %w", string(line), err)
		}
		out = append(out, ev)
	}
	return out, dec.Err()
}

// containsBPFLoadFailure inspects stderr for the verifier / loader errors
// the kloudlens main loop prints when the BPF object can't load. wait
// uses this to enrich the failure message with a --skip-bpf-programs hint
// so the operator can isolate the offending program quickly.
func containsBPFLoadFailure(stderr string) bool {
	patterns := []string{
		"load eBPF:",
		"load BPF collection",
		"invalid argument",
		"verifier",
	}
	matched := 0
	for _, p := range patterns {
		if strings.Contains(stderr, p) {
			matched++
		}
	}
	return matched >= 2
}

// dumpIntents formats up to 30 events for diagnostic output.
func dumpIntents(intents []types.IntentEvent) string {
	const max = 30
	var b strings.Builder
	for i, ev := range intents {
		if i >= max {
			fmt.Fprintf(&b, "... (%d more) ...\n", len(intents)-max)
			break
		}
		fmt.Fprintf(&b, " [%d] kind=%-15s attrs=%v\n", i, ev.Kind, ev.Attributes)
	}
	if len(intents) == 0 {
		b.WriteString(" (no intents emitted)\n")
	}
	return b.String()
}
