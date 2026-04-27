// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package lineage

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeProcEntry stages the three files Walker reads per PID. exe is a
// symlink target; empty string skips the symlink (mirrors a kernel thread
// or a permission-denied readlink).
type fakeProcEntry struct {
	pid  int32
	ppid int32
	comm string
	exe  string
}

func writeFakeProc(t *testing.T, root string, entries []fakeProcEntry) {
	t.Helper()
	for _, e := range entries {
		dir := filepath.Join(root, strconv.Itoa(int(e.pid)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		status := "Name:\t" + e.comm + "\nPPid:\t" + strconv.Itoa(int(e.ppid)) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(e.comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if e.exe != "" {
			if err := os.Symlink(e.exe, filepath.Join(dir, "exe")); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestChainBuildsRootFirst stages a five-deep chain (1 → 100 → 200 → 300
// → 400) and asserts the walker returns ancestors of 400 oldest-first
// without including the leaf itself. Verifies the common k8s pod tree
// shape (init → containerd-shim → entrypoint → user binary).
func TestChainBuildsRootFirst(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, []fakeProcEntry{
		{pid: 1, ppid: 0, comm: "init", exe: "/sbin/init"},
		{pid: 100, ppid: 1, comm: "containerd-shim", exe: "/usr/bin/containerd-shim"},
		{pid: 200, ppid: 100, comm: "bash", exe: "/bin/bash"},
		{pid: 300, ppid: 200, comm: "python3", exe: "/usr/bin/python3"},
		{pid: 400, ppid: 300, comm: "curl", exe: "/usr/bin/curl"},
	})

	w := &Walker{Root: root}
	chain := w.Chain(400)

	wantPIDs := []int32{1, 100, 200, 300}
	if len(chain) != len(wantPIDs) {
		t.Fatalf("chain length=%d, want %d (%+v)", len(chain), len(wantPIDs), chain)
	}
	for i, want := range wantPIDs {
		if chain[i].PID != want {
			t.Errorf("chain[%d].PID=%d, want %d", i, chain[i].PID, want)
		}
	}
	// PPID backfill: each entry's PPID should match the next-younger entry
	// on the original walk (so the chain reads as a parent pointer chain
	// from root downward).
	wantPPIDs := []int32{0, 1, 100, 200}
	for i, want := range wantPPIDs {
		if chain[i].PPID != want {
			t.Errorf("chain[%d].PPID=%d, want %d", i, chain[i].PPID, want)
		}
	}
	if chain[0].Comm != "init" || chain[0].Binary != "/sbin/init" {
		t.Errorf("root entry comm/binary lost: %+v", chain[0])
	}
	if chain[3].Comm != "python3" || chain[3].Binary != "/usr/bin/python3" {
		t.Errorf("leaf-parent comm/binary lost: %+v", chain[3])
	}
}

// TestChainStopsAtCap caps the walker at 2 even though a deeper chain
// exists. Guards against runaway walks on hosts with deep nesting (e.g.
// nested containers).
func TestChainStopsAtCap(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, []fakeProcEntry{
		{pid: 1, ppid: 0, comm: "init"},
		{pid: 10, ppid: 1, comm: "a"},
		{pid: 20, ppid: 10, comm: "b"},
		{pid: 30, ppid: 20, comm: "c"},
		{pid: 40, ppid: 30, comm: "d"},
	})

	w := &Walker{Root: root, Cap: 2}
	chain := w.Chain(40)

	if len(chain) != 2 {
		t.Fatalf("cap=2: got %d entries, want 2 (%+v)", len(chain), chain)
	}
	// With cap=2 the walker reads two ancestors (PID 30 and PID 20) before
	// the budget runs out; oldest-first ordering puts 20 ahead of 30.
	if chain[0].PID != 20 || chain[1].PID != 30 {
		t.Errorf("cap=2 chain order=%+v, want [20,30]", chain)
	}
}

// TestChainMissingPID returns an empty chain rather than panicking when
// the leaf pid has no /proc entry. Mirrors the case where the agent
// learns of an exec slightly after the process exited (race we cannot
// avoid with /proc-based lineage).
func TestChainMissingPID(t *testing.T) {
	w := &Walker{Root: t.TempDir()}
	if got := w.Chain(999); len(got) != 0 {
		t.Errorf("missing pid: got %d entries, want 0", len(got))
	}
}

// TestChainStopsAtInit halts the walk once PID 1 is recorded — init's
// PPID is 0 (kernel) and walking past would either no-op or trip on a
// kernel-thread node. Either is wrong; stopping cleanly is the right
// behavior.
func TestChainStopsAtInit(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, []fakeProcEntry{
		{pid: 1, ppid: 0, comm: "init"},
		{pid: 50, ppid: 1, comm: "child"},
	})

	w := &Walker{Root: root}
	chain := w.Chain(50)
	if len(chain) != 1 || chain[0].PID != 1 {
		t.Errorf("expected single init entry, got %+v", chain)
	}
}

// TestChainTolerantOfMissingComm: the walker must not abort on a per-PID
// metadata read failure — comm and exe are best-effort and a missing
// /proc/PID/comm just leaves the field blank. PPID resolution stays
// authoritative because /proc/PID/status is what drives the walk.
func TestChainTolerantOfMissingComm(t *testing.T) {
	root := t.TempDir()
	// Stage status for PID 1 + 60 but skip the comm file for PID 1.
	writeFakeProc(t, root, []fakeProcEntry{
		{pid: 60, ppid: 1, comm: "child"},
	})
	// Manually write only status for PID 1, no comm/exe.
	dir := filepath.Join(root, "1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("PPid:\t0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := &Walker{Root: root}
	chain := w.Chain(60)
	if len(chain) != 1 || chain[0].PID != 1 {
		t.Fatalf("walk should still surface init, got %+v", chain)
	}
	if chain[0].Comm != "" || chain[0].Binary != "" {
		t.Errorf("missing comm/exe should leave fields blank, got %+v", chain[0])
	}
}
