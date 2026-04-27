// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package lineage resolves a process's ancestor chain by walking /proc.
// One Walker per Pipeline; tests inject Root to point at a tmpdir fixture
// so the walker stays unit-testable on hosts that lack the target PIDs.
package lineage

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Entry is a single ancestor on the chain. PPID is filled when the next
// ancestor is also present in the chain; the eldest entry's PPID stays
// zero (pid 1's parent is 0; the root case where the walker stopped at
// the cap also leaves PPID=0 because the next link wasn't read).
type Entry struct {
	PID    int32
	PPID   int32
	Comm   string // /proc/PID/comm — kernel truncates to 15 chars + NUL
	Binary string // /proc/PID/exe symlink target; empty if unreadable
}

// Walker resolves ancestors via /proc/PID/status (PPid:) and per-PID
// metadata files. Zero-value Walker (Root="", Cap=0) walks the host's
// /proc up to defaultCap entries.
type Walker struct {
	Root string // defaults to "/proc"
	Cap  int    // chain length cap; 0 → defaultCap
}

const defaultCap = 16

// Chain returns ancestors of pid, oldest-first. The leaf pid itself is
// never included — the caller already has it. A missing /proc entry,
// PPID 0 (kernel thread), or self-parent breaks the walk silently;
// callers treat the result as best-effort.
func (w *Walker) Chain(pid int32) []Entry {
	root := w.Root
	if root == "" {
		root = "/proc"
	}
	cap := w.Cap
	if cap <= 0 {
		cap = defaultCap
	}

	var chain []Entry
	cursor := pid
	for i := 0; i < cap; i++ {
		ppid, err := readPPID(root, cursor)
		if err != nil || ppid <= 0 || ppid == cursor {
			break
		}
		chain = append(chain, Entry{
			PID:    ppid,
			Comm:   readComm(root, ppid),
			Binary: readExe(root, ppid),
		})
		if ppid == 1 {
			break
		}
		cursor = ppid
	}
	// Backfill PPID by reading it off the next-older entry on the chain
	// (each ancestor's parent is the entry that follows it in walk order).
	for i := 0; i < len(chain)-1; i++ {
		chain[i].PPID = chain[i+1].PID
	}
	// Reverse to oldest-first so the snapshot reads root → ... → leaf-parent.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// readPPID parses the "PPid:" line out of /proc/PID/status. We use status
// (not stat) because stat's comm field can contain spaces or parens that
// confuse field splitting; status is line-oriented `Key:\tValue`.
func readPPID(root string, pid int32) (int32, error) {
	data, err := os.ReadFile(filepath.Join(root, strconv.Itoa(int(pid)), "status")) // #nosec G304 -- root is the procfs root, pid is the kernel-issued task id
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return 0, err
		}
		return int32(n), nil
	}
	return 0, os.ErrNotExist
}

// readComm returns the trimmed contents of /proc/PID/comm, or "" on any
// read error (process exited mid-walk, permission denied, …).
func readComm(root string, pid int32) string {
	data, err := os.ReadFile(filepath.Join(root, strconv.Itoa(int(pid)), "comm")) // #nosec G304 -- root is the procfs root, pid is the kernel-issued task id
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(data), "\n")
}

// readExe resolves /proc/PID/exe to the binary path, or "" on error
// (kernel threads have no exe; exited processes return ENOENT).
func readExe(root string, pid int32) string {
	target, err := os.Readlink(filepath.Join(root, strconv.Itoa(int(pid)), "exe"))
	if err != nil {
		return ""
	}
	return target
}
