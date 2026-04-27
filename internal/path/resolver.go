// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package path implements Full Path Resolution (plan, G1()).
// Rules (summarized):
// - Every resolved path comes in two representations: container-absolute
// and host-absolute.
// - Relative paths (AT_FDCWD + relative) are absolutized using the
// caller's cwd at the syscall moment.
// - fd → path uses an injectable FDTable with /proc/<pid>/fd fallback.
// - Socket fds render as `socket:[inode]`.
// - Never silently drop: on failure, set PathUnresolved=true with a reason.
//
// This package is deliberately kernel-agnostic and tested with fakes so
// unit tests can run without root or BPF.
package path

import (
	"errors"
	"fmt"
	"os"
	pathpkg "path"
	"strings"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Reason codes emitted in ResolvedPath.UnresolvedReason.
const (
	ReasonFdTableMiss     = "fd_table_miss"
	ReasonPathTooLong     = "path_too_long"
	ReasonDentryTruncated = "dentry_truncated"
	ReasonBPFDPathMissing = "bpf_d_path_unavailable"
	ReasonProcLookupFail  = "proc_lookup_failed"
	ReasonNullByte        = "path_contains_null"
	ReasonEmpty           = "empty_input"
)

// FDTable answers fd→path lookups for a given process. Real implementations
// read /proc/<pid>/fd; tests provide a map-backed fake.
type FDTable interface {
	Lookup(pid int32, fd int32) (path string, isSocket bool, ok bool)
}

// MountResolver maps container-absolute paths to host-absolute paths by
// applying per-mntns overlay/bind mount offsets. Tests supply a stub.
type MountResolver interface {
	HostPath(mntns uint32, containerAbs string) (string, bool)
}

// ProcessCWD returns the cwd+root for a process at the time the syscall
// was captured.
type ProcessCWD interface {
	Lookup(pid int32) (cwd string, root string, ok bool)
}

// Resolver composes the three strategies. All fields are injectable.
type Resolver struct {
	FD    FDTable
	Mount MountResolver
	CWD   ProcessCWD
	// MaxLen is the truncation boundary for resolved paths. 0 = no limit.
	MaxLen int
}

// AtFDCWD mirrors the kernel constant without importing unix-only headers.
const AtFDCWD = -100

// Input is what a syscall decoder hands to the resolver.
type Input struct {
	PID           int32
	MntNS         uint32
	DirFD         int32  // AT_FDCWD for "no dir fd"
	RawPath       string // as captured by bpf (relative or absolute)
	ContainerRoot string // empty when host path == container path
}

// Resolve returns a ResolvedPath. It never returns an error — failures
// surface via PathUnresolved/UnresolvedReason. The caller always gets an
// event; the pipeline decides what to do with degraded quality.
func (r *Resolver) Resolve(in Input) types.ResolvedPath {
	out := types.ResolvedPath{}

	if in.RawPath == "" && in.DirFD == AtFDCWD {
		out.PathUnresolved = true
		out.UnresolvedReason = ReasonEmpty
		return out
	}

	if strings.ContainsRune(in.RawPath, 0) {
		out.PathUnresolved = true
		out.UnresolvedReason = ReasonNullByte
		out.DentryHint = tail(in.RawPath, 32)
		return out
	}

	// Start: absolutize according to DirFD.
	abs, reason := r.absolutize(in)
	if reason != "" {
		out.PathUnresolved = true
		out.UnresolvedReason = reason
		out.DentryHint = tail(in.RawPath, 32)
		return out
	}

	// Canonicalize: resolve ".." / "." / duplicate "/".
	abs = pathpkg.Clean(abs)

	// Enforce max length policy.
	if r.MaxLen > 0 && len(abs) > r.MaxLen {
		out.PathUnresolved = true
		out.UnresolvedReason = ReasonPathTooLong
		out.DentryHint = tail(abs, 32)
		return out
	}

	out.ContainerAbs = abs
	if r.Mount != nil {
		if host, ok := r.Mount.HostPath(in.MntNS, abs); ok {
			out.HostAbs = host
		}
	}
	return out
}

func (r *Resolver) absolutize(in Input) (string, string) {
	// Socket or other non-path fd: render explicitly.
	if r.FD != nil && in.RawPath == "" {
		if p, isSock, ok := r.FD.Lookup(in.PID, in.DirFD); ok {
			if isSock {
				return p, "" // caller sees e.g. "socket:[inode]"
			}
			return p, ""
		}
		return "", ReasonFdTableMiss
	}
	if strings.HasPrefix(in.RawPath, "/") {
		return in.RawPath, ""
	}
	// Relative path: resolve against dirfd or CWD.
	if in.DirFD == AtFDCWD {
		if r.CWD == nil {
			return "", ReasonProcLookupFail
		}
		cwd, _, ok := r.CWD.Lookup(in.PID)
		if !ok {
			return "", ReasonProcLookupFail
		}
		return pathpkg.Join(cwd, in.RawPath), ""
	}
	// Relative to a directory fd.
	if r.FD == nil {
		return "", ReasonFdTableMiss
	}
	dir, isSock, ok := r.FD.Lookup(in.PID, in.DirFD)
	if !ok || isSock || dir == "" {
		return "", ReasonFdTableMiss
	}
	return pathpkg.Join(dir, in.RawPath), ""
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n+3:]
}

// ProcFDTable is a live /proc/<pid>/fd-backed FDTable.
type ProcFDTable struct {
	ProcPath string // default "/proc"
}

// NewProcFDTable returns a table rooted at /proc.
func NewProcFDTable() *ProcFDTable { return &ProcFDTable{ProcPath: "/proc"} }

// Lookup implements FDTable.
func (p *ProcFDTable) Lookup(pid int32, fd int32) (string, bool, bool) {
	root := p.ProcPath
	if root == "" {
		root = "/proc"
	}
	link := fmt.Sprintf("%s/%d/fd/%d", root, pid, fd)
	target, err := os.Readlink(link)
	if err != nil {
		return "", false, false
	}
	if strings.HasPrefix(target, "socket:[") {
		return target, true, true
	}
	// "pipe:[...]" "anon_inode:..." also non-file fds — keep as-is and mark as "socket-like"
	// so the decoder does not treat them as filesystem paths.
	if strings.HasPrefix(target, "pipe:[") || strings.HasPrefix(target, "anon_inode:") {
		return target, true, true
	}
	return target, false, true
}

// ProcCWD is a live /proc/<pid>/cwd-backed ProcessCWD.
type ProcCWD struct {
	ProcPath string // default "/proc"
}

// NewProcCWD returns a live ProcessCWD rooted at /proc.
func NewProcCWD() *ProcCWD { return &ProcCWD{ProcPath: "/proc"} }

// Lookup implements ProcessCWD.
func (p *ProcCWD) Lookup(pid int32) (string, string, bool) {
	root := p.ProcPath
	if root == "" {
		root = "/proc"
	}
	cwd, err := os.Readlink(fmt.Sprintf("%s/%d/cwd", root, pid))
	if err != nil {
		return "", "", false
	}
	procRoot, err := os.Readlink(fmt.Sprintf("%s/%d/root", root, pid))
	if err != nil {
		procRoot = "/"
	}
	return cwd, procRoot, true
}

// Sentinel for "no resolver attached" callers that want to distinguish.
var ErrNoResolver = errors.New("resolver not configured")
