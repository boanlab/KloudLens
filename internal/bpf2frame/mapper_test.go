// SPDX-License-Identifier: Apache-2.0

package bpf2frame

import (
	"testing"

	"github.com/boanlab/kloudlens/internal/syscalls"
	"github.com/boanlab/kloudlens/pkg/types"
)

// atFDCWD mirrors the kernel constant so mapper tests can feed a realistic
// dirfd without importing from packages that depend on bpf2frame.
const atFDCWD = -100

func TestMapExecve(t *testing.T) {
	e := Event{HostPID: 4242, PID: 4242, UID: 0, SyscallID: syscalls.SysExecve, RetVal: 0}
	args := []any{
		"/usr/bin/python3",
		[]string{"python3", "-c", "print('hi')"},
		"/usr/bin/python3",
	}
	se := Map(e, args)
	if se.Category != "process" || se.Operation != "execute" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	if se.Resource != "/usr/bin/python3" || se.ExePath != "/usr/bin/python3" {
		t.Errorf("resource/exe: %q/%q", se.Resource, se.ExePath)
	}
	if len(se.Args) != 1 || se.Args[0].Value == "" {
		t.Errorf("argv arg not promoted: %+v", se.Args)
	}
	if se.Comm != "/usr/bin/python3" {
		t.Errorf("comm should be trailing source: %q", se.Comm)
	}
	if se.RetCode != "SUCCESS" {
		t.Errorf("retcode: %q", se.RetCode)
	}
}

func TestMapConnectAFINET(t *testing.T) {
	e := Event{SyscallID: syscalls.SysConnect, RetVal: 0, HostPID: 42}
	// AF_INET 10.0.0.5:5432 — address is little-endian as delivered by BPF.
	// 10.0.0.5 → bytes {10,0,0,5} → uint32 0x0500000a
	args := []any{
		int32(3),           // fd
		int32(2),           // AF_INET
		uint32(0x0500000a), // addr LE
		uint32(5432),       // port
		"/usr/bin/curl",    // source
	}
	se := Map(e, args)
	if se.Category != "network" || se.Operation != "connect" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	if se.Resource != "10.0.0.5:5432" {
		t.Fatalf("peer decode failed: %q", se.Resource)
	}
}

// TestMapConnectWithKernelPeerPID covers the optional peer_pid tag the
// BPF connect hook emits when its listener-registry lookup hits. The
// mapper must surface it as a named SyscallArg so the pipeline can
// resolve the peer's ContainerID without a second user-space lookup.
func TestMapConnectWithKernelPeerPID(t *testing.T) {
	e := Event{SyscallID: syscalls.SysConnect, RetVal: 0, HostPID: 42}
	args := []any{
		int32(3),           // fd
		int32(2),           // AF_INET
		uint32(0x0500000a), // addr LE (10.0.0.5)
		uint32(5432),       // port
		uint32(9999),       // peer_pid — kernel listener-registry hit
		"/usr/bin/curl",    // source (always last)
	}
	se := Map(e, args)
	if se.Resource != "10.0.0.5:5432" {
		t.Fatalf("peer decode: %q", se.Resource)
	}
	// Verify peer_pid was surfaced as a named arg.
	var seen bool
	for _, a := range se.Args {
		if a.Name == "peer_pid" && a.Value == "9999" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("peer_pid arg missing, got args=%+v", se.Args)
	}
}

// TestMapConnectPeerPIDZeroIgnored — a zero peer_pid means no-hit. The
// mapper skips the named arg so the pipeline's kernelPeerPID helper
// returns 0 (falls back to user-space peermatch).
func TestMapConnectPeerPIDZeroIgnored(t *testing.T) {
	e := Event{SyscallID: syscalls.SysConnect}
	args := []any{
		int32(3),
		int32(2),
		uint32(0x0500000a),
		uint32(5432),
		uint32(0), // peer_pid = 0 (no hit / older kernel build)
		"ssh",
	}
	se := Map(e, args)
	for _, a := range se.Args {
		if a.Name == "peer_pid" {
			t.Errorf("peer_pid=0 must be suppressed, got %+v", a)
		}
	}
}

// TestMapCloseWithKernelState covers the optional (path, open_ts_ns)
// args the BPF close hook emits when kl_fd_state tracked the originating
// openat. The mapper must surface both as named args and publish path as
// the event resource so the pipeline can synthesize a complete file
// intent without needing the openat frame.
func TestMapCloseWithKernelState(t *testing.T) {
	e := Event{SyscallID: syscalls.SysClose, RetVal: 0, HostPID: 42}
	args := []any{
		int32(7),                      // fd
		"/etc/passwd",                 // ARG_STR_REF resolved to path string
		uint64(1_700_000_000_000_000), // open_ts_ns
		"cat",                         // source
	}
	se := Map(e, args)
	if se.Operation != "close" {
		t.Fatalf("op: %q", se.Operation)
	}
	if se.Resource != "/etc/passwd" {
		t.Errorf("Resource = %q, want /etc/passwd", se.Resource)
	}
	var sawPath, sawTS bool
	for _, a := range se.Args {
		switch a.Name {
		case "path":
			sawPath = a.Value == "/etc/passwd"
		case "open_ts_ns":
			sawTS = a.Value == "1700000000000000"
		}
	}
	if !sawPath {
		t.Errorf("path arg missing: %+v", se.Args)
	}
	if !sawTS {
		t.Errorf("open_ts_ns arg missing: %+v", se.Args)
	}
}

// TestMapCloseNoKernelState confirms the legacy shape (fd + source only)
// still maps cleanly — kernels without kl_fd_state (older builds, LRU()
// evictions) must keep working.
func TestMapCloseNoKernelState(t *testing.T) {
	e := Event{SyscallID: syscalls.SysClose}
	args := []any{int32(7), "bash"}
	se := Map(e, args)
	if se.Resource != "" {
		t.Errorf("Resource must stay empty without kernel state, got %q", se.Resource)
	}
	for _, a := range se.Args {
		if a.Name == "path" || a.Name == "open_ts_ns" {
			t.Errorf("kernel-only args must not appear without state: %+v", a)
		}
	}
}

func TestMapConnectAFUNIX(t *testing.T) {
	e := Event{SyscallID: syscalls.SysConnect}
	args := []any{
		int32(3),               // fd
		int32(1),               // AF_UNIX
		"/var/run/docker.sock", // path
		uint32(0),              // unused
		"dockerd",              // source
	}
	se := Map(e, args)
	if se.Resource != "/var/run/docker.sock" {
		t.Fatalf("unix path: %q", se.Resource)
	}
}

func TestMapOpenat(t *testing.T) {
	e := Event{SyscallID: syscalls.SysOpenat, RetVal: 7}
	// Pkg 30: args[0] = dirfd, args[1] = path, args[2] = flags, args[3] = mode.
	args := []any{int32(atFDCWD), "/etc/passwd", int32(0), uint32(0), "/usr/bin/cat"}
	se := Map(e, args)
	if se.Category != "file" || se.Operation != "open" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	if se.Resource != "/etc/passwd" {
		t.Errorf("resource: %q", se.Resource)
	}
	// flags=0 (O_RDONLY) — the decoded arg should still be preserved so
	// downstream consumers can inspect it without re-parsing. dirfd=-100
	// (AT_FDCWD) should also have been captured for the Pkg 30 resolver.
	var sawFlags, sawDirfd bool
	for _, a := range se.Args {
		switch a.Name {
		case "flags":
			sawFlags = true
			if a.Value != "0" {
				t.Errorf("flags value: %q want 0", a.Value)
			}
		case "dirfd":
			sawDirfd = true
			if a.Value != "-100" {
				t.Errorf("dirfd value: %q want -100", a.Value)
			}
		}
	}
	if !sawFlags {
		t.Errorf("flags arg missing: %+v", se.Args)
	}
	if !sawDirfd {
		t.Errorf("dirfd arg missing: %+v", se.Args)
	}
}

func TestMapOpenatWriteFlags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flags  int32
		wantOp string
	}{
		{"O_RDONLY", 0x0, "open"},
		{"O_WRONLY", 0x1, "open_write"},
		{"O_RDWR", 0x2, "open_write"},
		{"O_CREAT", 0x40, "open_write"},
		{"O_RDONLY|O_TRUNC", 0x200, "open_write"},
		{"O_WRONLY|O_CREAT|O_TRUNC", 0x241, "open_write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := Event{SyscallID: syscalls.SysOpenat, RetVal: 7}
			args := []any{int32(atFDCWD), "/var/log/app.log", tc.flags, uint32(0o644), "/usr/bin/tee"}
			se := Map(e, args)
			if se.Operation != tc.wantOp {
				t.Fatalf("op: %q want %q", se.Operation, tc.wantOp)
			}
			if se.Resource != "/var/log/app.log" {
				t.Errorf("resource: %q", se.Resource)
			}
		})
	}
}

func TestMapOpenatMissingFlagsStillOpen(t *testing.T) {
	// Truncated ring frame: only the path survives. We must still emit
	// the generic "open" op (conservative read) rather than panicking or
	// promoting to write.
	e := Event{SyscallID: syscalls.SysOpenat, RetVal: 7}
	args := []any{"/etc/hosts"}
	se := Map(e, args)
	if se.Operation != "open" {
		t.Fatalf("op: %q want open (no flags available)", se.Operation)
	}
	for _, a := range se.Args {
		if a.Name == "flags" {
			t.Errorf("flags arg should be absent when truncated: %+v", se.Args)
		}
	}
}

func TestMapSetresuid(t *testing.T) {
	e := Event{SyscallID: syscalls.SysSetresuid}
	args := []any{uint32(0), uint32(0), uint32(0), "/bin/su"}
	se := Map(e, args)
	if se.Category != "creds" || se.Operation != "setuid" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
}

func TestMapSchedExit(t *testing.T) {
	e := Event{SyscallID: syscalls.SysSchedProcessExit}
	args := []any{"/usr/bin/curl"}
	se := Map(e, args)
	if se.Category != "process" || se.Operation != "exit" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	if se.ExePath != "/usr/bin/curl" {
		t.Errorf("exe: %q", se.ExePath)
	}
}

func TestMapUnknownSyscallFallback(t *testing.T) {
	e := Event{SyscallID: 9999}
	se := Map(e, nil)
	if se.Category != "default" {
		t.Errorf("fallback category: %q", se.Category)
	}
	if se.Operation != "syscall_9999" {
		t.Errorf("fallback op: %q", se.Operation)
	}
}

func TestMapRetCodeFormat(t *testing.T) {
	for _, tc := range []struct {
		rv   int32
		want string
	}{
		{0, "SUCCESS"}, {3, "3"}, {-22, "-22"}, {-1, "-1"},
	} {
		if got := retCode(tc.rv); got != tc.want {
			t.Errorf("retCode(%d) = %q, want %q", tc.rv, got, tc.want)
		}
	}
}

func TestMapTolerateTruncatedArgs(t *testing.T) {
	// execve usually 3 args, but BPF may drop on the floor — ensure we don't
	// panic when args is empty.
	e := Event{SyscallID: syscalls.SysExecve}
	se := Map(e, nil)
	if se.Category != "default" { // fallback since args empty
		t.Errorf("category with no args: %q", se.Category)
	}
}

// lookupArg returns the Value of the first SyscallArg matching name.
func lookupArg(args []types.SyscallArg, name string) (string, bool) {
	for _, a := range args {
		if a.Name == name {
			return a.Value, true
		}
	}
	return "", false
}

func TestMapCloneDecodesNSFlags(t *testing.T) {
	// CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWNET — typical container birth.
	const flags = uint64(0x20000000 | 0x00020000 | 0x40000000)
	e := Event{SyscallID: syscalls.SysClone, HostPID: 777}
	se := Map(e, []any{flags, "runc"})
	if se.Category != "process" || se.Operation != "clone" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	raw, ok := lookupArg(se.Args, "flags")
	if !ok {
		t.Fatalf("flags arg missing: %+v", se.Args)
	}
	if raw != "1610743808" {
		t.Errorf("flags raw: %q", raw)
	}
	sym, ok := lookupArg(se.Args, "ns_flags")
	if !ok {
		t.Fatalf("ns_flags arg missing: %+v", se.Args)
	}
	// Canonical order: NS, UTS(), IPC(), USER(), PID(), NET(), CGROUP(), TIME.
	if sym != "CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET" {
		t.Errorf("ns_flags: %q", sym)
	}
}

func TestMapCloneSkipsNSFlagsWhenPlainThread(t *testing.T) {
	// pthread_create uses CLONE_VM|CLONE_FS|… but NO CLONE_NEW* bits.
	const flags = uint64(0x00010f00)
	e := Event{SyscallID: syscalls.SysClone}
	se := Map(e, []any{flags, "some-binary"})
	if _, ok := lookupArg(se.Args, "ns_flags"); ok {
		t.Errorf("ns_flags should be absent for plain thread clone")
	}
}

func TestMapUnshareDecodesNSFlags(t *testing.T) {
	// unshare(CLONE_NEWUSER|CLONE_NEWNS)
	const flags = uint64(0x10000000 | 0x00020000)
	e := Event{SyscallID: syscalls.SysUnshare}
	se := Map(e, []any{flags, "unshare"})
	sym, ok := lookupArg(se.Args, "ns_flags")
	if !ok {
		t.Fatalf("ns_flags missing: %+v", se.Args)
	}
	if sym != "CLONE_NEWNS|CLONE_NEWUSER" {
		t.Errorf("ns_flags: %q", sym)
	}
}

// TestMapSetuidSurfacesNewUid pins the 1-arg setuid variant: uid(0) should
// appear as both "uid" (variant-specific name) and "new_uid" (the name the
// pipeline creds branch reads to build CredTransition.To). Without the
// "new_uid" alias, consumers would have to dispatch on syscall variant.
func TestMapSetuidSurfacesNewUid(t *testing.T) {
	e := Event{SyscallID: syscalls.SysSetuid, RetVal: 0, UID: 1000}
	se := Map(e, []any{uint32(0), "sudo"})
	if se.Category != "creds" || se.Operation != "setuid" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	if v, ok := lookupArg(se.Args, "uid"); !ok || v != "0" {
		t.Errorf("uid: %q ok=%v", v, ok)
	}
	if v, ok := lookupArg(se.Args, "new_uid"); !ok || v != "0" {
		t.Errorf("new_uid: %q ok=%v", v, ok)
	}
}

// TestMapSetresuidEuidWins verifies that the resolved new_uid alias picks
// the euid field (args[1]) — that's what set*uid(2) actually flips in
// terms of live kernel credentials, so the CredTransition "To" should
// track it, not the ruid/suid surface fields.
func TestMapSetresuidEuidWins(t *testing.T) {
	e := Event{SyscallID: syscalls.SysSetresuid, RetVal: 0, UID: 1000}
	// ruid=unchanged, euid=0 (escalate), suid=0.
	se := Map(e, []any{uint32(0xFFFFFFFF), uint32(0), uint32(0), "attacker"})
	if v, ok := lookupArg(se.Args, "euid"); !ok || v != "0" {
		t.Errorf("euid: %q ok=%v", v, ok)
	}
	if v, ok := lookupArg(se.Args, "ruid"); !ok || v != "unchanged" {
		t.Errorf("ruid should surface as unchanged: %q ok=%v", v, ok)
	}
	if v, ok := lookupArg(se.Args, "new_uid"); !ok || v != "0" {
		t.Errorf("new_uid should come from euid: %q ok=%v", v, ok)
	}
}

// TestMapSetreuidUnchangedEuidNoNewUid: when euid is -1 ("unchanged"),
// no new_uid should be emitted — the pipeline would otherwise record a
// no-op CredTransition that pollutes the timeline.
func TestMapSetreuidUnchangedEuidNoNewUid(t *testing.T) {
	e := Event{SyscallID: syscalls.SysSetreuid, RetVal: 0}
	se := Map(e, []any{uint32(1001), uint32(0xFFFFFFFF), "app"})
	if _, ok := lookupArg(se.Args, "new_uid"); ok {
		t.Errorf("unchanged euid should not produce new_uid")
	}
	if v, ok := lookupArg(se.Args, "euid"); !ok || v != "unchanged" {
		t.Errorf("euid should still surface as 'unchanged' for debugging: %q ok=%v", v, ok)
	}
}

// TestMapSetgidSymmetric smoke-checks the gid variant shares the path.
func TestMapSetgidSymmetric(t *testing.T) {
	e := Event{SyscallID: syscalls.SysSetgid, RetVal: 0, GID: 100}
	se := Map(e, []any{uint32(0), "app"})
	if se.Category != "creds" || se.Operation != "setgid" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	if v, ok := lookupArg(se.Args, "new_gid"); !ok || v != "0" {
		t.Errorf("new_gid: %q ok=%v", v, ok)
	}
}

func TestMapSetnsDecodesNSFlag(t *testing.T) {
	// setns(fd=5, nstype=CLONE_NEWPID) — single-bit case.
	e := Event{SyscallID: syscalls.SysSetns}
	se := Map(e, []any{int32(5), int32(0x20000000), "nsenter"})
	sym, ok := lookupArg(se.Args, "ns_flags")
	if !ok {
		t.Fatalf("ns_flags missing: %+v", se.Args)
	}
	if sym != "CLONE_NEWPID" {
		t.Errorf("ns_flags: %q", sym)
	}
}
