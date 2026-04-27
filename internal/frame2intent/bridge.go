// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package frame2intent

import (
	"context"
	pathpkg "path"
	"strings"
	"sync"

	"github.com/boanlab/kloudlens/internal/intent"
	"github.com/boanlab/kloudlens/pkg/types"
)

// atFDCWD mirrors the Linux AT_FDCWD constant. Userspace uses it to tell
// openat(2) "resolve relative to CWD" — the bridge skips its dirfd cache
// for this value and lets the CWD-based PathCompleter handle the path.
const atFDCWD int32 = -100

// MetaResolver maps (pidNS, mntNS) → ContainerMeta. The enricher package in
// a full deployment implements this; tests stub it.
type MetaResolver interface {
	Resolve(pidNS, mntNS uint32) types.ContainerMeta
}

// CgroupMetaResolver is an optional capability the resolver may satisfy.
// When the BPF wire header carries a non-zero cgroup_id, the bridge
// prefers this lookup over the NS pair because cgroup is per-task and
// uncoupled from hostPID/hostNetwork/hostMnt sharing — a privileged
// pod whose (pidNS, mntNS) collapses onto host inodes still resolves
// here. Resolvers that don't implement this interface (NopMetaResolver,
// older fixtures) gracefully fall through to the NS-pair path.
type CgroupMetaResolver interface {
	ResolveByCgroupID(cgroupID uint64) types.ContainerMeta
}

// BirthNotifier is the narrow contract the bridge needs to signal a container
// birth (clone/clone3 with namespace flags, unshare, setns). The enricher's
// *BirthNotifier satisfies this; tests use the no-op NopBirthNotifier.
type BirthNotifier interface {
	Notify(ctx context.Context)
}

// NopBirthNotifier ignores every call. Used when no enricher is attached.
type NopBirthNotifier struct{}

// Notify is a no-op for the nil notifier path.
func (NopBirthNotifier) Notify(context.Context) {}

// NopMetaResolver returns zero-valued ContainerMeta for every lookup.
type NopMetaResolver struct{}

func (NopMetaResolver) Resolve(_, _ uint32) types.ContainerMeta { return types.ContainerMeta{} }

// Bridge wires SyscallEvents into the intent.Aggregator. It holds just
// enough per-(pid, fd) state to correlate file open→IO→close and socket
// connect→IO→close. Socket tx/rx byte totals come from sendmsg/recvmsg
// retval; the BPF side does not read read/write retval, so ObserveFileIO
// fires with bytes=0 and the aggregator classifies FileRead vs FileWrite
// via open flags.
type Bridge struct {
	agg    *intent.Aggregator
	resolv MetaResolver
	births BirthNotifier
	ctx    context.Context

	mu       sync.Mutex
	fdPath   map[int64]string // (pid<<32 | fd) → path, so close can hand to agg
	fdIsSock map[int64]bool   // pid<<32|fd is a socket, routes close → ObserveSocketClose
}

// NewBridge returns a Bridge ready to accept events.
func NewBridge(agg *intent.Aggregator, mr MetaResolver) *Bridge {
	if mr == nil {
		mr = NopMetaResolver{}
	}
	return &Bridge{
		agg:      agg,
		resolv:   mr,
		births:   NopBirthNotifier{},
		ctx:      context.Background(),
		fdPath:   map[int64]string{},
		fdIsSock: map[int64]bool{},
	}
}

// AttachBirthNotifier wires a notifier that is signaled whenever the bridge
// observes a container-birth syscall (clone/clone3 with CLONE_NEWPID|NEWNS,
// unshare, setns). The notifier owns debouncing; the bridge just forwards.
// Passing nil reverts to the no-op notifier.
func (b *Bridge) AttachBirthNotifier(ctx context.Context, bn BirthNotifier) {
	if bn == nil {
		bn = NopBirthNotifier{}
	}
	b.births = bn
	if ctx != nil {
		b.ctx = ctx
	}
}

// Handle is a Handler that can be passed directly to Tracer.Start.
func (b *Bridge) Handle(e types.SyscallEvent) {
	// The mapper copies the wire header's PidNS/MntNS onto Meta but leaves
	// pod/container/namespace zero. Two-stage resolution:
	// 1. cgroup_id (per-task; survives hostPID/hostNetwork/hostMnt
	// collapsing the NS pair onto host inodes).
	// 2. (pidNS, mntNS) fallback when cgroup_id is zero or the cgroup
	// lookup yields nothing.
	// In either case we carry the NS pair forward so exporters still see
	// it even when the resolver returns zero (tests, fresh-container
	// races, non-k8s workloads).
	if !metaPopulated(e.Meta) {
		pidNS, mntNS := e.Meta.PidNS, e.Meta.MntNS
		var m types.ContainerMeta
		if e.CgroupID != 0 {
			if cr, ok := b.resolv.(CgroupMetaResolver); ok {
				m = cr.ResolveByCgroupID(e.CgroupID)
			}
		}
		// Fall through to NS pair when cgroup-id resolution returned
		// nothing useful (zero meta = walker missed AND not even a
		// host-process Cluster/NodeName stamp).
		if m.ContainerID == "" && m.Cluster == "" && m.NodeName == "" {
			m = b.resolv.Resolve(pidNS, mntNS)
		}
		if m.PidNS == 0 {
			m.PidNS = pidNS
		}
		if m.MntNS == 0 {
			m.MntNS = mntNS
		}
		e.Meta = m
	}
	eventID := e.EventID
	if eventID == "" {
		eventID = types.UUIDv7()
	}

	switch e.Category {
	case "process":
		b.handleProcess(e, eventID)
	case "file":
		b.handleFile(e, eventID)
	case "network":
		b.handleNetwork(e, eventID)
	}
}

func (b *Bridge) handleProcess(e types.SyscallEvent, eventID string) {
	switch e.Operation {
	case "execute":
		if e.RetVal != 0 {
			return
		}
		argv := argvFromArgs(e)
		b.agg.ObserveExec(e.PID, e.Resource, argv, "", eventID, e.TimestampNS, e.Meta)
		b.agg.FinalizeExec(e.PID, e.TimestampNS)
	case "exit":
		b.agg.OnProcessExit(e.PID, e.TimestampNS)
		b.forgetPID(e.PID)
	case "clone", "unshare", "setns":
		// Zero-miss container bootstrap: a container's birth shows up as
		// clone(CLONE_NEW*), unshare(CLONE_NEW*), or setns(fd, CLONE_NEW*).
		// Mapper now surfaces the CLONE_* flags as args[…].flags; gate the
		// Notify on any CLONE_NEW* bit so plain thread-clones (pthread_create)
		// don't trigger rescans. When flags are absent (degraded wire, older
		// kernel) fall back to unconditional notify — false-positives cost
		// one debounced /proc walk, false-negatives delay container
		// enrichment to the next periodic rescan.
		if b.births != nil {
			if notifyOnNSBirth(e) {
				b.births.Notify(b.ctx)
			}
		}
	}
}

func (b *Bridge) handleFile(e types.SyscallEvent, eventID string) {
	switch e.Operation {
	case "open", "open_write":
		if e.RetVal <= 0 { // BPF returns -errno on failure, 0 for stdin overlap
			return
		}
		// Pipeline.Handle deliberately clears Resource when an openat's
		// dirfd can't be absolutized (CWD-join would mislead). Without
		// the path, the resulting FileAccess intent has nothing
		// downstream consumers can act on — the close-side path-cache
		// lookup fails too. Drop here so empty-path file intents stop
		// polluting the JSONL stream and the dirfd cache stays accurate
		// (an empty fdPath entry would mask a real later open).
		if e.Resource == "" {
			return
		}
		fd := e.RetVal
		// Caching the final Resource (which Pipeline.ResolveDirfd may have
		// already absolutized via an earlier open's cached path) lets the
		// next openat(fd, relative) walk the tree one level deeper.
		key := fdKey(e.PID, fd)
		b.mu.Lock()
		b.fdPath[key] = e.Resource
		b.mu.Unlock()
		b.agg.ObserveFileOpen(e.PID, fd, e.Resource, openFlagHint(e), eventID, e.TimestampNS, e.Meta)
	case "close":
		fd := fdFromArgs(e)
		if fd == 0 {
			return
		}
		key := fdKey(e.PID, fd)
		b.mu.Lock()
		isSock := b.fdIsSock[key]
		delete(b.fdPath, key)
		delete(b.fdIsSock, key)
		b.mu.Unlock()
		if isSock {
			b.agg.ObserveSocketClose(e.PID, fd, eventID, e.TimestampNS)
			return
		}
		// When the BPF kl_fd_state map attached the original path +
		// open_ts to this close, we can synthesize a complete FileAccess
		// intent even if user-space missed the originating openat frame
		// (attach race, LRU eviction, container started before agent).
		// The mapper surfaces these as named args; an empty path falls
		// through to the basic ObserveFileClose path.
		kernelPath := namedArg(e, "path")
		openTs := uintNamedArg(e, "open_ts_ns")
		if kernelPath != "" || openTs != 0 {
			b.agg.ObserveFileCloseWithState(e.PID, fd, kernelPath, "",
				eventID, openTs, e.TimestampNS, e.Meta)
			return
		}
		b.agg.ObserveFileClose(e.PID, fd, eventID, e.TimestampNS)
	}
}

func (b *Bridge) handleNetwork(e types.SyscallEvent, eventID string) {
	switch e.Operation {
	case "socket":
		if e.RetVal <= 0 {
			return
		}
		fd := e.RetVal
		key := fdKey(e.PID, fd)
		b.mu.Lock()
		b.fdIsSock[key] = true
		b.mu.Unlock()
	case "connect":
		if e.Resource == "" {
			return
		}
		// Accept even non-zero RetVal for connect: EINPROGRESS is normal.
		fd := fdFromArgs(e)
		b.agg.ObserveSocketConnect(e.PID, fd, e.Resource, "tcp", eventID, e.TimestampNS, e.Meta)
	case "send", "recv":
		// sendmsg/recvmsg exit retval is the byte count; sendmmsg/recvmmsg
		// exit retval is a message count (the mapper tags those with
		// is_mmsg=1 so we can skip byte accounting cleanly). Negative
		// retval is a syscall error — drop it.
		if e.RetVal <= 0 {
			return
		}
		if uintNamedArg(e, "is_mmsg") != 0 {
			return
		}
		fd := fdFromArgs(e)
		if fd == 0 {
			return
		}
		kind := "tx"
		if e.Operation == "recv" {
			kind = "rx"
		}
		b.agg.ObserveSocketIO(e.PID, fd, kind, uint64(e.RetVal), eventID, e.TimestampNS, e.Meta) // #nosec G115 -- gated by RetVal > 0 above
	}
}

func (b *Bridge) forgetPID(pid int32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	want := int64(pid)
	// Iterate both maps. fdIsSock has standalone entries when socket ran
	// but connect never did — without this loop those leak per process
	// exit, growing unboundedly under workloads that create transient
	// sockets (DNS resolvers, health-checkers, short-lived clients).
	for k := range b.fdPath {
		if k>>32 == want {
			delete(b.fdPath, k)
			delete(b.fdIsSock, k)
		}
	}
	for k := range b.fdIsSock {
		if k>>32 == want {
			delete(b.fdIsSock, k)
		}
	}
}

func fdKey(pid, fd int32) int64 { return int64(pid)<<32 | int64(uint32(fd)) } // #nosec G115 -- fd is int32 reinterpreted as uint32 via two's complement for a composite map key

// metaPopulated is true when ContainerMeta carries any identity fields; used
// to decide whether the resolver should attempt enrichment.
func metaPopulated(m types.ContainerMeta) bool {
	return m.Pod != "" || m.Container != "" || m.ContainerID != "" || m.Namespace != "" || m.NodeName != ""
}

// argvFromArgs pulls the execve argv strarr slot back out of the mapper's
// structured args list. Returns nil if the argv wasn't serialized.
func argvFromArgs(e types.SyscallEvent) []string {
	for _, a := range e.Args {
		if a.Name == "argv" && a.Value != "" {
			// Value was joined with spaces; caller accepts that as the
			// canonical argv_hash input.
			return []string{a.Value}
		}
	}
	return nil
}

// openFlagHint returns one of "openr" / "openw" / "openrw" based on the
// access-mode bits the mapper preserved as args[flags]. Empty string when
// the mapper couldn't decode flags (truncated BPF frame) — the aggregator
// then falls back to opaque "Open" and any FileWrite signal is lost,
// which is preferable to misclassifying.
func openFlagHint(e types.SyscallEvent) string {
	for _, a := range e.Args {
		if a.Name != "flags" {
			continue
		}
		// Reuse the manual int parse loop already used for fd args — avoids
		// pulling strconv into this hot path.
		var v int32
		neg := false
		for i := 0; i < len(a.Value); i++ {
			c := a.Value[i]
			if i == 0 && c == '-' {
				neg = true
				continue
			}
			if c < '0' || c > '9' {
				break
			}
			v = v*10 + int32(c-'0')
		}
		if neg {
			v = -v
		}
		switch v & 0x3 { // O_ACCMODE
		case 0x1:
			return "openw"
		case 0x2:
			return "openrw"
		}
		// O_RDONLY — only O_CREAT / O_TRUNC can still flip to write. The
		// mapper already promoted those to Operation="open_write" so if we
		// landed here with mode=0, it's a true read.
		if e.Operation == "open_write" {
			return "openw"
		}
		return "openr"
	}
	return ""
}

// ResolveDirfd absolutizes a relative openat/openat2 path by looking up the
// dirfd in the bridge's fdPath cache. Returns (absPath, true) when the
// dirfd is known and its cached path is absolute; (rel, false) otherwise.
// The caller decides whether to fall back to CWD resolution or drop.
//
// AT_FDCWD is NOT handled here — the caller should route that to the
// CWD-based completer instead, since the bridge doesn't track CWD.
func (b *Bridge) ResolveDirfd(pid, dirfd int32, rel string) (string, bool) {
	if rel == "" || strings.HasPrefix(rel, "/") {
		return rel, true
	}
	b.mu.Lock()
	base, ok := b.fdPath[fdKey(pid, dirfd)]
	b.mu.Unlock()
	if !ok || base == "" || !strings.HasPrefix(base, "/") {
		return rel, false
	}
	return pathpkg.Clean(pathpkg.Join(base, rel)), true
}

// DirfdFromArgs pulls the decoded dirfd value out of ev.Args. Returns
// (0, false) when the mapper didn't record a dirfd (plain open(2) or a
// truncated openat frame the mapper fell back on).
func DirfdFromArgs(e types.SyscallEvent) (int32, bool) {
	for _, a := range e.Args {
		if a.Name != "dirfd" {
			continue
		}
		var v int32
		neg := false
		for i := 0; i < len(a.Value); i++ {
			c := a.Value[i]
			if i == 0 && c == '-' {
				neg = true
				continue
			}
			if c < '0' || c > '9' {
				break
			}
			v = v*10 + int32(c-'0')
		}
		if neg {
			v = -v
		}
		return v, true
	}
	return 0, false
}

// AtFDCWD exposes the AT_FDCWD constant to callers outside this package
// (pipeline.go in cmd/kloudlens) without leaking a magic number.
const AtFDCWD = atFDCWD

// CLONE_NEW* bits — kernel exposes identical constants for both
// clone(2) flags and setns(2) nstype. Keeping the mask local avoids a
// dependency on x/sys/unix just for eight constants.
const (
	cloneNewCgroup uint64 = 0x02000000
	cloneNewUTS    uint64 = 0x04000000
	cloneNewIPC    uint64 = 0x08000000
	cloneNewUser   uint64 = 0x10000000
	cloneNewPID    uint64 = 0x20000000
	cloneNewNet    uint64 = 0x40000000
	cloneNewNS     uint64 = 0x00020000
	cloneNewTime   uint64 = 0x00000080
	cloneNewMask          = cloneNewCgroup | cloneNewUTS | cloneNewIPC |
		cloneNewUser | cloneNewPID | cloneNewNet | cloneNewNS | cloneNewTime
)

// notifyOnNSBirth returns true when a clone/unshare/setns event carries at
// least one CLONE_NEW* bit. Absent flags arg → true (fail-open, see bridge
// comment). Parse errors → true for the same reason.
func notifyOnNSBirth(e types.SyscallEvent) bool {
	for _, a := range e.Args {
		if a.Name != "flags" {
			continue
		}
		var v uint64
		for i := 0; i < len(a.Value); i++ {
			c := a.Value[i]
			if c < '0' || c > '9' {
				return true
			}
			v = v*10 + uint64(c-'0')
		}
		return v&cloneNewMask != 0
	}
	return true
}

// fdFromArgs returns the "fd" arg for syscalls where the mapper stored it.
// namedArg returns the Value of the named arg, or "" if absent.
func namedArg(e types.SyscallEvent, name string) string {
	for _, a := range e.Args {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

// uintNamedArg returns the named arg parsed as uint64, or 0 on miss /
// parse failure.
func uintNamedArg(e types.SyscallEvent, name string) uint64 {
	v := namedArg(e, name)
	if v == "" {
		return 0
	}
	var out uint64
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < '0' || c > '9' {
			return 0
		}
		out = out*10 + uint64(c-'0')
	}
	return out
}

func fdFromArgs(e types.SyscallEvent) int32 {
	for _, a := range e.Args {
		if a.Name == "fd" {
			var v int32
			// Manual parse to avoid importing strconv just for this.
			for i := 0; i < len(a.Value); i++ {
				c := a.Value[i]
				if c < '0' || c > '9' {
					if i == 0 && c == '-' {
						continue
					}
					return v
				}
				v = v*10 + int32(c-'0')
			}
			if len(a.Value) > 0 && a.Value[0] == '-' {
				return -v
			}
			return v
		}
	}
	return 0
}
