// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package bpf2frame

import (
	"fmt"
	"strings"

	"github.com/boanlab/kloudlens/internal/syscalls"
	"github.com/boanlab/kloudlens/pkg/types"
)

// Map converts a raw wire Event plus its decoded arguments into a neutral
// types.SyscallEvent. Args are interpreted per-syscall; unknown syscalls get
// a generic "default" category. Callers own the resulting ContainerMeta
// lookup — the mapper leaves Meta zero-valued so callers can fill it from
// their nsMap asynchronously.
//
// The mapper is intentionally lenient: if the argument slice is shorter
// than expected it returns what it could decode rather than an error, so
// truncated ring-buffer frames still produce a usable partial event.
func Map(e Event, args []any) types.SyscallEvent {
	name := syscalls.SyscallName(e.SyscallID)
	ev := types.SyscallEvent{
		TimestampNS: e.Timestamp,
		CPUID:       uint32(e.CPUID),
		HostPID:     e.HostPID,
		HostTID:     e.HostTID,
		HostPPID:    e.HostPPID,
		PID:         e.PID,
		TID:         e.TID,
		UID:         e.UID,
		GID:         e.GID,
		SyscallID:   e.SyscallID,
		SyscallName: name,
		RetVal:      e.RetVal,
		RetCode:     retCode(e.RetVal),
		CgroupID:    e.CgroupID,
		// Surface the namespace identity from the wire header so the bridge
		// can hand (pidNS, mntNS) to the enricher. Downstream code path keeps
		// Meta zero-valued otherwise — the enricher fills pod/container.
		Meta: types.ContainerMeta{PidNS: e.PidNsID, MntNS: e.MntNsID},
	}

	if len(args) == 0 {
		ev.Category = "default"
		ev.Operation = name
		return ev
	}

	// Convention: the BPF program appends the caller's comm/exe as the
	// last TypeSource arg. If the trailing arg is a string and no
	// category-specific branch consumes it, promote it to ev.Comm.
	promoteSource := func() {
		if s, ok := args[len(args)-1].(string); ok && ev.Comm == "" {
			ev.Comm = s
		}
	}

	switch name {
	case "execve":
		ev.Category = "process"
		ev.Operation = "execute"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
			ev.ExePath = ev.Resource
		}
		if len(args) >= 2 {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "argv", Type: "strarr", Value: strings.Join(asStringSlice(args[1]), " ")})
		}
		promoteSource()

	case "execveat":
		ev.Category = "process"
		ev.Operation = "execute"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
			ev.ExePath = ev.Resource
		}
		if len(args) >= 2 {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "argv", Type: "strarr", Value: strings.Join(asStringSlice(args[1]), " ")})
		}
		promoteSource()

	case "clone", "clone3":
		ev.Category = "process"
		ev.Operation = "clone"
		// args[0] is the full CLONE_* flag ulong (bpf/kloudlens.bpf.c encodes
		// it verbatim for both clone and clone3). Userspace uses the
		// CLONE_NEW* bits to gate the BirthNotifier — pass the raw value
		// through so the bridge can inspect it cheaply. ns_flags carries a
		// "|"-joined symbolic subset for sinks that want readable output.
		if len(args) >= 1 {
			if flags, ok := asUint64(args[0]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "flags", Type: "ulong", Value: fmt.Sprint(flags)})
				if sym := decodeCloneNSFlags(flags); sym != "" {
					ev.Args = append(ev.Args, types.SyscallArg{Name: "ns_flags", Type: "str", Value: sym})
				}
			}
		}
		promoteSource()

	case "kill", "tgkill":
		ev.Category = "process"
		ev.Operation = "kill"
		if len(args) >= 1 {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "pid", Type: "int", Value: fmt.Sprint(args[0])})
		}
		if len(args) >= 2 {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "sig", Type: "int", Value: fmt.Sprint(args[1])})
		}
		promoteSource()

	case "setuid", "setreuid", "setresuid", "setfsuid":
		ev.Category = "creds"
		ev.Operation = "setuid"
		// Surface the new-uid target(s). Pipeline's creds branch turns these
		// into CredTransition.From/To (see pipeline.go). The BPF side may
		// emit only the trailing comm string; the bounded-by-name arg
		// extractor below tolerates that by only appending the args it
		// actually finds.
		collectUidGidArgs(&ev, name, args, "uid")
		promoteSource()

	case "setgid", "setregid", "setresgid", "setfsgid":
		ev.Category = "creds"
		ev.Operation = "setgid"
		collectUidGidArgs(&ev, name, args, "gid")
		promoteSource()

	case "capset":
		ev.Category = "creds"
		ev.Operation = "capset"
		promoteSource()

	case "cap_capable":
		// kprobe/cap_capable — emits (cap, opts). We promote cap to ev.Resource()
		// as a stable identifier so the baseline / contract layer can build
		// a cap-name allow-list ("CAP_NET_BIND_SERVICE" etc.) without having
		// to walk ev.Args. opts encodes flags like CAP_OPT_NOAUDIT — pass
		// through for any consumer that wants to filter audit-only checks.
		ev.Category = "creds"
		ev.Operation = "cap_capable"
		if len(args) >= 1 {
			if cap, ok := asInt32(args[0]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "cap", Type: "int", Value: fmt.Sprint(cap)})
				ev.Resource = capName(cap)
			}
		}
		if len(args) >= 2 {
			if opts, ok := asUint64(args[1]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "opts", Type: "uint", Value: fmt.Sprint(uint32(opts))}) // #nosec G115 -- BPF-decoded uint, narrowed for display
			}
		}
		promoteSource()

	case "prctl":
		// (option, arg2). PodSecurity / AppArmor adapters care about the
		// privilege-escalation knobs (PR_SET_NO_NEW_PRIVS=38, PR_CAP_AMBIENT=47,
		// PR_SET_DUMPABLE=4, PR_SET_KEEPCAPS=8). Surface option as ev.Operation()
		// for a stable per-option category.
		ev.Category = "process"
		ev.Operation = "prctl"
		if len(args) >= 1 {
			if opt, ok := asInt32(args[0]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "option", Type: "int", Value: fmt.Sprint(opt)})
				if name := prctlOptionName(opt); name != "" {
					ev.Resource = name
				}
			}
		}
		if len(args) >= 2 {
			if arg2, ok := asUint64(args[1]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "arg2", Type: "ulong", Value: fmt.Sprint(arg2)})
			}
		}
		promoteSource()

	case "mmap", "mprotect":
		// PROT_EXEC-only emission filtered in BPF; if we see the event the
		// workload is creating an executable mapping. Surface as the
		// process/exec_map operation so apparmor / seccomp adapters can pick
		// it up uniformly across both syscalls.
		ev.Category = "process"
		ev.Operation = "exec_map"
		if len(args) >= 1 {
			if addr, ok := asUint64(args[0]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "addr", Type: "ulong", Value: fmt.Sprint(addr)})
			}
		}
		if len(args) >= 2 {
			if length, ok := asUint64(args[1]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "length", Type: "ulong", Value: fmt.Sprint(length)})
			}
		}
		if len(args) >= 3 {
			if prot, ok := asUint64(args[2]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "prot", Type: "ulong", Value: fmt.Sprint(prot)})
			}
		}
		promoteSource()

	case "chroot":
		ev.Category = "process"
		ev.Operation = "chroot"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "ptrace":
		ev.Category = "process"
		ev.Operation = "ptrace"
		if len(args) >= 2 {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "request", Type: "int", Value: fmt.Sprint(args[0])})
			ev.Args = append(ev.Args, types.SyscallArg{Name: "pid", Type: "int", Value: fmt.Sprint(args[1])})
		}
		promoteSource()

	case "unshare":
		ev.Category = "process"
		ev.Operation = name
		if len(args) >= 1 {
			if flags, ok := asUint64(args[0]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "flags", Type: "ulong", Value: fmt.Sprint(flags)})
				if sym := decodeCloneNSFlags(flags); sym != "" {
					ev.Args = append(ev.Args, types.SyscallArg{Name: "ns_flags", Type: "str", Value: sym})
				}
			}
		}
		promoteSource()

	case "setns":
		ev.Category = "process"
		ev.Operation = name
		// setns emits (fd, nstype). nstype is one of the CLONE_NEW* values,
		// so route it through as "flags" for a uniform downstream test.
		if len(args) >= 2 {
			if ns, ok := asInt32(args[1]); ok {
				raw := uint64(uint32(ns)) // #nosec G115 -- int32 → uint32 via two's-complement bit pattern for flag decoding
				ev.Args = append(ev.Args, types.SyscallArg{Name: "flags", Type: "ulong", Value: fmt.Sprint(raw)})
				if sym := decodeCloneNSFlags(raw); sym != "" {
					ev.Args = append(ev.Args, types.SyscallArg{Name: "ns_flags", Type: "str", Value: sym})
				}
			}
		}
		promoteSource()

	case "open", "openat", "openat2":
		ev.Category = "file"
		ev.Operation = "open"
		// openat/openat2 frames lead with dirfd so userspace can resolve
		// relative paths against an earlier absolute open. Plain open(2)
		// keeps the (path, flags, mode) shape. We detect the layout by
		// type — an int32 at args[0] means dirfd-led, a string means a
		// path-led (or truncated) frame.
		pathIdx, flagsIdx := 0, 1
		if name == "openat" || name == "openat2" {
			if len(args) >= 1 {
				if dirfd, ok := asInt32(args[0]); ok {
					ev.Args = append(ev.Args, types.SyscallArg{Name: "dirfd", Type: "int", Value: fmt.Sprint(dirfd)})
					pathIdx, flagsIdx = 1, 2
				}
			}
		}
		if len(args) > pathIdx {
			ev.Resource = asString(args[pathIdx])
		}
		if len(args) > flagsIdx {
			if flags, ok := asInt32(args[flagsIdx]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "flags", Type: "int", Value: fmt.Sprint(flags)})
				if isWriteOpenFlags(flags) {
					ev.Operation = "open_write"
				}
			}
		}
		promoteSource()

	case "close":
		ev.Category = "file"
		ev.Operation = "close"
		if len(args) >= 1 {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(args[0])})
		}
		// Optional BPF-attached state from kl_fd_state: args[1]=path (from
		// the ARG_STR_REF resolve against the str cache) and args[2]=
		// open_ts_ns (uint64). Present only for fds the kernel tracked
		// from openat; missing when the open predated our attach or the
		// LRU evicted. Source tag, if emitted, is always last.
		if len(args) >= 3 {
			if path, ok := args[1].(string); ok && path != "" {
				ev.Resource = path
				ev.Args = append(ev.Args, types.SyscallArg{Name: "path", Type: "str", Value: path})
			}
			if ts, ok := args[2].(uint64); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "open_ts_ns", Type: "uint", Value: fmt.Sprint(ts)})
			}
		}
		promoteSource()

	case "chmod", "fchmodat":
		ev.Category = "file"
		ev.Operation = "chmod"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "fchmod":
		ev.Category = "file"
		ev.Operation = "chmod"
		if len(args) >= 1 {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(args[0])})
		}
		promoteSource()

	case "chown", "fchownat", "lchown":
		ev.Category = "file"
		ev.Operation = "chown"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "fchown":
		ev.Category = "file"
		ev.Operation = "chown"
		if len(args) >= 1 {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(args[0])})
		}
		promoteSource()

	case "unlink", "unlinkat":
		ev.Category = "file"
		ev.Operation = "unlink"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "rename", "renameat", "renameat2":
		ev.Category = "file"
		ev.Operation = "rename"
		if len(args) >= 2 {
			ev.Resource = asString(args[0])
			ev.Args = append(ev.Args,
				types.SyscallArg{Name: "oldpath", Type: "str", Value: asString(args[0])},
				types.SyscallArg{Name: "newpath", Type: "str", Value: asString(args[1])},
			)
		}
		promoteSource()

	case "link", "linkat", "symlink", "symlinkat":
		ev.Category = "file"
		ev.Operation = name
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "mkdir", "mkdirat":
		ev.Category = "file"
		ev.Operation = "mkdir"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "rmdir":
		ev.Category = "file"
		ev.Operation = "rmdir"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "mount":
		ev.Category = "file"
		ev.Operation = "mount"
		if len(args) >= 2 {
			ev.Resource = asString(args[1]) // dir_name
		}
		promoteSource()

	case "umount2":
		ev.Category = "file"
		ev.Operation = "umount"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "socket":
		ev.Category = "network"
		ev.Operation = "socket"
		promoteSource()

	case "bind":
		ev.Category = "network"
		ev.Operation = "bind"
		if fd, ok := args[0].(int32); ok {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(fd)})
		}
		if addr := decodeSockAddr(args); addr != "" {
			ev.Resource = addr
		}
		promoteSource()

	case "connect":
		ev.Category = "network"
		ev.Operation = "connect"
		if fd, ok := args[0].(int32); ok {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(fd)})
		}
		if addr := decodeSockAddr(args); addr != "" {
			ev.Resource = addr
		}
		// Optional peer_pid tag emitted by the BPF connect hook when the
		// listener registry has a hit. Lives at args[4] (uint32) — the
		// source tag, if present, is always the LAST arg, so a uint32 at
		// index 4 is unambiguous (the source string tag decodes to a Go
		// string, never a uint32).
		if len(args) >= 5 {
			if pid, ok := args[4].(uint32); ok && pid != 0 {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "peer_pid", Type: "uint", Value: fmt.Sprint(pid)})
			}
		}
		promoteSource()

	case "listen":
		ev.Category = "network"
		ev.Operation = "listen"
		if fd, ok := args[0].(int32); ok {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(fd)})
		}
		promoteSource()

	case "accept", "accept4":
		ev.Category = "network"
		ev.Operation = "accept"
		if fd, ok := args[0].(int32); ok {
			ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(fd)})
		}
		promoteSource()

	case "sendmsg", "recvmsg":
		// Wire shape from the ENTER hook: ARG_INT(fd) ARG_INT(flags). EXIT
		// merges its retval (byte count) onto the same event. The bridge
		// reads ev.RetVal as the byte total and routes it to
		// ObserveSocketIO; ev.Operation "send"/"recv" picks the direction.
		ev.Category = "network"
		if name == "sendmsg" {
			ev.Operation = "send"
		} else {
			ev.Operation = "recv"
		}
		if len(args) >= 1 {
			if fd, ok := args[0].(int32); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(fd)})
			}
		}
		promoteSource()

	case "sendmmsg", "recvmmsg":
		// Multi-message variants. retval is the count of messages
		// processed, not bytes — surface the call but leave byte
		// accounting to the single-call hooks.
		ev.Category = "network"
		if name == "sendmmsg" {
			ev.Operation = "send"
		} else {
			ev.Operation = "recv"
		}
		if len(args) >= 1 {
			if fd, ok := args[0].(int32); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "fd", Type: "int", Value: fmt.Sprint(fd)})
			}
		}
		// Mark as message-count, not bytes, so the bridge knows to skip
		// ObserveSocketIO on these (retval is a count, not a length).
		ev.Args = append(ev.Args, types.SyscallArg{Name: "is_mmsg", Type: "uint", Value: "1"})
		promoteSource()

	case "sched_process_exit":
		ev.Category = "process"
		ev.Operation = "exit"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
			ev.ExePath = ev.Resource
		}

	case "security_bprm_check",
		"security_file_open",
		"security_path_chroot",
		"security_path_chmod",
		"security_path_chown",
		"security_path_unlink",
		"security_path_mkdir",
		"security_path_rmdir",
		"security_path_link",
		"security_path_symlink":
		ev.Category = "security"
		ev.Operation = name
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "security_path_rename":
		ev.Category = "security"
		ev.Operation = name
		if len(args) >= 2 {
			ev.Resource = asString(args[0])
			ev.Args = append(ev.Args,
				types.SyscallArg{Name: "oldpath", Type: "str", Value: asString(args[0])},
				types.SyscallArg{Name: "newpath", Type: "str", Value: asString(args[1])},
			)
		} else if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		promoteSource()

	case "security_task_kill":
		ev.Category = "security"
		ev.Operation = name
		promoteSource()

	case "security_socket_connect",
		"security_socket_bind",
		"security_socket_sendmsg",
		"security_socket_recvmsg":
		// LSM kprobes emit (family, addr, port) via kl_put_sockaddr_kernel —
		// same shape as the connect/bind tracepoints, but starting at args[0]
		// because there's no leading fd. We hand it to decodeSockAddrAt so
		// the existing AF_INET / AF_UNIX render lands the rendered peer in
		// ev.Resource.
		ev.Category = "security"
		ev.Operation = name
		if addr := decodeSockAddrAt(args, 0); addr != "" {
			ev.Resource = addr
		}
		promoteSource()

	case "dns_answer":
		// One emit per A/AAAA record found in a DNS response. Wire shape:
		// ARG_RESOURCE(qname) ARG_UINT(rtype) ARG_UINT(addr_be)
		// ARG_ULONG(cgroup_id) ARG_SOURCE(comm)
		// The cilium adapter consumes ev.Resource as the FQDN and a peer
		// rendered from rtype+addr_be; cgroup_id lets the pipeline ask
		// the enricher for pod metadata even when the standard
		// pid_ns/mnt_ns header is bogus (cgroup_skb runs in softirq
		// context; current_task is unreliable). Until the contract IR
		// adds a dedicated DNS field we route through ev.Args so
		// downstream layers can opt in incrementally.
		ev.Category = "network"
		ev.Operation = "dns_answer"
		if len(args) >= 1 {
			ev.Resource = asString(args[0])
		}
		if len(args) >= 2 {
			if rtype, ok := asUint64(args[1]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "rtype", Type: "uint", Value: fmt.Sprint(uint32(rtype))}) // #nosec G115 -- BPF-decoded enum, fits u32
			}
		}
		if len(args) >= 3 {
			if addr, ok := args[2].(uint32); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "addr", Type: "uint", Value: fmt.Sprintf("%d.%d.%d.%d",
					byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))}) // #nosec G115 -- byte packing uint32 IPv4
			}
		}
		if len(args) >= 4 {
			if cgid, ok := asUint64(args[3]); ok {
				ev.Args = append(ev.Args, types.SyscallArg{Name: "cgroup_id", Type: "ulong", Value: fmt.Sprint(cgid)})
			}
		}
		promoteSource()

	default:
		ev.Category = "default"
		ev.Operation = name
		promoteSource()
	}

	return ev
}

// retCode emits a label ("SUCCESS" / "-EACCES" / ...) using a simple
// signed-nonzero convention; exporters map to errno strings via the
// platform package if needed.
func retCode(rv int32) string {
	if rv == 0 {
		return "SUCCESS"
	}
	if rv > 0 {
		return fmt.Sprintf("%d", rv)
	}
	return fmt.Sprintf("-%d", -rv)
}

// asString tolerates missing / wrongly typed args.
func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// Linux open(2) access-mode bits and the write-implying create/truncate flags.
// O_ACCMODE = 0x3 masks out the mode (RDONLY=0, WRONLY=1, RDWR=2); CREAT/TRUNC
// imply mutation even if the caller happened to also ask for O_RDONLY.
const (
	oAccMode int32 = 0x3
	oWrOnly  int32 = 0x1
	oRdWr    int32 = 0x2
	oCreat   int32 = 0x40
	oTrunc   int32 = 0x200
)

func isWriteOpenFlags(f int32) bool {
	mode := f & oAccMode
	if mode == oWrOnly || mode == oRdWr {
		return true
	}
	return f&(oCreat|oTrunc) != 0
}

// asInt32 pulls an int32 from a BPF-side arg. The wire decoder emits int32 for
// TypeInt; we also accept the common integer fallbacks so unit tests that
// inline literals keep working.
func asInt32(v any) (int32, bool) {
	switch x := v.(type) {
	case int32:
		return x, true
	case uint32:
		return int32(x), true // #nosec G115 -- narrowing a BPF-decoded uint32 arg, caller treats it as int32
	case int:
		return int32(x), true // #nosec G115 -- narrowing BPF-decoded arg, bounded by BPF map value size
	case int64:
		return int32(x), true // #nosec G115 -- narrowing BPF-decoded arg, bounded by BPF map value size
	}
	return 0, false
}

// asUint64 pulls a uint64 from a BPF-side arg. Mirrors asInt32 but accepts the
// full width TypeULong / TypeVarintU64 decoders produce, plus the unsigned
// narrow types for fallback paths.
func asUint64(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case int64:
		return uint64(x), true // #nosec G115 -- widening a BPF-decoded int64 arg
	case uint32:
		return uint64(x), true
	case int32:
		return uint64(uint32(x)), true // #nosec G115 -- int32 → uint32 via bit pattern, then widen
	case int:
		return uint64(x), true // #nosec G115 -- widening a BPF-decoded int arg
	}
	return 0, false
}

func asStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	if ss, ok := v.([]string); ok {
		return ss
	}
	return []string{fmt.Sprint(v)}
}

// decodeSockAddr scans bind/connect args for the encoded (family, addr, port)
// triple the BPF side emits. For AF_INET the shape is:
//
//	args[0]=fd(int32) args[1]=family(int32) args[2]=addr(uint32) args[3]=port(uint32)
//
// For AF_UNIX the third arg is a path string. For AF_PACKET we just fall back
// to a raw tag — the bridge only cares about routable peers for intent.
func decodeSockAddr(args []any) string {
	return decodeSockAddrAt(args, 1)
}

// decodeSockAddrAt is the indexed form. The security_socket_* LSM kprobes
// don't carry a leading fd (the kernel hands the kprobe a `struct socket *`
// instead), so their (family, addr, port) triple starts at args[0]. Both
// callers share the rendering logic.
func decodeSockAddrAt(args []any, familyIdx int) string {
	if len(args) <= familyIdx {
		return ""
	}
	family, ok := args[familyIdx].(int32)
	if !ok {
		return ""
	}
	switch family {
	case 1: // AF_UNIX
		if len(args) <= familyIdx+1 {
			return ""
		}
		return asString(args[familyIdx+1])
	case 2: // AF_INET
		if len(args) < familyIdx+3 {
			return ""
		}
		addr, aok := args[familyIdx+1].(uint32)
		port, pok := args[familyIdx+2].(uint32)
		if !aok || !pok {
			return ""
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d",
			byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24), port) // #nosec G115 -- byte packing uint32 IPv4 into 4 bytes
	}
	return ""
}

// capName returns the symbolic CAP_* name for a Linux capability number.
// Used by cap_capable to render ev.Resource so the baseline / contract layer
// builds an allow-list keyed on cap names instead of raw integers. Unknown
// numbers render as "CAP_<n>" so consumers can still group by id.
func capName(n int32) string {
	if name, ok := capNames[n]; ok {
		return name
	}
	return fmt.Sprintf("CAP_%d", n)
}

// capNames is keyed by the kernel's <linux/capability.h> cap-number assignment.
// Covers the full 0..40 range (CAP_LAST_CAP = 40 on 5.10; 41 on 6.x adds
// CAP_CHECKPOINT_RESTORE). Names match the userspace libcap convention so
// adapter output is directly readable as KubeArmor / AppArmor capability
// rule entries.
var capNames = map[int32]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
	32: "CAP_MAC_OVERRIDE",
	33: "CAP_MAC_ADMIN",
	34: "CAP_SYSLOG",
	35: "CAP_WAKE_ALARM",
	36: "CAP_BLOCK_SUSPEND",
	37: "CAP_AUDIT_READ",
	38: "CAP_PERFMON",
	39: "CAP_BPF",
	40: "CAP_CHECKPOINT_RESTORE",
}

// prctlOptionName maps a prctl option number to its symbolic name. Only the
// privilege-relevant subset is included — everything else returns "" so the
// mapper falls back to ev.Args without setting a Resource.
func prctlOptionName(opt int32) string {
	switch opt {
	case 4:
		return "PR_SET_DUMPABLE"
	case 8:
		return "PR_SET_KEEPCAPS"
	case 22:
		return "PR_SET_SECCOMP"
	case 23:
		return "PR_CAPBSET_READ"
	case 24:
		return "PR_CAPBSET_DROP"
	case 38:
		return "PR_SET_NO_NEW_PRIVS"
	case 39:
		return "PR_GET_NO_NEW_PRIVS"
	case 47:
		return "PR_CAP_AMBIENT"
	}
	return ""
}

// CLONE_NEW* bits — kernel exposes identical constants for both clone(2)
// flags and setns(2) nstype. Values mirror include/uapi/linux/sched.h.
const (
	cloneNewTime   uint64 = 0x00000080
	cloneNewNS     uint64 = 0x00020000
	cloneNewCgroup uint64 = 0x02000000
	cloneNewUTS    uint64 = 0x04000000
	cloneNewIPC    uint64 = 0x08000000
	cloneNewUser   uint64 = 0x10000000
	cloneNewPID    uint64 = 0x20000000
	cloneNewNet    uint64 = 0x40000000
)

// decodeCloneNSFlags returns a "|"-joined list of set CLONE_NEW* bits in
// canonical order (NS, UTS(), IPC(), USER(), PID(), NET(), CGROUP(), TIME()). Returns ""
// when no namespace bit is set — callers use the empty result to skip
// collectUidGidArgs appends the uid/gid values passed to the set{uid,gid}*
// family onto ev.Args using syscall-variant-specific names. Every variant's
// primary "new identity" ends up as "new_<uid|gid>" so downstream consumers
// (pipeline creds branch → history.RecordCred()) don't have to dispatch on
// the variant name. The kernel passes uid_t / gid_t as 32-bit values; a
// sentinel of uint32(-1) = 0xFFFFFFFF means "leave unchanged" for
// set(re|res)(u|g)id and is skipped.
//
// Shape per variant:
//
//	setuid(uid) → new: args[0]
//	setreuid(ruid, euid) → new: args[1] (euid) + ruid
//	setresuid(ruid, euid, suid) → new: args[1] (euid) + ruid, suid
//	setfsuid(fsuid) → new: args[0]
//
// and analogously for the gid variants. kind is "uid" or "gid".
func collectUidGidArgs(ev *types.SyscallEvent, variant string, args []any, kind string) {
	const unchanged = uint32(0xFFFFFFFF)
	appendID := func(name string, v any) (uint32, bool) {
		id, ok := asUint64(v)
		if !ok {
			return 0, false
		}
		u := uint32(id) // #nosec G115 -- narrowing BPF-decoded 64-bit ID, bounded by kernel namespace-id size
		if u == unchanged {
			// Preserve the wire value for tests that care, but skip new_*.
			ev.Args = append(ev.Args, types.SyscallArg{Name: name, Type: "uint32", Value: "unchanged"})
			return u, false
		}
		ev.Args = append(ev.Args, types.SyscallArg{Name: name, Type: "uint32", Value: fmt.Sprint(u)})
		return u, true
	}
	setNew := func(v uint32) {
		ev.Args = append(ev.Args, types.SyscallArg{Name: "new_" + kind, Type: "uint32", Value: fmt.Sprint(v)})
	}

	switch variant {
	case "setuid", "setgid", "setfsuid", "setfsgid":
		if len(args) >= 1 {
			if u, ok := appendID(kind, args[0]); ok {
				setNew(u)
			}
		}
	case "setreuid", "setregid":
		if len(args) >= 1 {
			appendID("r"+kind, args[0])
		}
		if len(args) >= 2 {
			if u, ok := appendID("e"+kind, args[1]); ok {
				setNew(u)
			}
		}
	case "setresuid", "setresgid":
		if len(args) >= 1 {
			appendID("r"+kind, args[0])
		}
		if len(args) >= 2 {
			if u, ok := appendID("e"+kind, args[1]); ok {
				setNew(u)
			}
		}
		if len(args) >= 3 {
			appendID("s"+kind, args[2])
		}
	}
}

// emitting the symbolic arg for plain thread-clones. Unknown bits above the
// namespace mask are ignored; this is decode-for-display, not audit.
func decodeCloneNSFlags(v uint64) string {
	var parts []string
	if v&cloneNewNS != 0 {
		parts = append(parts, "CLONE_NEWNS")
	}
	if v&cloneNewUTS != 0 {
		parts = append(parts, "CLONE_NEWUTS")
	}
	if v&cloneNewIPC != 0 {
		parts = append(parts, "CLONE_NEWIPC")
	}
	if v&cloneNewUser != 0 {
		parts = append(parts, "CLONE_NEWUSER")
	}
	if v&cloneNewPID != 0 {
		parts = append(parts, "CLONE_NEWPID")
	}
	if v&cloneNewNet != 0 {
		parts = append(parts, "CLONE_NEWNET")
	}
	if v&cloneNewCgroup != 0 {
		parts = append(parts, "CLONE_NEWCGROUP")
	}
	if v&cloneNewTime != 0 {
		parts = append(parts, "CLONE_NEWTIME")
	}
	return strings.Join(parts, "|")
}
