// SPDX-License-Identifier: Apache-2.0

package policy

// Preset returns a built-in HookSubscription by name.
// Returns nil if the name is unknown.
func Preset(name string) *HookSubscription {
	switch name {
	case "security-minimal":
		return &HookSubscription{
			APIVersion: "kloudlens.io/v1",
			Kind:       "HookSubscription",
			Metadata:   Metadata{Name: "security-minimal"},
			Spec: Spec{
				Pairing: "enter_exit",
				Syscalls: HookList{Include: []string{
					"execve", "execveat", "setuid", "setgid", "ptrace",
				}},
				Priority: Priority{
					Critical: []string{"execve", "execveat", "ptrace", "setuid", "setgid"},
					Normal:   "*",
				},
				Graceful: Graceful{OnMissing: "skip"},
				Enrichment: Enrichment{
					Level:             "full",
					HistoryDepth:      defaultHistoryDepth,
					HistoryWindowSecs: defaultHistoryWindowSec,
				},
			},
		}
	case "security-standard":
		return &HookSubscription{
			APIVersion: "kloudlens.io/v1",
			Kind:       "HookSubscription",
			Metadata:   Metadata{Name: "security-standard"},
			Spec: Spec{
				Pairing: "enter_exit",
				Syscalls: HookList{Include: []string{
					"execve", "execveat", "openat", "openat2", "connect", "accept", "accept4",
					"ptrace", "setuid", "setgid", "capset", "unshare", "setns",
					"chmod", "fchmod", "fchmodat", "mount", "umount2",
				}},
				LSM: HookList{Include: []string{
					"bprm_check_security", "file_open", "task_kill", "socket_connect",
				}},
				Decode: DecodeOpts{ResolvePath: true, ResolveFd: true, DumpArgv: "truncate(256)"},
				Sampling: map[string]string{
					"openat": "1/10",
				},
				Priority: Priority{
					Critical: []string{
						"execve", "execveat", "ptrace", "connect", "setuid", "capset",
						"bprm_check_security",
					},
					Normal: "*",
				},
				Graceful: Graceful{OnMissing: "fallback", Fallback: map[string]string{
					"bprm_check_security": "kprobe:security_bprm_check",
					"file_open":           "kprobe:security_file_open",
					"openat2":             "syscall_tracepoint:openat",
				}},
				Enrichment: Enrichment{
					Level:             "full",
					HistoryDepth:      defaultHistoryDepth,
					HistoryWindowSecs: defaultHistoryWindowSec,
					Correlations: []string{
						"file_written_then_executed",
						"connect_after_dns",
						"exec_after_chmod_x",
					},
				},
			},
		}
	case "forensics-full":
		// Closest to "everything we know about". Kernel may reject if not all supported.
		return &HookSubscription{
			APIVersion: "kloudlens.io/v1",
			Kind:       "HookSubscription",
			Metadata:   Metadata{Name: "forensics-full"},
			Spec: Spec{
				Pairing: "enter_exit",
				Syscalls: HookList{Include: []string{
					"execve", "execveat", "clone", "clone3", "openat", "openat2", "open",
					"close", "read", "write", "connect", "accept", "accept4", "bind",
					"listen", "socket", "sendto", "recvfrom", "ptrace", "setuid", "setgid",
					"setreuid", "setregid", "capset", "unshare", "setns", "mount", "umount2",
					"chroot", "chmod", "fchmod", "fchmodat", "unlink", "unlinkat",
					"rename", "renameat", "renameat2", "link", "linkat", "symlink",
					"symlinkat", "mkdir", "mkdirat", "rmdir",
				}},
				LSM: HookList{Include: []string{
					"bprm_check_security", "file_open", "task_kill", "socket_connect",
					"inode_unlink", "sb_mount",
				}},
				Decode: DecodeOpts{ResolvePath: true, ResolveFd: true, DumpArgv: "truncate(1024)"},
				Priority: Priority{
					Critical: []string{"execve", "execveat", "ptrace", "connect", "setuid", "capset", "mount"},
					Normal:   "*",
				},
				Graceful: Graceful{OnMissing: "skip"},
				Enrichment: Enrichment{
					Level:             "full",
					HistoryDepth:      64,
					HistoryWindowSecs: 120,
					Correlations: []string{
						"file_written_then_executed",
						"connect_after_dns",
						"exec_after_chmod_x",
						"read_sensitive_before_send",
						"privilege_escalation_window",
					},
				},
			},
		}
	case "network-only":
		return &HookSubscription{
			APIVersion: "kloudlens.io/v1",
			Kind:       "HookSubscription",
			Metadata:   Metadata{Name: "network-only"},
			Spec: Spec{
				Pairing: "enter_exit",
				Syscalls: HookList{Include: []string{
					"socket", "bind", "connect", "accept", "accept4", "listen", "sendto", "recvfrom",
				}},
				LSM:      HookList{Include: []string{"socket_connect"}},
				Priority: Priority{Critical: []string{"connect", "accept", "accept4"}, Normal: "*"},
				Graceful: Graceful{OnMissing: "skip"},
				Enrichment: Enrichment{
					Level:             "minimal",
					HistoryDepth:      8,
					HistoryWindowSecs: 15,
				},
			},
		}
	}
	return nil
}

// PresetNames returns all available preset names for enumeration.
func PresetNames() []string {
	return []string{"security-minimal", "security-standard", "forensics-full", "network-only"}
}
