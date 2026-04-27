// SPDX-License-Identifier: Apache-2.0

package hookprobe

import (
	"strings"
	"testing"
	"testing/fstest"
)

// buildFakeFS constructs a minimal fake rootfs that exercises every probe path.
func buildFakeFS() fstest.MapFS {
	fs := fstest.MapFS{
		"proc/version": &fstest.MapFile{
			Data: []byte("Linux version 6.17.0-20-generic (root@host) #1 SMP\n"),
		},
		"sys/kernel/security/lsm": &fstest.MapFile{
			Data: []byte("capability,lockdown,yama,apparmor,bpf"),
		},
		"sys/kernel/btf/vmlinux":                               &fstest.MapFile{Data: []byte{1, 2, 3}},
		"sys/fs/cgroup/cgroup.controllers":                     &fstest.MapFile{Data: []byte("cpu memory")},
		"sys/kernel/security/lockdown":                         &fstest.MapFile{Data: []byte("none [integrity] confidentiality")},
		"sys/kernel/tracing/events/syscalls":                   &fstest.MapFile{Mode: 0o755 | 1<<31},
		"sys/kernel/tracing/events/syscalls/sys_enter_execve":  &fstest.MapFile{Mode: 0o755 | 1<<31},
		"sys/kernel/tracing/events/syscalls/sys_exit_execve":   &fstest.MapFile{Mode: 0o755 | 1<<31},
		"sys/kernel/tracing/events/syscalls/sys_enter_openat":  &fstest.MapFile{Mode: 0o755 | 1<<31},
		"sys/kernel/tracing/events/syscalls/sys_exit_openat":   &fstest.MapFile{Mode: 0o755 | 1<<31},
		"sys/kernel/tracing/events/syscalls/sys_enter_connect": &fstest.MapFile{Mode: 0o755 | 1<<31},
		"sys/kernel/tracing/events/syscalls/sys_exit_connect":  &fstest.MapFile{Mode: 0o755 | 1<<31},
		"sys/kernel/tracing/available_filter_functions": &fstest.MapFile{
			Data: []byte("security_bprm_check\nsecurity_file_open\nfilp_close\nsome_other_symbol\n"),
		},
		"proc/kallsyms": &fstest.MapFile{
			Data: []byte("ffffffff81000000 T security_task_kill\nffffffff81000010 T security_path_chmod\n"),
		},
	}
	return fs
}

func TestDiscoverFakeKernel(t *testing.T) {
	p := &Probe{
		FS:            buildFakeFS(),
		TraceRoot:     "sys/kernel/tracing",
		KallsymsPath:  "proc/kallsyms",
		AvailableFns:  "sys/kernel/tracing/available_filter_functions",
		LSMPath:       "sys/kernel/security/lsm",
		BTFPath:       "sys/kernel/btf/vmlinux",
		OSReleasePath: "etc/os-release",
		NodeID:        "test-node",
	}
	r, err := p.Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if r.NodeID != "test-node" {
		t.Fatalf("node id: %s", r.NodeID)
	}
	if !r.Kernel.HasBTF {
		t.Fatal("BTF expected")
	}
	if r.Kernel.CgroupVer != "v2" {
		t.Fatalf("cgroup: %s", r.Kernel.CgroupVer)
	}
	if r.Kernel.Lockdown != "integrity" {
		t.Fatalf("lockdown: %s", r.Kernel.Lockdown)
	}
	if r.Helpers["ringbuf"] != "yes" || r.Helpers["bpf_d_path"] != "yes" || r.Helpers["bpf_lsm"] != "yes" {
		t.Fatalf("helpers: %+v", r.Helpers)
	}
	// syscall tracepoints
	for _, sc := range []string{"execve", "openat", "connect"} {
		hc, ok := r.HookAvailable("syscall_tracepoint", sc)
		if !ok || !hc.Available {
			t.Fatalf("expected syscall %s available, got %+v", sc, hc)
		}
	}
	// LSM bpf enabled → all LSM names available
	hc, _ := r.HookAvailable("lsm_bpf", "bprm_check_security")
	if !hc.Available {
		t.Fatal("bprm_check_security should be available under lsm=bpf")
	}
	// kprobe set mixed sources
	expected := map[string]bool{
		"security_bprm_check": true,
		"security_file_open":  true,
		"filp_close":          true,
		"security_task_kill":  true,
		"security_path_chmod": true,
	}
	for name, want := range expected {
		hc, _ := r.HookAvailable("kprobe", name)
		if hc.Available != want {
			t.Fatalf("kprobe %s: want %v got %+v", name, want, hc)
		}
	}
}

func TestLSMMissingMakesHooksUnavailable(t *testing.T) {
	fs := buildFakeFS()
	// remove bpf from LSM list
	fs["sys/kernel/security/lsm"] = &fstest.MapFile{Data: []byte("capability,yama,apparmor")}
	p := &Probe{
		FS: fs, TraceRoot: "sys/kernel/tracing", KallsymsPath: "proc/kallsyms",
		AvailableFns: "sys/kernel/tracing/available_filter_functions",
		LSMPath:      "sys/kernel/security/lsm", BTFPath: "sys/kernel/btf/vmlinux", NodeID: "n",
	}
	r, _ := p.Discover()
	hc, _ := r.HookAvailable("lsm_bpf", "file_open")
	if hc.Available {
		t.Fatal("lsm_bpf should be unavailable without bpf in lsm list")
	}
	if hc.UnavailableReason == "" {
		t.Fatal("reason should be set")
	}
	if !strings.Contains(hc.FallbackSuggestion, "kprobe:") {
		t.Fatalf("fallback suggestion missing: %s", hc.FallbackSuggestion)
	}
}

func TestKernelTooOldHelpers(t *testing.T) {
	fs := buildFakeFS()
	fs["proc/version"] = &fstest.MapFile{Data: []byte("Linux version 5.4.0-1-generic\n")}
	p := &Probe{FS: fs, TraceRoot: "sys/kernel/tracing", KallsymsPath: "proc/kallsyms",
		AvailableFns: "sys/kernel/tracing/available_filter_functions",
		LSMPath:      "sys/kernel/security/lsm", BTFPath: "sys/kernel/btf/vmlinux"}
	r, _ := p.Discover()
	if r.Helpers["ringbuf"] != "no" {
		t.Fatalf("ringbuf should be no on 5.4: %+v", r.Helpers)
	}
	if r.Helpers["bpf_d_path"] != "no" {
		t.Fatalf("bpf_d_path should be no on 5.4")
	}
	if r.Helpers["bpf_lsm"] != "no" {
		t.Fatalf("bpf_lsm should be no on 5.4")
	}
}
