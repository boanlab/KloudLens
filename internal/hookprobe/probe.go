// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package caps implements Capability Discovery: probe the
// running kernel for syscall tracepoints, BPF-LSM hook availability,
// kprobe-capable symbols, and BPF helper support.
//
// This package relies strictly on read-only filesystem inspection —
// it does not attempt to load BPF programs. Dry-attach verification is
// left to the tracer package where the BPF objects actually live.
package hookprobe

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Probe is the pluggable surface against the host. Tests substitute an
// afero-style fake filesystem + plain string buffers.
type Probe struct {
	FS            fs.FS
	TraceRoot     string // default "sys/kernel/tracing"
	KallsymsPath  string // default "proc/kallsyms"
	AvailableFns  string // default "sys/kernel/tracing/available_filter_functions"
	LSMPath       string // default "sys/kernel/security/lsm"
	BTFPath       string // default "sys/kernel/btf/vmlinux"
	OSReleasePath string // default "etc/os-release"
	UnameVersion  string // set by Discover if left empty
	NodeID        string
}

// DefaultProbe returns a probe configured against the live rootfs.
func DefaultProbe(nodeID string) *Probe {
	return &Probe{
		FS:            os.DirFS("/"),
		TraceRoot:     "sys/kernel/tracing",
		KallsymsPath:  "proc/kallsyms",
		AvailableFns:  "sys/kernel/tracing/available_filter_functions",
		LSMPath:       "sys/kernel/security/lsm",
		BTFPath:       "sys/kernel/btf/vmlinux",
		OSReleasePath: "etc/os-release",
		NodeID:        nodeID,
	}
}

// Discover runs every probe and returns a CapabilityReport.
func (p *Probe) Discover() (*types.CapabilityReport, error) {
	report := &types.CapabilityReport{
		NodeID:  p.NodeID,
		Kernel:  p.kernelInfo(),
		Helpers: p.helpers(),
	}

	// Syscall tracepoints under TraceRoot/events/syscalls/sys_enter_<name>
	syscalls, err := p.listSyscallTracepoints()
	if err == nil {
		for _, name := range syscalls {
			report.Hooks = append(report.Hooks, types.HookCap{
				Kind: "syscall_tracepoint", Name: name, Available: true,
			})
		}
	}

	// LSM BPF hooks: presence of /sys/kernel/security/lsm containing "bpf".
	lsmNames := []string{
		"bprm_check_security", "file_open", "task_kill",
		"socket_connect", "inode_unlink", "sb_mount",
	}
	lsmAvailable, lsmReason := p.bpfLSMStatus()
	for _, name := range lsmNames {
		hc := types.HookCap{Kind: "lsm_bpf", Name: name, Available: lsmAvailable}
		if !lsmAvailable {
			hc.UnavailableReason = lsmReason
			hc.FallbackSuggestion = "kprobe:security_" + strings.TrimSuffix(name, "_security")
		}
		report.Hooks = append(report.Hooks, hc)
	}

	// kprobe-capable symbols: sample a curated list via
	// kallsyms/available_filter_functions. Symbols inlined by the kernel
	// (compiler choice; varies by build) are reported as unavailable —
	// the sensor still loads, the corresponding signal stream just stays
	// dark on that node.
	kprobeCandidates := []string{
		"security_bprm_check", "security_file_open", "security_task_kill",
		"security_path_chmod", "security_path_chown", "security_path_unlink",
		"security_path_rename", "security_path_link", "security_path_mkdir",
		"security_path_rmdir", "security_path_chroot", "filp_close",
		"cap_capable",
		"security_socket_connect", "security_socket_bind",
		"security_socket_sendmsg", "security_socket_recvmsg",
	}
	kprobeSet := p.kprobeSymbolSet(kprobeCandidates)
	for _, name := range kprobeCandidates {
		report.Hooks = append(report.Hooks, types.HookCap{
			Kind: "kprobe", Name: name, Available: kprobeSet[name],
			UnavailableReason: missingIfNot(kprobeSet[name], "not in kallsyms/available_filter_functions"),
		})
	}

	return report, nil
}

func missingIfNot(ok bool, reason string) string {
	if ok {
		return ""
	}
	return reason
}

func (p *Probe) kernelInfo() types.KernelInfo {
	info := types.KernelInfo{Version: p.UnameVersion}
	if info.Version == "" {
		if b, err := fs.ReadFile(p.FS, "proc/version"); err == nil {
			info.Version = strings.TrimSpace(string(b))
		}
	}
	if b, err := fs.ReadFile(p.FS, p.LSMPath); err == nil {
		lsmStr := strings.TrimSpace(string(b))
		info.LSMs = splitAndTrim(lsmStr, ',')
	}
	if _, err := fs.Stat(p.FS, p.BTFPath); err == nil {
		info.HasBTF = true
	}
	if _, err := fs.Stat(p.FS, "sys/fs/cgroup/cgroup.controllers"); err == nil {
		info.CgroupVer = "v2"
	} else if _, err := fs.Stat(p.FS, "sys/fs/cgroup/memory"); err == nil {
		info.CgroupVer = "v1"
	}
	if b, err := fs.ReadFile(p.FS, "sys/kernel/security/lockdown"); err == nil {
		s := strings.TrimSpace(string(b))
		// Parse "none [integrity] confidentiality" → "integrity"
		if i := strings.IndexByte(s, '['); i >= 0 {
			if j := strings.IndexByte(s[i:], ']'); j > 0 {
				info.Lockdown = s[i+1 : i+j]
			}
		}
	}
	return info
}

func (p *Probe) helpers() map[string]string {
	h := map[string]string{}
	// Presence of specific events/files is used as a proxy for helper availability.
	// A true dry-load would be needed for exactness, but this gives a reliable
	// static signal from /sys without needing CAP_BPF.
	if _, err := fs.Stat(p.FS, filepath.Join(p.TraceRoot, "events/syscalls")); err == nil {
		h["syscall_tracepoints"] = "yes"
	}
	// ringbuf: requires kernel 5.8+. We infer from kernel version string prefix.
	if kv := p.kernelVersionTuple(); kv[0] > 5 || (kv[0] == 5 && kv[1] >= 8) {
		h["ringbuf"] = "yes"
	} else {
		h["ringbuf"] = "no"
	}
	if kv := p.kernelVersionTuple(); kv[0] > 5 || (kv[0] == 5 && kv[1] >= 9) {
		h["bpf_d_path"] = "yes"
	} else {
		h["bpf_d_path"] = "no"
	}
	if kv := p.kernelVersionTuple(); kv[0] > 5 || (kv[0] == 5 && kv[1] >= 7) {
		h["bpf_lsm"] = "yes"
	} else {
		h["bpf_lsm"] = "no"
	}
	return h
}

// kernelVersionTuple returns (major, minor) parsed from /proc/version; [0,0] if unparseable.
func (p *Probe) kernelVersionTuple() [2]int {
	var out [2]int
	b, err := fs.ReadFile(p.FS, "proc/version")
	if err != nil || len(b) == 0 {
		return out
	}
	// "Linux version 6.17.0-20-generic ..." → 6.17
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return out
	}
	v := fields[2]
	if i := strings.IndexByte(v, '.'); i > 0 {
		major := parseIntDefault(v[:i], 0)
		rest := v[i+1:]
		j := strings.IndexAny(rest, ".-")
		var minor int
		if j > 0 {
			minor = parseIntDefault(rest[:j], 0)
		} else {
			minor = parseIntDefault(rest, 0)
		}
		out[0] = major
		out[1] = minor
	}
	return out
}

func parseIntDefault(s string, def int) int {
	n := 0
	if s == "" {
		return def
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

func splitAndTrim(s string, sep byte) []string {
	var out []string
	for _, p := range strings.Split(s, string([]byte{sep})) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (p *Probe) listSyscallTracepoints() ([]string, error) {
	entries, err := fs.ReadDir(p.FS, filepath.Join(p.TraceRoot, "events/syscalls"))
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n := e.Name()
		switch {
		case strings.HasPrefix(n, "sys_enter_"):
			set[strings.TrimPrefix(n, "sys_enter_")] = struct{}{}
		case strings.HasPrefix(n, "sys_exit_"):
			set[strings.TrimPrefix(n, "sys_exit_")] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	return out, nil
}

func (p *Probe) bpfLSMStatus() (bool, string) {
	b, err := fs.ReadFile(p.FS, p.LSMPath)
	if err != nil {
		return false, "LSM list not readable"
	}
	lsms := splitAndTrim(strings.TrimSpace(string(b)), ',')
	for _, l := range lsms {
		if l == "bpf" {
			return true, ""
		}
	}
	return false, "lsm=bpf boot param missing"
}

func (p *Probe) kprobeSymbolSet(candidates []string) map[string]bool {
	want := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		want[c] = false
	}
	// Prefer available_filter_functions — cheaper and explicitly lists probeable symbols.
	if f, err := p.FS.Open(p.AvailableFns); err == nil {
		scanSymbols(f, want)
		_ = f.Close()
	}
	if allFound(want) {
		return want
	}
	if f, err := p.FS.Open(p.KallsymsPath); err == nil {
		scanSymbols(f, want)
		_ = f.Close()
	}
	return want
}

func allFound(m map[string]bool) bool {
	for _, v := range m {
		if !v {
			return false
		}
	}
	return true
}

func scanSymbols(r fs.File, want map[string]bool) {
	bs := bufio.NewScanner(r)
	bs.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for bs.Scan() {
		line := bs.Text()
		// kallsyms format: "addr type name [module]"
		// available_filter_functions: "name" possibly with annotation
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[len(fields)-1]
		// strip module suffix "[module]"
		if strings.HasPrefix(name, "[") {
			if len(fields) >= 2 {
				name = fields[len(fields)-2]
			}
		}
		// kallsyms: third token is the function name
		if len(fields) >= 3 && len(fields[0]) >= 8 {
			name = fields[2]
		}
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
}
