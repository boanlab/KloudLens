// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package bpf2frame

import (
	"testing"

	"github.com/boanlab/kloudlens/internal/syscalls"
)

// capName resolves a numeric Linux capability to its CAP_* symbol so the
// baseline / contract layer can build allow-lists keyed on names rather than
// raw ints. Unknown ids must still render deterministically as "CAP_<n>" so
// kernel additions (e.g. the 5.x → 6.x CAP_LAST_CAP creep) keep grouping
// under a stable prefix.
func TestCapName(t *testing.T) {
	cases := []struct {
		in   int32
		want string
	}{
		{0, "CAP_CHOWN"},
		{7, "CAP_SETUID"},
		{12, "CAP_NET_ADMIN"},
		{21, "CAP_SYS_ADMIN"},
		{38, "CAP_PERFMON"},
		{39, "CAP_BPF"},
		{40, "CAP_CHECKPOINT_RESTORE"},
		{41, "CAP_41"},   // future — kernel adds beyond table
		{-1, "CAP_-1"},   // sentinel
		{255, "CAP_255"}, // wildly out of range
	}
	for _, c := range cases {
		if got := capName(c.in); got != c.want {
			t.Errorf("capName(%d)=%q want %q", c.in, got, c.want)
		}
	}
}

// prctlOptionName covers the privilege-relevant prctl options the AppArmor /
// PodSecurity adapters care about. Anything outside this curated set must
// return "" so the mapper falls through to ev.Args without setting Resource.
func TestPrctlOptionName(t *testing.T) {
	known := map[int32]string{
		4:  "PR_SET_DUMPABLE",
		8:  "PR_SET_KEEPCAPS",
		22: "PR_SET_SECCOMP",
		23: "PR_CAPBSET_READ",
		24: "PR_CAPBSET_DROP",
		38: "PR_SET_NO_NEW_PRIVS",
		39: "PR_GET_NO_NEW_PRIVS",
		47: "PR_CAP_AMBIENT",
	}
	for opt, want := range known {
		if got := prctlOptionName(opt); got != want {
			t.Errorf("prctlOptionName(%d)=%q want %q", opt, got, want)
		}
	}
	// Anything else must be empty so the mapper leaves Resource unset and
	// the option just lands in ev.Args as the raw int.
	for _, unknown := range []int32{0, 1, 5, 9, 26, 100, -1} {
		if got := prctlOptionName(unknown); got != "" {
			t.Errorf("prctlOptionName(%d)=%q, want empty", unknown, got)
		}
	}
}

// TestMapCapCapable wires capName into Map(cap_capable, ...) so the cap
// number arrives as both the named arg and as ev.Resource. Without this
// test, a regression in Map's arg ordering or in capName's lookup table
// would silently break BPF capability-rule generation.
func TestMapCapCapable(t *testing.T) {
	e := Event{HostPID: 7, SyscallID: syscalls.SysCapCapable}
	args := []any{
		int32(12),       // CAP_NET_ADMIN
		uint64(0),       // opts
		"/usr/bin/curl", // source (always last)
	}
	se := Map(e, args)
	if se.Category != "creds" || se.Operation != "cap_capable" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	if se.Resource != "CAP_NET_ADMIN" {
		t.Errorf("Resource=%q want CAP_NET_ADMIN (capName lookup broken?)", se.Resource)
	}
	var sawCap, sawOpts bool
	for _, a := range se.Args {
		if a.Name == "cap" && a.Value == "12" {
			sawCap = true
		}
		if a.Name == "opts" {
			sawOpts = true
		}
	}
	if !sawCap || !sawOpts {
		t.Errorf("expected cap+opts args, got %+v", se.Args)
	}
}

// TestMapCapCapableUnknownNumber covers the CAP_<n> fallback for cap ids
// the mapper's static table doesn't carry. Operators upgrading to a kernel
// that introduces a new capability should still see *some* identifier in
// their ev.Resource; "" would be a regression.
func TestMapCapCapableUnknownNumber(t *testing.T) {
	e := Event{SyscallID: syscalls.SysCapCapable}
	args := []any{int32(99), uint64(0), "/sbin/init"}
	se := Map(e, args)
	if se.Resource != "CAP_99" {
		t.Errorf("Resource=%q, want CAP_99", se.Resource)
	}
}

// TestMapPrctlKnownOption: 38 = PR_SET_NO_NEW_PRIVS. Mapper promotes the
// option as ev.Resource so seccomp / PodSecurity adapters can dedupe by
// the symbolic name.
func TestMapPrctlKnownOption(t *testing.T) {
	e := Event{HostPID: 1, SyscallID: 157} // 157 = prctl on amd64
	args := []any{int32(38), uint64(1), "/usr/bin/runc"}
	se := Map(e, args)
	if se.Category != "process" || se.Operation != "prctl" {
		t.Fatalf("cat/op: %q/%q", se.Category, se.Operation)
	}
	if se.Resource != "PR_SET_NO_NEW_PRIVS" {
		t.Errorf("Resource=%q, want PR_SET_NO_NEW_PRIVS", se.Resource)
	}
	var optSeen, arg2Seen bool
	for _, a := range se.Args {
		if a.Name == "option" && a.Value == "38" {
			optSeen = true
		}
		if a.Name == "arg2" && a.Value == "1" {
			arg2Seen = true
		}
	}
	if !optSeen || !arg2Seen {
		t.Errorf("missing option/arg2 args: %+v", se.Args)
	}
}

// TestMapPrctlUnknownOption: option 99 is outside the curated symbol set,
// so the mapper must leave Resource empty (forcing baseline rules to key
// on the raw int rather than synthesizing a fake name).
func TestMapPrctlUnknownOption(t *testing.T) {
	e := Event{SyscallID: 157}
	args := []any{int32(99), uint64(0), "/sbin/init"}
	se := Map(e, args)
	if se.Resource != "" {
		t.Errorf("Resource=%q, want empty for unknown prctl option", se.Resource)
	}
	var optSeen bool
	for _, a := range se.Args {
		if a.Name == "option" && a.Value == "99" {
			optSeen = true
		}
	}
	if !optSeen {
		t.Errorf("option arg missing: %+v", se.Args)
	}
}
