// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSeverityRoundTrip(t *testing.T) {
	cases := []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical, SeverityUnknown}
	for _, sv := range cases {
		got := SeverityFromString(sv.String())
		if got != sv {
			t.Fatalf("roundtrip %s: got %s", sv, got)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityHigh.AtLeast(SeverityMedium) {
		t.Fatal("high should meet medium threshold")
	}
	if SeverityLow.AtLeast(SeverityMedium) {
		t.Fatal("low should not meet medium threshold")
	}
}

func TestSyscallEventJSONOmitEmpty(t *testing.T) {
	e := SyscallEvent{
		EventID:     "abc",
		SyscallID:   59,
		SyscallName: "execve",
		Meta: ContainerMeta{
			Namespace: "default",
			Pod:       "hello",
		},
	}
	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// Fields not set should be omitted to keep wire payload small.
	for _, want := range []string{`"event_id":"abc"`, `"syscall_id":59`, `"syscall_name":"execve"`, `"namespace":"default"`, `"pod":"hello"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
	for _, unwanted := range []string{`"comm"`, `"exe_path"`, `"retcode"`, `"labels"`, `"history"`} {
		if strings.Contains(s, unwanted) {
			t.Fatalf("unexpected %s in %s", unwanted, s)
		}
	}
}

func TestResolvedPathUnresolvedShape(t *testing.T) {
	rp := ResolvedPath{
		PathUnresolved:   true,
		UnresolvedReason: "fd_table_miss",
		DentryHint:       "...passwd",
	}
	b, _ := json.Marshal(&rp)
	s := string(b)
	if !strings.Contains(s, `"path_unresolved":true`) || !strings.Contains(s, `"unresolved_reason":"fd_table_miss"`) {
		t.Fatalf("bad shape: %s", s)
	}
}

func TestCapabilityReportHookAvailable(t *testing.T) {
	r := &CapabilityReport{
		Hooks: []HookCap{
			{Kind: "syscall_tracepoint", Name: "execve", Available: true},
			{Kind: "lsm_bpf", Name: "file_open", Available: false, UnavailableReason: "lsm=bpf missing"},
		},
	}
	if _, ok := r.HookAvailable("syscall_tracepoint", "execve"); !ok {
		t.Fatal("expected execve")
	}
	if hc, ok := r.HookAvailable("lsm_bpf", "file_open"); !ok || hc.Available {
		t.Fatalf("file_open lookup wrong: %+v", hc)
	}
	if _, ok := r.HookAvailable("kprobe", "missing"); ok {
		t.Fatal("missing hook should not match")
	}
}
