// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package sensor

import (
	"fmt"
	"strconv"
	"strings"
)

// NSKey is the (pid_ns, mnt_ns) pair the BPF side keys the skip map on. The
// wire layout in `st_skip_ns_map` is `(uint64(pidNS)<<32) | uint64(mntNS)` —
// callers hand us the decoded fields and the loader does the composition.
type NSKey struct {
	PidNS uint32
	MntNS uint32
}

// Uint64 returns the exact BPF-map key BPF uses in should_monitor.
func (k NSKey) Uint64() uint64 { return uint64(k.PidNS)<<32 | uint64(k.MntNS) }

// LiveOptions configures the live BPF loader. Zero value: raw_syscalls
// disabled, no namespace filtering.
//
// The two ns lists are mutually exclusive: setting TargetNS puts the
// toggle map into "only monitor these" mode, setting ExceptNS keeps the
// default "monitor everything except these" mode. If both are set,
// TargetNS wins and ExceptNS is ignored.
type LiveOptions struct {
	// EnableRawSyscalls attaches the two `raw_syscalls` tracepoints. They
	// fire on every syscall system-wide, duplicate the targeted per-syscall
	// tracepoints, and are only useful for rare-syscall discovery — keep
	// them off unless explicitly needed.
	EnableRawSyscalls bool

	// TargetNS is the allow-list of namespace keys to monitor. When non-
	// empty, the BPF filter switches to "monitor only these keys" mode.
	TargetNS []NSKey

	// ExceptNS is the deny-list of namespace keys to skip. Only consulted
	// when TargetNS is empty.
	ExceptNS []NSKey

	// SkipPrograms names BPF programs (matching ProgramSpec keys, e.g.
	// "kl_dns_recvmsg_exit") that the loader will drop from the spec
	// before NewCollection. Provides a runtime escape hatch for kernel-
	// version-specific verifier rejections — production runs leave this
	// empty, and the e2e tests use it to keep the rest of the pipeline
	// working when a single program won't load on the developer kernel.
	SkipPrograms []string
}

// ParseNSList accepts a comma-separated list of `pidNS:mntNS` pairs (decimal
// uint32, no leading zeros required) and returns the decoded keys. Empty /
// whitespace-only input yields a nil slice so callers can pass through a
// missing flag value untouched.
//
// Example: "4026531835:4026531840,4026532123:4026532130"
func ParseNSList(s string) ([]NSKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]NSKey, 0, len(parts))
	for _, raw := range parts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		colon := strings.IndexByte(raw, ':')
		if colon <= 0 || colon == len(raw)-1 {
			return nil, fmt.Errorf("tracer: ns key %q: want pidNS:mntNS", raw)
		}
		pidNS, err := strconv.ParseUint(raw[:colon], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("tracer: ns key %q: pidNS: %w", raw, err)
		}
		mntNS, err := strconv.ParseUint(raw[colon+1:], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("tracer: ns key %q: mntNS: %w", raw, err)
		}
		out = append(out, NSKey{PidNS: uint32(pidNS), MntNS: uint32(mntNS)})
	}
	return out, nil
}

// Mode reports which filter mode LiveOptions will request from the BPF side.
// Callers and tests use this to reason about the toggle_map value without
// peeking at map contents.
func (o LiveOptions) Mode() string {
	if len(o.TargetNS) > 0 {
		return "target"
	}
	if len(o.ExceptNS) > 0 {
		return "except"
	}
	return "all"
}
