// SPDX-License-Identifier: Apache-2.0
//go:build linux

package hookprobe

import (
	"os"
	"testing"
)

// TestLiveProbe exercises the probe against the actual host kernel.
// Requires /sys/kernel/tracing to be mounted (typical on Linux). If not
// mounted, the test is skipped rather than failed.
func TestLiveProbe(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/tracing/events/syscalls"); err != nil {
		t.Skipf("tracing not mounted: %v", err)
	}
	p := DefaultProbe("live")
	r, err := p.Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if r.Kernel.Version == "" {
		t.Fatal("kernel version should be populated on live probe")
	}
	// On any modern Linux we expect execve tracepoint to exist.
	hc, ok := r.HookAvailable("syscall_tracepoint", "execve")
	if !ok || !hc.Available {
		t.Fatalf("execve tracepoint missing on live kernel; got %+v", hc)
	}
	t.Logf("live probe: kernel=%q lsms=%v btf=%v cgroup=%s hooks=%d helpers=%v",
		r.Kernel.Version, r.Kernel.LSMs, r.Kernel.HasBTF, r.Kernel.CgroupVer,
		len(r.Hooks), r.Helpers)
}
