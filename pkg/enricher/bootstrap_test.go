// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Builds a minimal /proc-like tree with one containerized PID and one host
// PID, for Bootstrap + BirthNotifier tests.
func fakeProcTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mkPID := func(pid string, pidNS, mntNS string, cgroup string) {
		nsDir := filepath.Join(root, pid, "ns")
		if err := os.MkdirAll(nsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("pid:["+pidNS+"]", filepath.Join(nsDir, "pid")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("mnt:["+mntNS+"]", filepath.Join(nsDir, "mnt")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Container PID: kubepods cgroup with a 64-char containerd ID.
	cid := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	mkPID("1234", "4026531100", "4026531200",
		"0::/kubepods.slice/kubepods-pod11111111_2222_3333_4444_555555555555.slice/cri-containerd-"+cid+".scope\n")
	// Host PID with no container cgroup — must be skipped.
	mkPID("1", "4026531836", "4026531840", "0::/init.scope\n")
	return root
}

func TestBootstrapPopulatesNSMap(t *testing.T) {
	root := fakeProcTree(t)
	e := NewEnricher(Options{Proc: &ProcScanner{Root: root}, NodeName: "n1"})
	if err := e.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	meta := e.Resolve(4026531100, 4026531200)
	if meta.ContainerID == "" {
		t.Fatalf("expected container meta post-bootstrap, got %+v", meta)
	}
	if meta.NodeName != "n1" {
		t.Errorf("NodeName not stamped: %+v", meta)
	}
}

func TestBirthNotifierDebouncesBursts(t *testing.T) {
	root := fakeProcTree(t)
	e := NewEnricher(Options{Proc: &ProcScanner{Root: root}})
	// Prime so the notifier's first call counts as "immediate".
	if err := e.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	bn := NewBirthNotifier(e, 50*time.Millisecond)
	// Override clock to deterministic advance. atomic.Int64 so the deferred
	// goroutine's closure read races cleanly with the test-goroutine writes.
	var nowNS atomic.Int64
	bn.now = func() time.Time { return time.Unix(0, nowNS.Load()) }

	// Burst of notifications within the debounce window.
	bn.Notify(context.Background()) // t=0: immediate scan
	first := bn.LastScanNS()
	nowNS.Store(int64(10 * time.Millisecond))
	bn.Notify(context.Background()) // deferred
	nowNS.Store(int64(20 * time.Millisecond))
	bn.Notify(context.Background()) // coalesced into same deferred

	// Advance real time past the debounce window so the deferred fires.
	time.Sleep(120 * time.Millisecond)
	if got := bn.LastScanNS(); got == first {
		t.Fatalf("deferred scan never fired: lastScanNS unchanged at %d", got)
	}
}

func TestBootstrapIdempotent(t *testing.T) {
	root := fakeProcTree(t)
	e := NewEnricher(Options{Proc: &ProcScanner{Root: root}})
	for i := 0; i < 3; i++ {
		if err := e.Bootstrap(context.Background()); err != nil {
			t.Fatalf("bootstrap[%d]: %v", i, err)
		}
	}
	if s := e.Stats(); s.NSSize == 0 {
		t.Fatalf("NSSize=0 after repeated bootstraps: %+v", s)
	}
}
