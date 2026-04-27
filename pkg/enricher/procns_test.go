// SPDX-License-Identifier: Apache-2.0

package enricher

import (
	"os"
	"path/filepath"
	"testing"
)

// TestProcScannerFixture builds a fake /proc layout with two containers and
// a systemd user-slice process, and asserts Scan yields exactly the two
// container entries keyed by their (pidNS, mntNS) pairs.
func TestProcScannerFixture(t *testing.T) {
	root := t.TempDir()
	// Container A: cri-containerd under k8s besteffort pod. PIDs 100, 101.
	writePID(t, root, 100,
		"pid:[4026532001]", "mnt:[4026532002]",
		"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podaaaa_bbbb.slice/cri-containerd-"+hex64("a1")+".scope")
	writePID(t, root, 101,
		"pid:[4026532001]", "mnt:[4026532002]",
		"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podaaaa_bbbb.slice/cri-containerd-"+hex64("a1")+".scope")
	// Container B: different NS pair.
	writePID(t, root, 200,
		"pid:[4026532003]", "mnt:[4026532004]",
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podcccc_dddd.slice/cri-containerd-"+hex64("b2")+".scope")
	// User slice process (no container).
	writePID(t, root, 999,
		"pid:[4026531836]", "mnt:[4026531832]",
		"0::/user.slice/user-1000.slice/session-214.scope")
	// Non-numeric directory — should be ignored.
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	s := ProcScanner{Root: root}
	got, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(got), got)
	}
	keyA := NSKey{PidNS: 4026532001, MntNS: 4026532002}
	keyB := NSKey{PidNS: 4026532003, MntNS: 4026532004}
	a, okA := got[keyA]
	b, okB := got[keyB]
	if !okA || !okB {
		t.Fatalf("missing expected keys; got %+v", got)
	}
	if a.ContainerID != hex64("a1") || a.PodUID != "aaaa_bbbb" {
		t.Errorf("A mismatch: %+v", a)
	}
	if a.SamplePID != 100 { // earliest PID retained
		t.Errorf("A SamplePID: want 100, got %d", a.SamplePID)
	}
	if b.ContainerID != hex64("b2") || b.PodUID != "cccc_dddd" || b.SamplePID != 200 {
		t.Errorf("B mismatch: %+v", b)
	}
}

func TestNSMapHitMiss(t *testing.T) {
	m := NewNSMap()
	k := NSKey{PidNS: 7, MntNS: 8}
	if _, ok := m.Lookup(k); ok {
		t.Fatal("fresh map should miss")
	}
	m.Set(k, RawEntry{ContainerID: "cafef00d"})
	e, ok := m.Lookup(k)
	if !ok || e.ContainerID != "cafef00d" {
		t.Fatalf("want hit, got %+v ok=%v", e, ok)
	}
	m.Replace(nil)
	if _, ok := m.Lookup(k); ok {
		t.Fatal("post-replace should miss")
	}
	hits, misses, size := m.Stats()
	if hits != 1 || misses != 2 || size != 0 {
		t.Fatalf("stats: hits=%d misses=%d size=%d", hits, misses, size)
	}
}

func writePID(t *testing.T, root string, pid int, pidNS, mntNS, cgroup string) {
	t.Helper()
	pidDir := filepath.Join(root, itoa(pid))
	nsDir := filepath.Join(pidDir, "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// readlink resolves the ns entries — write symlinks whose targets are the
	// canonical "pid:[inode]" form the kernel exposes.
	if err := os.Symlink(pidNS, filepath.Join(nsDir, "pid")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mntNS, filepath.Join(nsDir, "mnt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroup+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// itoa avoids pulling strconv into the test-only path above; matches the
// style used elsewhere in this repo for tiny helpers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// hex64 returns a 64-character hex string seeded from the given suffix so
// test fixtures produce realistic containerd container IDs.
func hex64(seed string) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, 64)
	for i := range out {
		out[i] = alphabet[(i+int(seed[0]))%16]
	}
	// Embed the seed for visual debuggability at the tail.
	copy(out[len(out)-len(seed):], seed)
	return string(out)
}
