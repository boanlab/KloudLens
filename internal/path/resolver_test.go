// SPDX-License-Identifier: Apache-2.0

package path

import (
	"os"
	"strings"
	"testing"
)

type fakeFD struct {
	entries map[[2]int32]struct {
		path   string
		socket bool
		ok     bool
	}
}

func (f *fakeFD) put(pid, fd int32, path string, socket bool) {
	if f.entries == nil {
		f.entries = map[[2]int32]struct {
			path   string
			socket bool
			ok     bool
		}{}
	}
	f.entries[[2]int32{pid, fd}] = struct {
		path   string
		socket bool
		ok     bool
	}{path, socket, true}
}

func (f *fakeFD) Lookup(pid, fd int32) (string, bool, bool) {
	e, ok := f.entries[[2]int32{pid, fd}]
	if !ok {
		return "", false, false
	}
	return e.path, e.socket, true
}

type fakeCWD map[int32]struct{ cwd, root string }

func (f fakeCWD) Lookup(pid int32) (string, string, bool) {
	v, ok := f[pid]
	if !ok {
		return "", "", false
	}
	return v.cwd, v.root, true
}

type fakeMount map[uint32]string

func (f fakeMount) HostPath(mntns uint32, containerAbs string) (string, bool) {
	pref, ok := f[mntns]
	if !ok {
		return "", false
	}
	return pref + containerAbs, true
}

func TestResolveAbsolutePath(t *testing.T) {
	r := &Resolver{Mount: fakeMount{42: "/var/lib/docker/overlay2/abc"}}
	out := r.Resolve(Input{PID: 100, MntNS: 42, DirFD: AtFDCWD, RawPath: "/etc/passwd"})
	if out.PathUnresolved {
		t.Fatalf("unexpected unresolved: %+v", out)
	}
	if out.ContainerAbs != "/etc/passwd" || out.HostAbs != "/var/lib/docker/overlay2/abc/etc/passwd" {
		t.Fatalf("bad mapping: %+v", out)
	}
}

func TestResolveRelativeWithCWD(t *testing.T) {
	r := &Resolver{CWD: fakeCWD{100: {cwd: "/var/app", root: "/"}}}
	out := r.Resolve(Input{PID: 100, DirFD: AtFDCWD, RawPath: "logs/app.log"})
	if out.ContainerAbs != "/var/app/logs/app.log" {
		t.Fatalf("expected join, got %+v", out)
	}
}

func TestResolveCanonicalizesDotDot(t *testing.T) {
	r := &Resolver{CWD: fakeCWD{100: {cwd: "/var/app/subdir", root: "/"}}}
	out := r.Resolve(Input{PID: 100, DirFD: AtFDCWD, RawPath: "../../../etc/passwd"})
	if out.ContainerAbs != "/etc/passwd" {
		t.Fatalf("cleaning failed: %s", out.ContainerAbs)
	}
	// Three-deep cwd, two .. components should hop to /var.
	out = r.Resolve(Input{PID: 100, DirFD: AtFDCWD, RawPath: "../../etc/passwd"})
	if out.ContainerAbs != "/var/etc/passwd" {
		t.Fatalf("intermediate cleaning: %s", out.ContainerAbs)
	}
}

func TestResolveRelativeViaDirFD(t *testing.T) {
	fd := &fakeFD{}
	fd.put(100, 5, "/var/app/conf", false)
	r := &Resolver{FD: fd}
	out := r.Resolve(Input{PID: 100, DirFD: 5, RawPath: "db.yaml"})
	if out.ContainerAbs != "/var/app/conf/db.yaml" {
		t.Fatalf("got %+v", out)
	}
}

func TestResolveEmptyInput(t *testing.T) {
	r := &Resolver{}
	out := r.Resolve(Input{PID: 100, DirFD: AtFDCWD})
	if !out.PathUnresolved || out.UnresolvedReason != ReasonEmpty {
		t.Fatalf("expected empty unresolved: %+v", out)
	}
}

func TestResolveNullByteRejected(t *testing.T) {
	r := &Resolver{}
	out := r.Resolve(Input{PID: 100, DirFD: AtFDCWD, RawPath: "/etc/pass\x00wd"})
	if !out.PathUnresolved || out.UnresolvedReason != ReasonNullByte {
		t.Fatalf("expected null byte reject: %+v", out)
	}
	if out.DentryHint == "" {
		t.Fatal("hint should be populated on failure")
	}
}

func TestResolveFdTableMiss(t *testing.T) {
	r := &Resolver{FD: &fakeFD{}}
	out := r.Resolve(Input{PID: 100, DirFD: 99, RawPath: "rel"})
	if !out.PathUnresolved || out.UnresolvedReason != ReasonFdTableMiss {
		t.Fatalf("expected fd miss, got %+v", out)
	}
}

func TestResolveSocketFd(t *testing.T) {
	fd := &fakeFD{}
	fd.put(100, 3, "socket:[12345]", true)
	r := &Resolver{FD: fd}
	out := r.Resolve(Input{PID: 100, DirFD: 3, RawPath: ""})
	if out.PathUnresolved {
		t.Fatalf("socket fd shouldn't be unresolved: %+v", out)
	}
	if !strings.HasPrefix(out.ContainerAbs, "socket:[") {
		t.Fatalf("expected socket:[...], got %s", out.ContainerAbs)
	}
}

func TestResolveMaxLenTruncates(t *testing.T) {
	r := &Resolver{MaxLen: 10}
	out := r.Resolve(Input{PID: 100, DirFD: AtFDCWD, RawPath: "/very/long/path/that/exceeds/limit"})
	if !out.PathUnresolved || out.UnresolvedReason != ReasonPathTooLong {
		t.Fatalf("expected too-long: %+v", out)
	}
}

func TestTailHelper(t *testing.T) {
	if tail("abc", 10) != "abc" {
		t.Fatal("short preserved")
	}
	got := tail("abcdefghijk", 8)
	// 8 total = "..." + 5 chars.
	if got != "...ghijk" {
		t.Fatalf("got %s", got)
	}
}

// Live test — resolve /proc/self paths using the live resolver implementations.
func TestLiveProcResolverSelf(t *testing.T) {
	pid := int32(os.Getpid())
	cwdTable := NewProcCWD()
	fdTable := NewProcFDTable()

	cwd, root, ok := cwdTable.Lookup(pid)
	if !ok {
		t.Skip("/proc not mounted")
	}
	if cwd == "" || !strings.HasPrefix(cwd, "/") {
		t.Fatalf("unexpected cwd %q", cwd)
	}
	if root == "" {
		t.Fatal("expected root populated")
	}

	// Open an fd, ensure the FDTable recovers its path.
	f, err := os.CreateTemp("", "klpath-live-*")
	if err != nil {
		t.Fatalf("tempfile: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()); _ = f.Close() }()
	fd := int32(f.Fd())
	path, isSocket, ok := fdTable.Lookup(pid, fd)
	if !ok {
		t.Fatalf("fd %d lookup failed", fd)
	}
	if isSocket {
		t.Fatal("temp file should not be a socket")
	}
	// os.CreateTemp may prefix with /tmp; readlink should return the same path.
	if !strings.HasSuffix(path, f.Name()) {
		t.Fatalf("fd path mismatch: got=%s want suffix %s", path, f.Name())
	}

	// Socket fd: open a UDP socket via net.
	sockFD, err := openSocketFD()
	if err != nil {
		t.Skipf("cannot open socket: %v", err)
	}
	defer sockFD.Close()
	spath, isSocket, ok := fdTable.Lookup(pid, int32(sockFD.FD()))
	if !ok {
		t.Fatalf("socket fd lookup failed")
	}
	if !isSocket || !strings.HasPrefix(spath, "socket:[") {
		t.Fatalf("expected socket: prefix, got %s (isSocket=%v)", spath, isSocket)
	}

	// Full resolver path.
	r := &Resolver{FD: fdTable, CWD: cwdTable}
	out := r.Resolve(Input{PID: pid, DirFD: AtFDCWD, RawPath: "."})
	if out.PathUnresolved {
		t.Fatalf("self cwd should resolve: %+v", out)
	}
	if out.ContainerAbs != cwd {
		t.Fatalf("expected %s got %s", cwd, out.ContainerAbs)
	}
}
