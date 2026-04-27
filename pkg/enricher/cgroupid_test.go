// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestCgroupIDIndexResolves builds a fake cgroupv2 layout and verifies
// the indexer maps the resulting directory inode → relative path. Mirrors
// the real on-disk shape under /sys/fs/cgroup/kubepods.slice/... so a
// regression in the inode walker would surface here without needing root
// or a real cgroupv2 mount.
func TestCgroupIDIndexResolves(t *testing.T) {
	root := t.TempDir()
	cid := hex64("aa")
	relPath := filepath.Join("kubepods.slice", "kubepods-besteffort.slice",
		"kubepods-besteffort-podabc.slice", "cri-containerd-"+cid+".scope")
	full := filepath.Join(root, relPath)
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(full)
	if err != nil {
		t.Fatal(err)
	}
	wantInode := st.Sys().(*syscall.Stat_t).Ino

	idx := NewCgroupIDIndex(root)
	idx.Rescan()

	got, ok := idx.Lookup(wantInode)
	if !ok {
		t.Fatalf("expected inode %d in index, got miss", wantInode)
	}
	if got != relPath {
		t.Errorf("path = %q, want %q", got, relPath)
	}
}

// TestResolveByCgroupIDPodMetaPropagates builds a fake cgroup tree + a
// CRI cache entry and asserts ResolveByCgroupID stitches them: cgroup
// inode → cgroup path → containerID → CRIRecord → ContainerMeta with
// pod/namespace populated. This is the exact attribution path the
// pipeline's DNSAnswer handler relies on for cgroup_skb-emitted events.
func TestResolveByCgroupIDPodMetaPropagates(t *testing.T) {
	root := t.TempDir()
	cid := hex64("c1")
	relPath := filepath.Join("kubepods.slice",
		"kubepods-burstable-pod"+hex64("p1")+".slice",
		"cri-containerd-"+cid+".scope")
	if err := os.MkdirAll(filepath.Join(root, relPath), 0o755); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(root, relPath))
	inode := st.Sys().(*syscall.Stat_t).Ino

	e := NewEnricher(Options{
		NodeName:   "test-node",
		Cluster:    "test-cluster",
		Proc:       &ProcScanner{Root: t.TempDir()},
		CgroupRoot: root,
	})
	e.cri.Replace([]CRIRecord{{
		ContainerID:   cid,
		ContainerName: "ubuntu",
		PodName:       "ubuntu-1-abcdef",
		PodNamespace:  "default",
		Image:         "boanlab/ubuntu:latest",
		Labels:        map[string]string{"app": "ubuntu-1"},
	}})
	e.cgIDs.Rescan()

	meta := e.ResolveByCgroupID(inode)
	if meta.Pod != "ubuntu-1-abcdef" {
		t.Errorf("Pod=%q, want ubuntu-1-abcdef", meta.Pod)
	}
	if meta.Namespace != "default" {
		t.Errorf("Namespace=%q, want default", meta.Namespace)
	}
	if meta.ContainerID != cid {
		t.Errorf("ContainerID=%q, want %q", meta.ContainerID, cid)
	}
	if meta.NodeName != "test-node" || meta.Cluster != "test-cluster" {
		t.Errorf("identity stamp lost: %+v", meta)
	}
	if meta.Labels["app"] != "ubuntu-1" {
		t.Errorf("labels lost: %+v", meta.Labels)
	}
}

// TestResolveByCgroupIDZeroAndMiss covers the two short-circuits the
// pipeline relies on: cgroup_id=0 (BPF didn't populate the field, e.g.
// older object) returns zero meta with no rescan, and an unknown id
// triggers a rescan but still returns zero when nothing matches.
func TestResolveByCgroupIDZeroAndMiss(t *testing.T) {
	e := NewEnricher(Options{
		Proc:       &ProcScanner{Root: t.TempDir()},
		CgroupRoot: t.TempDir(),
	})
	if got := e.ResolveByCgroupID(0); got.ContainerID != "" || got.Pod != "" {
		t.Errorf("zero id should yield zero meta, got %+v", got)
	}
	if got := e.ResolveByCgroupID(999999); got.ContainerID != "" || got.Pod != "" {
		t.Errorf("miss should yield zero meta (or host-process meta), got %+v", got)
	}
}

// TestResolveByCgroupIDHostProcess: cgroup paths that don't match any
// container-runtime prefix (systemd unit, user slice) should return a
// meta with no ContainerID but Cluster/NodeName stamped — useful so
// downstream consumers can still see the event came from this node.
func TestResolveByCgroupIDHostProcess(t *testing.T) {
	root := t.TempDir()
	relPath := filepath.Join("system.slice", "sshd.service")
	if err := os.MkdirAll(filepath.Join(root, relPath), 0o755); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(root, relPath))
	inode := st.Sys().(*syscall.Stat_t).Ino

	e := NewEnricher(Options{
		NodeName:   "test-node",
		Cluster:    "test-cluster",
		Proc:       &ProcScanner{Root: t.TempDir()},
		CgroupRoot: root,
	})
	e.cgIDs.Rescan()

	meta := e.ResolveByCgroupID(inode)
	if meta.ContainerID != "" {
		t.Errorf("host-process cgroup should not yield a container ID, got %q", meta.ContainerID)
	}
	if meta.NodeName != "test-node" || meta.Cluster != "test-cluster" {
		t.Errorf("identity stamp missing on host-process meta: %+v", meta)
	}
}
