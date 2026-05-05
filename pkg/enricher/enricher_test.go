// SPDX-License-Identifier: Apache-2.0

package enricher

import (
	"context"
	"testing"

	"github.com/boanlab/kloudlens/pkg/types"
)

// TestEnricherResolveWithCRI plumbs a fake procfs + a pre-populated CRI cache
// through Enricher.Resolve and asserts the resulting ContainerMeta carries
// pod/namespace/container/label data end-to-end.
func TestEnricherResolveWithCRI(t *testing.T) {
	root := t.TempDir()
	writePID(t, root, 100,
		"pid:[4026532001]", "mnt:[4026532002]",
		"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podaaaa.slice/cri-containerd-"+hex64("a1")+".scope")

	e := NewEnricher(Options{
		NodeName: "omen",
		Cluster:  "lab-0",
		Proc:     &ProcScanner{Root: root},
	})
	// Seed the CRI cache directly; we don't need a real crictl here.
	e.cri.Replace([]CRIRecord{
		{
			ContainerID:   hex64("a1"),
			ContainerName: "ubuntu-1-container",
			Image:         "boanlab/ubuntu-with-utils:0.1",
			PodName:       "ubuntu-1-abc",
			PodNamespace:  "multiubuntu",
			PodUID:        "aa-aa",
			Labels:        map[string]string{"deployment": "ubuntu-1", "group": "group-1"},
		},
	})
	e.Rescan(context.Background())

	got := e.Resolve(4026532001, 4026532002)
	if got.Pod != "ubuntu-1-abc" || got.Namespace != "multiubuntu" {
		t.Fatalf("pod/ns: %+v", got)
	}
	if got.Container != "ubuntu-1-container" || got.ContainerID != hex64("a1") {
		t.Fatalf("container: %+v", got)
	}
	if got.Image != "boanlab/ubuntu-with-utils:0.1" {
		t.Fatalf("image: %q", got.Image)
	}
	if got.NodeName != "omen" || got.Cluster != "lab-0" {
		t.Fatalf("identity stamp: %+v", got)
	}
	if got.Labels["deployment"] != "ubuntu-1" {
		t.Fatalf("labels: %+v", got.Labels)
	}
}

// TestEnricherResolveMissKeepsNS covers the bridge contract: a miss returns
// a Meta carrying only the NS pair so downstream code can still correlate.
func TestEnricherResolveMissKeepsNS(t *testing.T) {
	e := NewEnricher(Options{Proc: &ProcScanner{Root: t.TempDir()}})
	got := e.Resolve(4026532900, 4026532901)
	if got.ContainerID != "" || got.Pod != "" {
		t.Fatalf("unexpected enrichment: %+v", got)
	}
	if got.PidNS != 4026532900 || got.MntNS != 4026532901 {
		t.Fatalf("NS not preserved on miss: %+v", got)
	}
}

// TestEnricherResolveMissStampsNodeIdentity: even when the NS pair is
// unknown (host process, fresh container, non-k8s host), the node-side
// identity (Cluster + NodeName) MUST land on the returned meta so the
// operator can attribute the event to a node. Regression guard for the
// gap that left ~half of NetworkExchange/FileRead events without
// cluster/node columns.
func TestEnricherResolveMissStampsNodeIdentity(t *testing.T) {
	e := NewEnricher(Options{
		Proc:     &ProcScanner{Root: t.TempDir()},
		Cluster:  "test-cluster",
		NodeName: "node-a",
	})
	got := e.Resolve(4026532800, 4026532801)
	if got.Cluster != "test-cluster" || got.NodeName != "node-a" {
		t.Fatalf("miss should stamp node identity, got %+v", got)
	}
	if got.ContainerID != "" || got.Pod != "" {
		t.Fatalf("miss should not invent container/pod fields: %+v", got)
	}
}

// TestEnricherResolveHostProcessZero asserts the short-circuit for NS=(0,0)
// which represents a malformed wire frame / a truly host-rooted process.
func TestEnricherResolveHostProcessZero(t *testing.T) {
	e := NewEnricher(Options{})
	got := e.Resolve(0, 0)
	if got.PidNS != 0 || got.MntNS != 0 || got.ContainerID != "" ||
		got.Pod != "" || got.Container != "" || got.Namespace != "" ||
		got.Image != "" || got.NodeName != "" || got.Cluster != "" || got.Labels != nil {
		t.Fatalf("want zero-value meta for host process, got %+v", got)
	}
	_ = types.ContainerMeta{}
}

// TestEnricherResolveMissIsHotPathSafe asserts the v0.1.5 contract: a
// cache miss must NOT walk /proc on the Resolve hot path. The miss
// returns partial meta (cluster + node + raw NS); the next periodic
// Rescan picks up the container, after which Resolve returns full meta.
func TestEnricherResolveMissIsHotPathSafe(t *testing.T) {
	root := t.TempDir()
	e := NewEnricher(Options{Proc: &ProcScanner{Root: root}})
	e.Rescan(context.Background()) // empty snapshot

	// New container appears AFTER the initial scan.
	writePID(t, root, 200,
		"pid:[4026532011]", "mnt:[4026532012]",
		"0::/kubepods.slice/cri-containerd-"+hex64("c3")+".scope")

	// First Resolve is a miss — must not trigger a scan, must return
	// partial meta with only NS values stamped.
	got := e.Resolve(4026532011, 4026532012)
	if got.ContainerID != "" {
		t.Fatalf("Resolve must not synchronously scan on miss; got ContainerID=%q", got.ContainerID)
	}
	if got.PidNS != 4026532011 || got.MntNS != 4026532012 {
		t.Fatalf("miss should preserve NS pair: %+v", got)
	}

	// After a periodic rescan, the same lookup returns full meta.
	e.Rescan(context.Background())
	got = e.Resolve(4026532011, 4026532012)
	if got.ContainerID != hex64("c3") {
		t.Fatalf("rescan didn't pick up new container: %+v", got)
	}
}
