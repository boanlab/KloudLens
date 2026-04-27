// SPDX-License-Identifier: Apache-2.0

package enricher

import (
	"testing"
)

// TestParseCRISnapshot covers the join between `crictl ps` (containers) and
// `crictl pods` (sandboxes), including user-label merge from the pod side
// (e.g. `deployment`, `group`) — which is where multiubuntu's intent-level
// grouping labels live.
func TestParseCRISnapshot(t *testing.T) {
	ps := `{
	 "containers": [
	 {"id":"aaa111","podSandboxId":"sb-1","metadata":{"name":"ubuntu-1-container"},
	 "image":{"image":"sha256:xxx","userSpecifiedImage":"boanlab/ubuntu-with-utils:0.1"},
	 "imageRef":"sha256:xxx",
	 "labels":{"io.kubernetes.pod.name":"ubuntu-1-abc","io.kubernetes.pod.namespace":"multiubuntu","io.kubernetes.container.name":"ubuntu-1-container"}},
	 {"id":"bbb222","podSandboxId":"sb-2","metadata":{"name":"hostnet"},
	 "image":{"image":"sha256:yyy"},
	 "imageRef":"sha256:yyy",
	 "labels":{}}
	 ]
	}`
	pods := `{
	 "items": [
	 {"id":"sb-1","metadata":{"name":"ubuntu-1-abc","namespace":"multiubuntu","uid":"aa-bb"},
	 "labels":{"deployment":"ubuntu-1","group":"group-1","container":"ubuntu-1"}},
	 {"id":"sb-2","metadata":{"name":"hostnet","namespace":"default","uid":"cc-dd"},
	 "labels":{"app":"hostnet"}}
	 ]
	}`

	got, err := parseCRISnapshot([]byte(ps), []byte(pods))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}
	a := got[0]
	if a.ContainerID != "aaa111" || a.ContainerName != "ubuntu-1-container" {
		t.Errorf("container fields: %+v", a)
	}
	if a.PodName != "ubuntu-1-abc" || a.PodNamespace != "multiubuntu" || a.PodUID != "aa-bb" {
		t.Errorf("pod fields: %+v", a)
	}
	if a.Image != "boanlab/ubuntu-with-utils:0.1" {
		t.Errorf("image preference (userSpecified wins): %q", a.Image)
	}
	if a.Labels["deployment"] != "ubuntu-1" || a.Labels["group"] != "group-1" {
		t.Errorf("pod label merge missing: %+v", a.Labels)
	}
	if a.Labels["io.kubernetes.container.name"] != "ubuntu-1-container" {
		t.Errorf("container label preserved: %+v", a.Labels)
	}

	b := got[1]
	if b.PodName != "hostnet" || b.Image != "sha256:yyy" {
		t.Errorf("fallback image + pod join: %+v", b)
	}
}

// TestParseCRISnapshotMissingPods asserts that a container with no matching
// sandbox (race between ps and pods, or a detached container) still returns
// partial data so the resolver can expose at least a container ID / image.
func TestParseCRISnapshotMissingPods(t *testing.T) {
	ps := `{"containers":[{"id":"zzz","podSandboxId":"gone","metadata":{"name":"detached"},"image":{"image":"img"},"imageRef":"img"}]}`
	pods := `{"items":[]}`
	got, err := parseCRISnapshot([]byte(ps), []byte(pods))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || got[0].PodName != "" || got[0].ContainerID != "zzz" {
		t.Fatalf("graceful degrade: %+v", got)
	}
}

func TestNormalizePodUID(t *testing.T) {
	if got := NormalizePodUID("aa-bb-cc"); got != "aa_bb_cc" {
		t.Fatalf("normalize: %q", got)
	}
}
