// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

// dockerFakeSocket starts a miniature Docker Engine over a unix socket in
// t.TempDir and returns the "unix://..." endpoint. The server answers
// GET /containers/json with the supplied body; any other route returns 404.
func dockerFakeSocket(t *testing.T, body string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "unix://" + sock
}

func TestDockerClientSnapshotParsesResponse(t *testing.T) {
	body := `[
	 {
	 "Id": "abc123",
	 "Names": ["/api-server"],
	 "Image": "myregistry/api:1.2.3",
	 "State": "running",
	 "Labels": {"team": "platform"}
	 },
	 {
	 "Id": "k8s-managed",
	 "Names": ["/k8s_nginx_web-0_prod_abc_0"],
	 "Image": "nginx:1.27",
	 "State": "running",
	 "Labels": {
	 "io.kubernetes.pod.name": "web-0",
	 "io.kubernetes.pod.namespace": "prod",
	 "io.kubernetes.pod.uid": "abc-def"
	 }
	 },
	 {
	 "Id": "dead",
	 "Names": ["/gone"],
	 "Image": "alpine",
	 "State": "exited",
	 "Labels": {}
	 }
	]`
	endpoint := dockerFakeSocket(t, body)
	c := &DockerClient{Endpoint: endpoint}
	recs, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Non-running containers must be filtered.
	if len(recs) != 2 {
		t.Fatalf("want 2 running records, got %d: %+v", len(recs), recs)
	}
	if recs[0].ContainerID != "abc123" || recs[0].ContainerName != "api-server" ||
		recs[0].Image != "myregistry/api:1.2.3" {
		t.Errorf("record 0 = %+v", recs[0])
	}
	if recs[0].PodName != "" || recs[0].PodNamespace != "" {
		t.Errorf("record 0 must have no pod metadata, got %+v", recs[0])
	}
	if recs[1].PodName != "web-0" || recs[1].PodNamespace != "prod" || recs[1].PodUID != "abc-def" {
		t.Errorf("record 1 pod metadata = %+v", recs[1])
	}
}

func TestDockerClientMissingSocketReturnsUnavailable(t *testing.T) {
	c := &DockerClient{Endpoint: "unix:///tmp/kloudlens-nonexistent.sock"}
	_, err := c.Snapshot(context.Background())
	if err == nil {
		t.Fatal("expected error when socket is missing")
	}
	if !errors.Is(err, ErrDockerUnavailable) {
		t.Errorf("want ErrDockerUnavailable, got %v", err)
	}
}

func TestDockerClientRejectsUnknownScheme(t *testing.T) {
	c := &DockerClient{Endpoint: "ssh://docker.example"}
	_, err := c.Snapshot(context.Background())
	if err == nil {
		t.Fatal("expected error on unsupported scheme")
	}
}

// TestEnricherResolveViaDockerOnlyMode asserts the Options.Docker path is
// actually consulted when Options.CRI is nil. A resolver configured with
// Docker-only enrichment should populate Image / Container / Pod labels
// from the /containers/json response.
func TestEnricherResolveViaDockerOnlyMode(t *testing.T) {
	// The /proc scanner won't find our fake NS:containerID pair, so we
	// stub the NSMap directly. Start with no CRI and a Docker-only
	// endpoint.
	endpoint := dockerFakeSocket(t, `[
	 {
	 "Id": "cafe01",
	 "Names": ["/redis"],
	 "Image": "redis:7",
	 "State": "running",
	 "Labels": {"role": "cache"}
	 }
	]`)
	e := NewEnricher(Options{
		Docker:   &DockerClient{Endpoint: endpoint},
		NodeName: "node-a",
	})
	// Force a snapshot (no procs to scan); populates the CRI cache via
	// the docker branch in rescan.
	e.rescan(context.Background())
	// Seed the NS map so the lookup succeeds — normally ProcScanner does
	// this, but the test runs in a sandbox where /proc entries don't map
	// to "cafe01".
	e.ns.Replace(map[NSKey]RawEntry{
		{PidNS: 42, MntNS: 43}: {ContainerID: "cafe01"},
	})
	meta := e.Resolve(42, 43)
	if meta.ContainerID != "cafe01" {
		t.Errorf("ContainerID = %q, want cafe01", meta.ContainerID)
	}
	if meta.Container != "redis" || meta.Image != "redis:7" {
		t.Errorf("name/image = %+v", meta)
	}
	if meta.Labels["role"] != "cache" {
		t.Errorf("labels = %+v", meta.Labels)
	}
	if meta.NodeName != "node-a" {
		t.Errorf("NodeName = %q, want node-a", meta.NodeName)
	}
}
