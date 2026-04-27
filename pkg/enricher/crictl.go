// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// CRIRecord is the flattened subset of `crictl ps -o json` + `crictl pods`
// that the enricher needs. One record per running container.
type CRIRecord struct {
	ContainerID   string
	ContainerName string
	Image         string
	PodName       string
	PodNamespace  string
	PodUID        string
	Labels        map[string]string
}

// CRIClient queries a node's CRI runtime via the crictl binary. Using crictl
// (instead of vendoring k8s.io/cri-api) keeps the daemon binary small and
// avoids the compatibility matrix of runtime.v1 proto revisions. The trade-off
// is a fork/exec per snapshot, which is fine for the low-frequency polling
// the enricher does (default 30 s).
//
// Zero-value CRIClient{} works: the default Binary is "crictl" and the
// default Endpoint is whatever the host's /etc/crictl.yaml dictates (so
// users who have already configured crictl don't need extra flags). Pass
// Endpoint="unix:///run/containerd/containerd.sock" explicitly to be safe
// on stock cluster installs.
type CRIClient struct {
	Binary   string        // defaults to "crictl"
	Endpoint string        // e.g. unix:///run/containerd/containerd.sock
	Timeout  time.Duration // per-invocation; defaults to 3 s
}

// ErrCRIUnavailable is returned when the crictl binary isn't on PATH or the
// runtime socket can't be reached. Callers treat it as a soft failure and
// stay in ContainerID-only enrichment mode.
var ErrCRIUnavailable = errors.New("enricher: crictl unavailable")

// Snapshot invokes `crictl ps -o json` and `crictl pods -o json`, joins them
// on podSandboxID, and returns one CRIRecord per running container. The
// returned slice is never partial: if either probe fails the whole call
// errors so the caller can keep the previous snapshot instead of half-
// populating the cache.
func (c *CRIClient) Snapshot(ctx context.Context) ([]CRIRecord, error) {
	bin := c.Binary
	if bin == "" {
		bin = "crictl"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, ErrCRIUnavailable
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	psOut, err := c.run(ctx, bin, "ps", "-o", "json")
	if err != nil {
		return nil, err
	}
	podsOut, err := c.run(ctx, bin, "pods", "-o", "json")
	if err != nil {
		return nil, err
	}
	return parseCRISnapshot(psOut, podsOut)
}

func (c *CRIClient) run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	a := args
	if c.Endpoint != "" {
		// Prepend --runtime-endpoint / --image-endpoint so the call is
		// self-contained and works even without /etc/crictl.yaml.
		a = append([]string{"--runtime-endpoint", c.Endpoint, "--image-endpoint", c.Endpoint}, args...)
	}
	cmd := exec.CommandContext(ctx, bin, a...) // #nosec G204 -- bin is a CLI/config-supplied crictl binary path; caller controls it
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// parseCRISnapshot is factored out so tests can feed canned JSON without
// needing crictl installed.
func parseCRISnapshot(psOut, podsOut []byte) ([]CRIRecord, error) {
	var ps struct {
		Containers []struct {
			ID           string                `json:"id"`
			PodSandboxID string                `json:"podSandboxId"`
			Metadata     struct{ Name string } `json:"metadata"`
			Image        struct {
				Image     string `json:"image"`
				UserImage string `json:"userSpecifiedImage"`
			} `json:"image"`
			ImageRef string            `json:"imageRef"`
			Labels   map[string]string `json:"labels"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(psOut, &ps); err != nil {
		return nil, err
	}
	var pods struct {
		Items []struct {
			ID       string `json:"id"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
				UID       string `json:"uid"`
			} `json:"metadata"`
			Labels map[string]string `json:"labels"`
		} `json:"items"`
	}
	if err := json.Unmarshal(podsOut, &pods); err != nil {
		return nil, err
	}
	podByID := make(map[string]int, len(pods.Items))
	for i, p := range pods.Items {
		podByID[p.ID] = i
	}
	out := make([]CRIRecord, 0, len(ps.Containers))
	for _, c := range ps.Containers {
		rec := CRIRecord{
			ContainerID:   c.ID,
			ContainerName: c.Metadata.Name,
			Image:         firstNonEmpty(c.Image.UserImage, c.Image.Image, c.ImageRef),
			Labels:        c.Labels,
		}
		if i, ok := podByID[c.PodSandboxID]; ok {
			p := pods.Items[i]
			rec.PodName = p.Metadata.Name
			rec.PodNamespace = p.Metadata.Namespace
			rec.PodUID = p.Metadata.UID
			// Merge pod-level labels (e.g. the "deployment"/"group" labels
			// from multiubuntu.yaml) without overwriting container labels.
			if rec.Labels == nil {
				rec.Labels = map[string]string{}
			}
			for k, v := range p.Labels {
				if _, exists := rec.Labels[k]; !exists {
					rec.Labels[k] = v
				}
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// NormalizePodUID strips dashes from a pod UID so it can be compared against
// the underscore-form UID embedded in cgroup slices ("pod<uid>.slice"). Both
// forms exist in the wild because systemd escapes '-' to '_' when making the
// slice name.
func NormalizePodUID(uid string) string {
	return strings.ReplaceAll(uid, "-", "_")
}
