// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package enricher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DockerClient queries the Docker Engine API over a unix (or tcp) socket.
// It is the standalone-Docker counterpart to CRIClient; on hosts that run
// neither Kubernetes nor a CRI-compatible runtime, this is the way the
// enricher gets container metadata.
//
// Only GET /containers/json is used — one request per rescan returns the
// full running set. Docker Engine ships the endpoint on every modern
// version; no shell-out to the docker CLI is required. Zero-value
// DockerClient{} works: the default Endpoint is the standard unix socket.
//
// Kubernetes pod context is only surfaced when the container carries the
// io.kubernetes.pod.{name,namespace,uid} labels (the historical dockershim
// tag). Pure Docker workloads leave PodName / PodNamespace empty; the
// returned CRIRecord still populates ContainerID / Image / Labels.
type DockerClient struct {
	// Endpoint is the Docker API address. Supported schemes:
	// unix:///path/to/docker.sock (default: unix:///var/run/docker.sock)
	// tcp://host:port
	// http://host:port (alias for tcp, no TLS)
	Endpoint string

	// Timeout bounds a single /containers/json request. 0 → 3 s.
	Timeout time.Duration

	// APIVersion, if set, pins the Docker API version (e.g. "1.41"). Most
	// deployments can omit this — the Engine negotiates the latest when
	// the path lacks a /vX.Y prefix.
	APIVersion string
}

// ErrDockerUnavailable is returned when the Docker socket can't be reached.
// Callers treat it as a soft failure and keep the previous snapshot.
var ErrDockerUnavailable = errors.New("enricher: docker unavailable")

// Snapshot returns one CRIRecord per running container seen by the Docker
// daemon. Non-running containers are filtered out; stopped containers are
// not an interesting observation target for the tracer.
func (d *DockerClient) Snapshot(ctx context.Context) ([]CRIRecord, error) {
	endpoint := d.Endpoint
	if endpoint == "" {
		endpoint = "unix:///var/run/docker.sock"
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, host, err := dockerHTTPClient(endpoint, timeout)
	if err != nil {
		return nil, err
	}
	path := "/containers/json"
	if d.APIVersion != "" {
		path = "/v" + strings.TrimPrefix(d.APIVersion, "v") + path
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		// Wrap connect-side errors as ErrDockerUnavailable so callers can
		// distinguish "socket missing" from "bad JSON" without string-matching.
		if isConnectError(err) {
			return nil, fmt.Errorf("%w: %v", ErrDockerUnavailable, err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: GET %s = %d %s", path, resp.StatusCode, string(body))
	}
	return parseDockerSnapshot(body)
}

// dockerHTTPClient returns an http.Client whose Transport dials the
// configured endpoint, plus the synthetic host URL ("http://docker") to
// use in requests. For unix sockets the client is scoped to the dial path.
func dockerHTTPClient(endpoint string, timeout time.Duration) (*http.Client, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", fmt.Errorf("docker endpoint %q: %w", endpoint, err)
	}
	switch u.Scheme {
	case "unix":
		sock := u.Path
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		}
		return &http.Client{Transport: tr, Timeout: timeout}, "http://docker", nil
	case "tcp", "http":
		return &http.Client{Timeout: timeout}, "http://" + u.Host, nil
	default:
		return nil, "", fmt.Errorf("docker endpoint scheme %q not supported (want unix|tcp|http)", u.Scheme)
	}
}

// isConnectError folds the few error shapes net.Dial returns for unreachable
// sockets into a single predicate. Enumerating the permanent "go look()
// somewhere else" cases is easier than enumerating all transient errors.
func isConnectError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return false
}

// parseDockerSnapshot decodes the /containers/json response. Factored out
// so the test can drive it with a canned body.
func parseDockerSnapshot(body []byte) ([]CRIRecord, error) {
	var containers []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Image  string            `json:"Image"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("docker: parse /containers/json: %w", err)
	}
	out := make([]CRIRecord, 0, len(containers))
	for _, c := range containers {
		if c.State != "" && c.State != "running" {
			continue
		}
		rec := CRIRecord{
			ContainerID:   c.ID,
			ContainerName: firstDockerName(c.Names),
			Image:         c.Image,
			Labels:        c.Labels,
		}
		// Older Kubernetes-over-docker deployments tag pod identity onto
		// the container as standard labels. Carry them into the record so
		// downstream Resolve attaches the same shape as the CRI path.
		if c.Labels != nil {
			rec.PodName = c.Labels["io.kubernetes.pod.name"]
			rec.PodNamespace = c.Labels["io.kubernetes.pod.namespace"]
			rec.PodUID = c.Labels["io.kubernetes.pod.uid"]
		}
		out = append(out, rec)
	}
	return out, nil
}

// firstDockerName returns the first container name with the leading "/"
// stripped (Docker's /containers/json returns names like "/foo"). Empty
// when the slice is empty.
func firstDockerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}
