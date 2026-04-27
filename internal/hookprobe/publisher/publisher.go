// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package publisher writes the agent's CapabilityReport to a cluster-scoped
// NodeCapability CR (kloudlens.io/v1). Plan + Tier 5.
//
// The CR mirrors what the /metrics capability_info gauge exposes — having
// the same data in etcd lets cluster-wide tooling (klctl caps diff, policy
// admission hooks) read a single source of truth without scraping every
// agent's metrics endpoint. Kept dep-light: direct REST against the kube
// apiserver using the in-cluster ServiceAccount mounts.
package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

const (
	defaultAPIServer = "https://kubernetes.default.svc"
	defaultCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- well-known kubelet SA path, not a hardcoded secret

	crAPIVersion = "kloudlens.io/v1"
	crKind       = "NodeCapability"

	// basePath is the cluster-scoped collection URL. Names append as /<node>.
	basePath = "/apis/kloudlens.io/v1/nodecapabilities"
)

// Publisher writes a CapabilityReport to a per-node NodeCapability CR.
// Zero-value Publisher uses the in-cluster defaults; tests set APIServer +
// HTTPClient.
type Publisher struct {
	// APIServer defaults to https://kubernetes.default.svc when empty.
	APIServer string
	// CAFile / TokenFile default to the in-cluster ServiceAccount mounts.
	// Tests leave them empty and supply HTTPClient directly.
	CAFile    string
	TokenFile string
	// HTTPClient overrides the default client (tests). Production leaves nil.
	HTTPClient *http.Client
	// NodeName is the CR's metadata.name — must be DNS-1123 compliant.
	NodeName string
	// Interval governs re-publish cadence. 0 → 5 minutes.
	Interval time.Duration
	// Report is a snapshot producer. Called once per interval so a long-
	// running agent reflects kernel state changes (e.g. module load that
	// adds a previously-missing hook). Must be safe for concurrent calls.
	Report func() (*types.CapabilityReport, error)
}

// defaultInterval is deliberately coarse — capabilities are static modulo
// rare events (kernel module load, security-module policy change). Five
// minutes keeps the CR fresh without hammering etcd on a large fleet.
const defaultInterval = 5 * time.Minute

// Run blocks until ctx is cancelled, publishing the current report once
// immediately and then on every tick. Individual publish failures are
// logged (via fmt.Fprintln to stderr) but don't abort the loop — a
// transient apiserver hiccup should not take down the agent.
func (p *Publisher) Run(ctx context.Context) error {
	if p.NodeName == "" {
		return errors.New("publisher: NodeName is required")
	}
	if p.Report == nil {
		return errors.New("publisher: Report is required")
	}
	if p.APIServer == "" {
		p.APIServer = defaultAPIServer
	}
	if p.Interval == 0 {
		p.Interval = defaultInterval
	}
	// CAFile / TokenFile defaults only apply on the production path where we
	// build the client ourselves. Tests supply HTTPClient directly and rely
	// on empty TokenFile to skip setAuth — filling in the SA mount path here
	// would break that contract.
	if p.HTTPClient == nil {
		if p.CAFile == "" {
			p.CAFile = defaultCAFile
		}
		if p.TokenFile == "" {
			p.TokenFile = defaultTokenFile
		}
		cl, err := buildClient(p.CAFile)
		if err != nil {
			return err
		}
		p.HTTPClient = cl
	}

	// Immediate publish so the CR exists as soon as the agent is up; the
	// ticker then refreshes on cadence. Error on first try isn't fatal —
	// apiserver may still be warming up during a rolling restart.
	if err := p.publishOnce(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "capspublisher: initial publish: %v\n", err)
	}

	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := p.publishOnce(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "capspublisher: publish: %v\n", err)
			}
		}
	}
}

// publishOnce: GET the existing CR; on 404 POST a stub; then PUT the
// status subresource with the freshly-gathered report. Using PUT on
// /status (not PATCH) keeps the server-side merge deterministic — the
// agent owns the entire status block, no shared ownership with other
// controllers.
func (p *Publisher) publishOnce(ctx context.Context) error {
	rep, err := p.Report()
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	rv, exists, err := p.getResourceVersion(ctx)
	if err != nil {
		return err
	}
	if !exists {
		if err := p.createStub(ctx); err != nil {
			return err
		}
		// After create, re-fetch RV — the stored object has one; we need
		// it to PUT the status without a 409.
		rv, _, err = p.getResourceVersion(ctx)
		if err != nil {
			return err
		}
	}
	return p.putStatus(ctx, rv, rep)
}

func (p *Publisher) getResourceVersion(ctx context.Context) (string, bool, error) {
	u := p.APIServer + basePath + "/" + p.NodeName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false, err
	}
	if err := p.setAuth(req); err != nil {
		return "", false, err
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode >= 400 {
		return "", false, fmt.Errorf("get %s: %s", u, readErr(resp))
	}
	var obj struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return "", false, fmt.Errorf("decode get: %w", err)
	}
	return obj.Metadata.ResourceVersion, true, nil
}

func (p *Publisher) createStub(ctx context.Context) error {
	body := map[string]any{
		"apiVersion": crAPIVersion,
		"kind":       crKind,
		"metadata":   map[string]any{"name": p.NodeName},
		"spec":       map[string]any{"node": p.NodeName},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := p.APIServer + basePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := p.setAuth(req); err != nil {
		return err
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 409 Conflict is benign — a race with another agent, a controller,
	// or our own previous attempt means the CR now exists; next loop
	// iteration will do the GET+PUT path.
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("post %s: %s", u, readErr(resp))
	}
	return nil
}

func (p *Publisher) putStatus(ctx context.Context, rv string, rep *types.CapabilityReport) error {
	status := buildStatus(rep)
	body := map[string]any{
		"apiVersion": crAPIVersion,
		"kind":       crKind,
		"metadata": map[string]any{
			"name":            p.NodeName,
			"resourceVersion": rv,
		},
		"status": status,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := p.APIServer + basePath + "/" + p.NodeName + "/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := p.setAuth(req); err != nil {
		return err
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("put status %s: %s", u, readErr(resp))
	}
	return nil
}

// buildStatus flattens a CapabilityReport into the CRD's status schema.
// Field selection mirrors deployments/crds/nodecapabilities.yaml — any
// new scalar in the schema needs both a line here and a schema update.
func buildStatus(rep *types.CapabilityReport) map[string]any {
	hooks := make([]map[string]any, 0, len(rep.Hooks))
	degraded := []string{}
	for _, h := range rep.Hooks {
		mech := h.Kind // "syscall_tracepoint" | "lsm_bpf" | "kprobe" | "tracepoint"
		hooks = append(hooks, map[string]any{
			"name":      h.Name,
			"available": h.Available,
			"reason":    h.UnavailableReason,
			"mechanism": mech,
		})
		if !h.Available {
			degraded = append(degraded, fmt.Sprintf("%s:%s", mech, h.Name))
		}
	}
	// The CRD schema is fixed — compute the summary booleans from the
	// report rather than passing through a richer object.
	hasLSM := slices.Contains(rep.Kernel.LSMs, "bpf")
	hasFentry, hasKprobeMulti := false, false
	if v, ok := rep.Helpers["bpf_fentry"]; ok && v == "yes" {
		hasFentry = true
	}
	if v, ok := rep.Helpers["kprobe_multi"]; ok && v == "yes" {
		hasKprobeMulti = true
	}
	return map[string]any{
		"reportedAt":  time.Now().UTC().Format(time.RFC3339),
		"kernel":      rep.Kernel.Version,
		"arch":        rep.Helpers["arch"], // may be empty if the probe doesn't fill it
		"btf":         rep.Kernel.HasBTF,
		"ringbuf":     true, // CRDs predate the soft-fail; every supported kernel ships ringbuf
		"bpfLSM":      hasLSM,
		"fentry":      hasFentry,
		"kprobeMulti": hasKprobeMulti,
		"cgroupV2":    rep.Kernel.CgroupVer == "v2",
		"hooks":       hooks,
		"degraded":    degraded,
	}
}

func (p *Publisher) setAuth(req *http.Request) error {
	// Empty TokenFile is a test shortcut — callers swap in a fake HTTPClient
	// and don't need real creds.
	if p.TokenFile == "" {
		return nil
	}
	token, err := os.ReadFile(p.TokenFile)
	if err != nil {
		return fmt.Errorf("read token %s: %w", p.TokenFile, err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	return nil
}

func buildClient(caFile string) (*http.Client, error) {
	caBytes, err := os.ReadFile(caFile) // #nosec G304 -- caFile is a CLI/config-supplied TLS trust root
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("CA file %s has no PEM certs", caFile)
	}
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

func readErr(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Sprintf("%d: %s", resp.StatusCode, string(b))
}
