// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package enricher maps (pidNS, mntNS) → ContainerMeta by scanning /proc and
// (when available) consulting the node's CRI runtime. It satisfies
// tracer.MetaResolver so the Bridge can attach pod/container identity to each
// SyscallEvent.
//
// The enricher is deliberately node-local and free of k8s.io/apimachinery
// dependencies: the procfs walker yields a ContainerID from cgroup-v2 lines
// and CRI enrichment shells out to crictl when the socket is reachable. This
// keeps the daemon image thin and avoids a hard dependency on any specific
// runtime client library.
package enricher

import (
	"strings"
)

// ContainerIDFromCgroup parses a cgroup-v2 entry line and returns the runtime
// container ID, or the empty string when the process is outside a container.
//
// Recognized shapes (current Linux distros + container runtimes):
//
//	cri-containerd-<64 hex>.scope — k8s via containerd
//	containerd-<64 hex>.scope — containerd w/o CRI prefix
//	docker-<64 hex>.scope / docker/<hex> — Docker / older cgroup-v1 form
//	crio-<64 hex>.scope — CRI-O
//	libpod-<64 hex>.scope — Podman
//
// Non-container processes (systemd services, user slices) return "". Leading
// slices like kubepods.slice/kubepods-besteffort.slice/... are walked per
// segment so any nested pod-level slice is tolerated.
func ContainerIDFromCgroup(cgroupLine string) string {
	// A cgroup-v2 line is "0::/path"; a cgroup-v1 line is "<hier>:<ctrls>:<path>".
	// We only care about the trailing path. Accept either.
	path := cgroupLine
	if i := strings.LastIndex(cgroupLine, ":"); i >= 0 {
		path = cgroupLine[i+1:]
	}
	// Walk slash-separated segments and try every recognized prefix per segment
	// so the longest/most specific runtime marker wins regardless of slice
	// nesting order.
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if id := extractID(seg); id != "" {
			return id
		}
	}
	return ""
}

// ContainerIDFromCgroupFile reads every line of a cgroup file and returns the
// first non-empty container ID. cgroup-v2 has exactly one line; cgroup-v1 has
// one per hierarchy and is expected to be consistent across lines.
func ContainerIDFromCgroupFile(contents string) string {
	for _, line := range strings.Split(contents, "\n") {
		if id := ContainerIDFromCgroup(strings.TrimSpace(line)); id != "" {
			return id
		}
	}
	return ""
}

// PodUIDFromCgroup extracts the pod UID embedded in kubepods slice segments
// like "kubepods-besteffort-pod<uid>.slice". Returns "" when the cgroup path
// is not under kubepods (non-k8s container, host process). The UID keeps its
// underscore form — crictl/kube emit it either way and matching tolerates it.
func PodUIDFromCgroup(cgroupLine string) string {
	path := cgroupLine
	if i := strings.LastIndex(cgroupLine, ":"); i >= 0 {
		path = cgroupLine[i+1:]
	}
	for _, seg := range strings.Split(path, "/") {
		if !strings.HasPrefix(seg, "kubepods") {
			continue
		}
		// Find "-pod" within the segment and take the rest up to .slice/.scope.
		idx := strings.Index(seg, "-pod")
		if idx < 0 {
			continue
		}
		tail := seg[idx+len("-pod"):]
		tail = trimSuffixes(tail, ".slice", ".scope")
		if tail != "" {
			return tail
		}
	}
	return ""
}

// extractID looks for a known runtime prefix in a single cgroup segment and
// strips the trailing ".scope" / ".service" marker systemd appends. 64 hex
// chars is the Docker/containerd convention; we intentionally accept shorter
// IDs (CRI-O uses 64 too, but Podman occasionally truncates in dumps) and let
// the caller length-check downstream if it needs to.
func extractID(seg string) string {
	seg = trimSuffixes(seg, ".scope", ".service")
	for _, prefix := range []string{
		"cri-containerd-",
		"containerd-",
		"crio-",
		"libpod-",
		"docker-",
	} {
		if strings.HasPrefix(seg, prefix) {
			return seg[len(prefix):]
		}
	}
	// Legacy cgroup-v1 "docker/<id>" shape: the segment itself is the id when
	// the parent segment is "docker". The caller passes us segments one at a
	// time so we detect this only via length + hex heuristic: 32+ chars and
	// all-hex means "probably a container id".
	if len(seg) >= 32 && looksHex(seg) {
		return seg
	}
	return ""
}

func trimSuffixes(s string, suffixes ...string) string {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return s[:len(s)-len(suffix)]
		}
	}
	return s
}

func looksHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
