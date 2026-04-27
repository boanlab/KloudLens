// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package types defines the on-wire data model shared by tracer, enricher,
// exporter, and klctl. Structures mirror protobuf/event.proto but are kept
// hand-maintained so internal code paths do not need generated stubs.
package types

// WireSchemaVersion identifies the on-wire event-format generation this
// build produces and consumes. Because proto3 field additions are already
// additive, the token exists specifically to flag breaking layout steps
// (per-CPU delta headers, intent state-machine variants, repeated
// ResolvedPath on IntentEvent) — consumers mismatched on this token
// should refuse rather than silently mis-parse frames.
//
// v2: event_type moved to byte 0 of the wire header; compact frames
// (16-byte header + args, EVENT_COMPACT_UNARY()) share the bulk_file
// ringbuf with full frames and are dispatched off byte 0.
const WireSchemaVersion = "v2"

// Severity categorizes how urgently an event should be surfaced.
type Severity int32

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// SeverityFromString parses severity names used by YAML policies.
func SeverityFromString(s string) Severity {
	switch s {
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

// AtLeast returns true if s meets or exceeds threshold.
func (s Severity) AtLeast(threshold Severity) bool { return s >= threshold }

// ContainerMeta is the K8s/container enrichment attached to every primary event.
type ContainerMeta struct {
	Cluster     string            `json:"cluster,omitempty"`
	NodeName    string            `json:"node_name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Pod         string            `json:"pod,omitempty"`
	Container   string            `json:"container,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
	Image       string            `json:"image,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	PidNS       uint32            `json:"pidns,omitempty"`
	MntNS       uint32            `json:"mntns,omitempty"`
}

// SyscallArg is a single decoded syscall argument.
type SyscallArg struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
	Raw   []byte `json:"raw,omitempty"`
}

// SyscallEvent is the unified primary event.
type SyscallEvent struct {
	TimestampNS uint64 `json:"timestamp_ns"`
	EventID     string `json:"event_id"`
	CPUID       uint32 `json:"cpu_id"`
	HostPID     int32  `json:"host_pid"`
	HostTID     int32  `json:"host_tid"`
	HostPPID    int32  `json:"host_ppid"`
	PID         int32  `json:"pid"`
	TID         int32  `json:"tid"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Comm        string `json:"comm,omitempty"`
	ExePath     string `json:"exe_path,omitempty"`
	// CgroupID is the cgroupv2 inode for the task that produced this
	// event. The enricher prefers this over (PidNS, MntNS()) for
	// container attribution because cgroup is per-task and survives
	// hostPID/hostNetwork/hostMnt sharing scenarios that collapse
	// the NS pair onto host inodes.
	CgroupID uint64 `json:"cgroup_id,omitempty"`

	SyscallID   int32        `json:"syscall_id"`
	SyscallName string       `json:"syscall_name"`
	Args        []SyscallArg `json:"args,omitempty"`
	RetVal      int32        `json:"retval"`
	RetCode     string       `json:"retcode,omitempty"`
	DurationNS  uint64       `json:"duration_ns,omitempty"`

	Category  string   `json:"category,omitempty"`
	Operation string   `json:"operation,omitempty"`
	Resource  string   `json:"resource,omitempty"`
	Severity  Severity `json:"severity,omitempty"`

	Meta    ContainerMeta      `json:"meta"`
	History *HistoricalContext `json:"history,omitempty"`
}

// IntentEvent represents a higher-level action aggregated from one or more
// raw syscall events (e.g. FileRead, FileWrite, NetworkExchange).
type IntentEvent struct {
	IntentID             string             `json:"intent_id"`
	Kind                 string             `json:"kind"` // FileRead|FileWrite|NetworkExchange|...
	StartNS              uint64             `json:"start_ns"`
	EndNS                uint64             `json:"end_ns"`
	ContributingEventIDs []string           `json:"contributing_event_ids,omitempty"`
	Attributes           map[string]string  `json:"attributes,omitempty"`
	Meta                 ContainerMeta      `json:"meta"`
	Severity             Severity           `json:"severity,omitempty"`
	Confidence           float64            `json:"confidence,omitempty"`
	History              *HistoricalContext `json:"history,omitempty"`
}

// DeviationEvent reports observed behavior that diverges from the learned
// baseline profile for a workload.
type DeviationEvent struct {
	DeviationID      string        `json:"deviation_id"`
	ProfileID        string        `json:"profile_id"`
	Kind             string        `json:"kind"` // new_exec|new_connect_target|new_file_path|rare_syscall|markov_anomaly
	DeviationScore   float64       `json:"deviation_score"`
	Evidence         string        `json:"evidence,omitempty"`
	RelatedIntentIDs []string      `json:"related_intent_ids,omitempty"`
	Meta             ContainerMeta `json:"meta"`
}

// GraphEdge is a directed relation in the causal session graph linking
// processes, files, sockets, and other kernel objects across a session.
type GraphEdge struct {
	EdgeID     string            `json:"edge_id"`
	Kind       string            `json:"kind"` // FORK|EXEC|IPC_CONNECT|FILE_TOUCH|SIGNAL|PTRACE|MOUNT_SHARE
	SrcNode    string            `json:"src_node"`
	DstNode    string            `json:"dst_node"`
	TSNS       uint64            `json:"ts_ns"`
	SessionID  string            `json:"session_id,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// ResolvedPath captures both container-relative and host-absolute views of a
// filesystem path along with the inode and device that uniquely identify it.
type ResolvedPath struct {
	ContainerAbs     string `json:"container_abs,omitempty"`
	HostAbs          string `json:"host_abs,omitempty"`
	Inode            uint64 `json:"inode,omitempty"`
	DevMajor         uint32 `json:"dev_major,omitempty"`
	DevMinor         uint32 `json:"dev_minor,omitempty"`
	MountID          string `json:"mount_id,omitempty"`
	FollowedSymlink  bool   `json:"followed_symlink,omitempty"`
	PathUnresolved   bool   `json:"path_unresolved,omitempty"`
	UnresolvedReason string `json:"unresolved_reason,omitempty"`
	DentryHint       string `json:"dentry_hint,omitempty"`
}

// ContainerLifecycleEvent — emitted on create/destroy.
type ContainerLifecycleEvent struct {
	TimestampNS uint64        `json:"timestamp_ns"`
	Kind        string        `json:"kind"` // CREATE|START|STOP|DESTROY
	Meta        ContainerMeta `json:"meta"`
	RootPID     int32         `json:"root_pid,omitempty"`
}

// HistoricalContext bundles the recent process/container history attached
// to a primary event to support after-the-fact correlation.
type HistoricalContext struct {
	Ancestors       []ProcessAncestor          `json:"ancestors,omitempty"`
	RecentProcess   []HistoryEntry             `json:"recent_process,omitempty"`
	RecentContainer []HistoryEntry             `json:"recent_container,omitempty"`
	Correlations    []Correlation              `json:"correlations,omitempty"`
	Bootstrap       *ContainerBootstrapSummary `json:"bootstrap,omitempty"`
	CredTimeline    []CredTransition           `json:"cred_timeline,omitempty"`
}

type ProcessAncestor struct {
	PID         int32  `json:"pid"`
	Binary      string `json:"binary,omitempty"`
	ArgvHash    string `json:"argv_hash,omitempty"`
	ExecTSNS    uint64 `json:"exec_ts_ns,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
}

type HistoryEntry struct {
	TSNS    uint64 `json:"ts_ns"`
	Kind    string `json:"kind"`
	Summary string `json:"summary,omitempty"`
	RefID   string `json:"ref_id,omitempty"`
}

type Correlation struct {
	Kind    string  `json:"kind"`
	Summary string  `json:"summary,omitempty"`
	RefID   string  `json:"ref_id,omitempty"`
	Score   float64 `json:"score,omitempty"`
}

type ContainerBootstrapSummary struct {
	StartNS          uint64   `json:"start_ns"`
	FirstExecs       []string `json:"first_execs,omitempty"`
	FirstReads       []string `json:"first_reads,omitempty"`
	FirstPeers       []string `json:"first_peers,omitempty"`
	BootstrapOngoing bool     `json:"bootstrap_ongoing"`
}

type CredTransition struct {
	TSNS  uint64 `json:"ts_ns"`
	From  string `json:"from"`
	To    string `json:"to"`
	Cause string `json:"cause"`
}
