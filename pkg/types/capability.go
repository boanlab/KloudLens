// SPDX-License-Identifier: Apache-2.0

package types

// KernelInfo describes the kernel the agent is running on.
type KernelInfo struct {
	Version   string   `json:"version"`
	LSMs      []string `json:"lsms,omitempty"`
	CgroupVer string   `json:"cgroup_ver,omitempty"`
	HasBTF    bool     `json:"has_btf"`
	Lockdown  string   `json:"lockdown,omitempty"`
}

// HookCap records one probe result.
type HookCap struct {
	Kind               string   `json:"kind"` // syscall_tracepoint|lsm_bpf|kprobe|tracepoint
	Name               string   `json:"name"`
	Available          bool     `json:"available"`
	UnavailableReason  string   `json:"unavailable_reason,omitempty"`
	ArgSchema          []string `json:"arg_schema,omitempty"`
	FallbackSuggestion string   `json:"fallback_suggestion,omitempty"`
}

// CapabilityReport is emitted by Agent.Capabilities.
type CapabilityReport struct {
	NodeID  string            `json:"node_id"`
	Kernel  KernelInfo        `json:"kernel"`
	Helpers map[string]string `json:"helpers,omitempty"` // e.g. bpf_d_path=yes
	Hooks   []HookCap         `json:"hooks,omitempty"`
}

// HookAvailable returns the first HookCap matching kind+name, if any.
func (r *CapabilityReport) HookAvailable(kind, name string) (HookCap, bool) {
	for _, h := range r.Hooks {
		if h.Kind == kind && h.Name == name {
			return h, true
		}
	}
	return HookCap{}, false
}
