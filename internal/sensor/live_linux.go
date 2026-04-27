// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build linux && amd64

package sensor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// bpfObjectBytes is supplied by embed_amd64.go, which embeds the
// bpf2go-named object (kloudlens_x86_bpfel.o) produced by bpf/Makefile.

// LiveEBPF loads the embedded system_tracer BPF program with default options
// (raw_syscalls disabled, no NS filter). See LiveEBPFWith for the option
// surface.
func LiveEBPF() (*EBPFSensor, error) { return LiveEBPFWith(LiveOptions{}) }

// LiveEBPFWith loads the embedded system_tracer BPF program, attaches every
// tracepoint/kprobe declared by the object (respecting opts.EnableRawSyscalls),
// opens the two ring buffers (critical + non-critical), populates the ns-skip
// filter per opts.TargetNS / opts.ExceptNS(), and returns an EBPFSensor that
// drains them as RawSources.
//
// The returned tracer's Stop closes the ringbufs, then the attached links,
// then the eBPF collection. Callers must hold CAP_BPF / CAP_PERFMON on
// kernels that require them.
func LiveEBPFWith(opts LiveOptions) (*EBPFSensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("tracer: remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObjectBytes))
	if err != nil {
		return nil, fmt.Errorf("tracer: load BPF spec: %w", err)
	}
	// Drop programs the operator asked us to skip. Used for kernel-version-
	// specific verifier rejections that would otherwise abort the entire
	// collection load.
	for _, name := range opts.SkipPrograms {
		delete(spec.Programs, name)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("tracer: load BPF collection: %w", err)
	}

	var links []io.Closer
	closeAll := func() {
		for _, l := range links {
			_ = l.Close()
		}
		coll.Close()
	}

	// Populate the self-TGID map BEFORE attaching any program so the
	// /sys/kernel/tracing/events/.../id opens link.Tracepoint does at
	// attach time aren't observed by tracepoints we just attached. Order
	// matters: write the map, then attach. Older BPF objects without the
	// map fall through silently for forward-compat.
	if selfMap, ok := coll.Maps["kl_self_tgid"]; ok {
		// #nosec G115 -- os.Getpid is positive and fits in uint32 on every
		// supported kernel (PID_MAX_LIMIT < 2^22 by default).
		tgid := uint32(os.Getpid())
		if err := selfMap.Update(uint32(0), tgid, ebpf.UpdateAny); err != nil {
			closeAll()
			return nil, fmt.Errorf("tracer: populate kl_self_tgid: %w", err)
		}
	}

	for name, prog := range coll.Programs {
		pspec, ok := spec.Programs[name]
		if !ok {
			continue
		}
		// raw_syscalls fire on every syscall in the system and duplicate
		// the targeted per-syscall tracepoints the object also installs.
		// Keep them opt-in via LiveOptions.EnableRawSyscalls.
		if !opts.EnableRawSyscalls && strings.Contains(pspec.SectionName, "raw_syscalls") {
			continue
		}
		l, attachErr := attachProgram(pspec.SectionName, prog)
		if attachErr != nil {
			closeAll()
			return nil, fmt.Errorf("tracer: attach %s (%s): %w", name, pspec.SectionName, attachErr)
		}
		if l != nil {
			links = append(links, l)
		}
	}

	if err := applyNSFilter(coll, opts); err != nil {
		closeAll()
		return nil, err
	}

	// One ringbuf per kernel-side category (bpf/maps.bpf.h). Each opens a
	// separate cilium/ebpf reader so the pumps can drain independently — a
	// burst on kl_events_bulk_file can't stall kl_events_bulk_net.
	ringSpecs := []struct {
		name string
		kind string // for error messages only
	}{
		{"kl_events_crit", "crit"},
		{"kl_events_bulk_file", "bulk_file"},
		{"kl_events_bulk_net", "bulk_net"},
		{"kl_events_bulk_proc", "bulk_proc"},
		{"kl_events_bulk_file_meta", "bulk_file_meta"},
		{"kl_events_dns", "dns"},
		{"kl_events_proc_lc", "proc_lc"},
		{"kl_events_sock_lc", "sock_lc"},
	}
	readers := make([]*ringbuf.Reader, 0, len(ringSpecs))
	closeReaders := func() {
		for _, r := range readers {
			_ = r.Close()
		}
	}
	for _, rs := range ringSpecs {
		m, ok := coll.Maps[rs.name]
		if !ok {
			closeReaders()
			closeAll()
			return nil, fmt.Errorf("sensor: ringbuf %s not found", rs.name)
		}
		rb, err := ringbuf.NewReader(m)
		if err != nil {
			closeReaders()
			closeAll()
			return nil, fmt.Errorf("tracer: ringbuf %s: %w", rs.kind, err)
		}
		readers = append(readers, rb)
	}

	sources := make([]RawSource, 0, len(readers))
	for _, rb := range readers {
		sources = append(sources, newRingbufSource(rb))
	}
	tr := NewEBPFSensor(sources...)
	for _, l := range links {
		tr.AddCloser(l)
	}
	tr.AddCloser(collectionCloser{coll: coll})
	// kl_sampling_rate is optional for forward-compat with older objects —
	// if the map is missing, the sensor just keeps sampler nil and
	// SetBulkSamplingRate returns ErrSamplerUnavailable. Current builds of
	// bpf/maps.bpf.h always declare it, so the hit path is the norm.
	if rateMap, ok := coll.Maps["kl_sampling_rate"]; ok {
		tr.sampler = ebpfSampler{m: rateMap}
	}
	// kl_rb_drops is optional at the Go layer — BPF objects without
	// the drop-counter map are tolerated.
	if dropMap, ok := coll.Maps["kl_rb_drops"]; ok {
		tr.rbDrops = ebpfRingbufDrops{m: dropMap}
	}
	// kl_str_intern is optional for forward-compat with objects that
	// still ship the presence-only kl_str_seen. Wire a fallback lookup
	// so the decoder resolves ARG_STR_REF tags whose original full
	// string frame the userspace cache missed.
	if internMap, ok := coll.Maps["kl_str_intern"]; ok {
		tr.strs.SetKernelDict(ebpfKernelDict{m: internMap})
	}
	return tr, nil
}

// ebpfKernelDict adapts the kl_str_intern LRU map into the kernelDict
// interface. Lookup reads the fixed-size value (len + bytes) and returns
// the decoded string. A map miss, read error, or zero/oversized length
// returns ("", false) so callers treat it as a normal cache miss.
type ebpfKernelDict struct{ m *ebpf.Map }

// internValSize mirrors sizeof(struct kl_intern_val) in bpf/maps.bpf.h:
// __u16 len (2) + __u8 bytes[254] (254) = 256 bytes. Kept as a constant
// so the cilium/ebpf binary read doesn't have to introspect the map
// spec on every lookup.
const internValSize = 256

func (d ebpfKernelDict) Lookup(hash uint64) (string, bool) {
	var val [internValSize]byte
	if err := d.m.Lookup(&hash, &val); err != nil {
		return "", false
	}
	// Layout: LE u16 length, then content bytes (no trailing NUL).
	l := int(val[0]) | int(val[1])<<8
	if l == 0 || l > internValSize-2 {
		return "", false
	}
	return string(val[2 : 2+l]), true
}

// ebpfRingbufDrops reads the kl_rb_drops per-CPU array. Slots mirror the
// KL_RB_DROP_* constants in bpf/maps.bpf.h (0=crit, 1=bulk_file, 2=bulk_net,
// 3=bulk_proc, 4=dns, 5=proc_lc, 6=sock_lc, 7=bulk_file_meta).
type ebpfRingbufDrops struct{ m *ebpf.Map }

// ringbuf drop slot indices — must match KL_RB_DROP_* in bpf/maps.bpf.h.
const (
	rbDropSlotCrit         uint32 = 0
	rbDropSlotBulkFile     uint32 = 1
	rbDropSlotBulkNet      uint32 = 2
	rbDropSlotBulkProc     uint32 = 3
	rbDropSlotDNS          uint32 = 4
	rbDropSlotProcLC       uint32 = 5
	rbDropSlotSockLC       uint32 = 6
	rbDropSlotBulkFileMeta uint32 = 7
)

func (d ebpfRingbufDrops) Read() (RingbufDrops, error) {
	var out RingbufDrops
	slots := []struct {
		idx   uint32
		name  string
		field *uint64
	}{
		{rbDropSlotCrit, "crit", &out.Crit},
		{rbDropSlotBulkFile, "bulk_file", &out.BulkFile},
		{rbDropSlotBulkNet, "bulk_net", &out.BulkNet},
		{rbDropSlotBulkProc, "bulk_proc", &out.BulkProc},
		{rbDropSlotDNS, "dns", &out.DNS},
		{rbDropSlotProcLC, "proc_lc", &out.ProcLC},
		{rbDropSlotSockLC, "sock_lc", &out.SockLC},
		{rbDropSlotBulkFileMeta, "bulk_file_meta", &out.BulkFileMeta},
	}
	for _, s := range slots {
		var vals []uint64
		if err := d.m.Lookup(s.idx, &vals); err != nil {
			return RingbufDrops{}, fmt.Errorf("sensor: lookup kl_rb_drops[%s]: %w", s.name, err)
		}
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		*s.field = sum
	}
	return out, nil
}

// ebpfSampler adapts the kl_sampling_rate ARRAY map to the samplerSink
// contract. Key 0 is the only slot (max_entries=1 in maps.bpf.h).
type ebpfSampler struct{ m *ebpf.Map }

func (s ebpfSampler) SetBulkSamplingRate(rate uint32) error {
	return s.m.Update(uint32(0), rate, ebpf.UpdateAny)
}

// applyNSFilter writes st_toggle_map and st_skip_ns_map per opts. BPF side:
//
//	should_monitor reads toggle[0]. toggle=1 → "target" mode (only NS keys
//	present in skip_ns_map pass). toggle=0 → "except" mode (NS keys present
//	in skip_ns_map are dropped; everything else passes).
//
// The two modes are mutually exclusive; TargetNS wins when both are given.
// Absent filters leave the maps empty (toggle stays at zero-value 0 →
// "monitor everything").
func applyNSFilter(coll *ebpf.Collection, opts LiveOptions) error {
	toggleMap, ok := coll.Maps["kl_ns_toggle"]
	if !ok {
		return errors.New("sensor: kl_ns_toggle not found")
	}
	skipMap, ok := coll.Maps["kl_ns_filter"]
	if !ok {
		return errors.New("sensor: kl_ns_filter not found")
	}
	var toggle uint32
	var keys []NSKey
	switch {
	case len(opts.TargetNS) > 0:
		toggle = 1
		keys = opts.TargetNS
	case len(opts.ExceptNS) > 0:
		toggle = 0
		keys = opts.ExceptNS
	default:
		// Nothing to filter; default-0 toggle is already correct. Don't
		// even write the map in case a concurrent process has populated
		// it: an empty CLI leaves the map alone.
		return nil
	}
	if err := toggleMap.Update(uint32(0), toggle, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("sensor: update kl_ns_toggle: %w", err)
	}
	// Filter-map value is 1 for target entries and 0 for except entries. The
	// BPF side only checks presence (`bpf_map_lookup_elem != NULL`), so the
	// stored value is cosmetic — debug tooling can dump it to distinguish
	// which half of the map an entry came from.
	skipVal := uint32(0)
	if toggle == 1 {
		skipVal = 1
	}
	for _, k := range keys {
		if err := skipMap.Update(k.Uint64(), skipVal, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("sensor: update kl_ns_filter[%d:%d]: %w", k.PidNS, k.MntNS, err)
		}
	}
	return nil
}

// attachProgram dispatches on the SEC prefix to the matching link
// helper. Unrecognized sections return nil, nil so the loader ignores
// them. Returns io.Closer because the cgroup_skb path supplies its own
// handle (PROG_ATTACH with BPF_F_ALLOW_MULTI) outside cilium/ebpf's
// link.Link surface.
func attachProgram(section string, prog *ebpf.Program) (io.Closer, error) {
	switch {
	case strings.HasPrefix(section, "tracepoint/"), strings.HasPrefix(section, "tp/"):
		trimmed := strings.TrimPrefix(section, "tracepoint/")
		trimmed = strings.TrimPrefix(trimmed, "tp/")
		parts := strings.Split(trimmed, "/")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid tracepoint section %q", section)
		}
		// Legacy quirk: SEC("tp/syscalls/raw_syscalls/sys_enter") puts the
		// real group name in the penultimate segment. Using the last two
		// handles both normal "tp/X/Y" and the 4-segment form.
		group := parts[len(parts)-2]
		event := parts[len(parts)-1]
		return link.Tracepoint(group, event, prog, nil)
	case strings.HasPrefix(section, "kprobe/"):
		return link.Kprobe(strings.TrimPrefix(section, "kprobe/"), prog, nil)
	case strings.HasPrefix(section, "kretprobe/"):
		return link.Kretprobe(strings.TrimPrefix(section, "kretprobe/"), prog, nil)
	case strings.HasPrefix(section, "fentry/"), strings.HasPrefix(section, "fexit/"):
		// fentry/fexit are BPF_PROG_TYPE_TRACING with BTF-typed attach
		// targets. The attach target function name is encoded in the
		// program spec's AttachTo field (set by libbpf's SEC parser at
		// load time), so link.AttachTracing pulls it from the program
		// directly — we don't need to pass it here.
		return link.AttachTracing(link.TracingOptions{Program: prog})
	case strings.HasPrefix(section, "lsm/"):
		// BPF_PROG_TYPE_LSM. Attach target (e.g. bprm_check_security) is in
		// the program spec's AttachTo; link.AttachLSM resolves it from the
		// program. Requires CONFIG_BPF_LSM=y and "bpf" in the kernel's LSM
		// list — absence surfaces as an EINVAL at attach time which the
		// outer loader reports as a fatal attach error.
		return link.AttachLSM(link.LSMOptions{Program: prog})
	case strings.HasPrefix(section, "cgroup_skb/"):
		// BPF_PROG_TYPE_CGROUP_SKB attached at the cgroupv2 unified
		// hierarchy root. One attach point catches every descendant
		// cgroup's network packets. Section examples:
		// "cgroup_skb/ingress", "cgroup_skb/egress".
		return attachCgroupSkb(section, prog)
	default:
		return nil, nil
	}
}

// cgroupV2Root is the conventional cgroup v2 unified hierarchy mount.
// Distros that mount cgroupv1 mixed mode at /sys/fs/cgroup/unified can
// override via the KLOUDLENS_CGROUP_ROOT env var; an empty result skips
// cgroup_skb attaches gracefully.
const cgroupV2Root = "/sys/fs/cgroup"

// attachCgroupSkb attaches a cgroup_skb program at the unified
// hierarchy root with BPF_F_ALLOW_MULTI so descendant cgroups inherit
// the hook (PROG_ATTACH semantics — bpf_link's cgroup attach is
// single-attach-only and does not propagate). The returned handle
// detaches + closes the cgroup fd on Close.
func attachCgroupSkb(section string, prog *ebpf.Program) (io.Closer, error) {
	root := os.Getenv("KLOUDLENS_CGROUP_ROOT")
	if root == "" {
		root = cgroupV2Root
	}
	var attachType ebpf.AttachType
	switch strings.TrimPrefix(section, "cgroup_skb/") {
	case "ingress":
		attachType = ebpf.AttachCGroupInetIngress
	case "egress":
		attachType = ebpf.AttachCGroupInetEgress
	default:
		return nil, fmt.Errorf("cgroup_skb: unknown direction in %q", section)
	}
	cgroup, err := os.Open(root) // #nosec G304,G703 -- root is a fixed cgroupv2 mount path
	if err != nil {
		return nil, fmt.Errorf("cgroup_skb: open %s: %w", root, err)
	}
	const bpfFAllowMulti = 0x2 // matches kernel's BPF_F_ALLOW_MULTI
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(cgroup.Fd()), // #nosec G115 -- cgroup fd fits in int by kernel contract
		Program: prog,
		Attach:  attachType,
		Flags:   bpfFAllowMulti,
	}); err != nil {
		_ = cgroup.Close()
		return nil, fmt.Errorf("cgroup_skb attach %s at %s: %w", section, root, err)
	}
	return &cgroupAttachCloser{cgroup: cgroup, prog: prog, attach: attachType}, nil
}

// cgroupAttachCloser wraps a legacy PROG_ATTACH cgroup hook so the sensor
// Stop path can detach + close the cgroup fd cleanly.
type cgroupAttachCloser struct {
	cgroup *os.File
	prog   *ebpf.Program
	attach ebpf.AttachType
}

func (c *cgroupAttachCloser) Close() error {
	defer c.cgroup.Close()
	return link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  int(c.cgroup.Fd()), // #nosec G115 -- cgroup fd fits in int by kernel contract
		Program: c.prog,
		Attach:  c.attach,
	})
}

// collectionCloser wraps ebpf.Collection.Close (which returns no error) so
// it satisfies io.Closer.
type collectionCloser struct{ coll *ebpf.Collection }

func (c collectionCloser) Close() error { c.coll.Close(); return nil }

// ringbufSource adapts cilium/ebpf's ringbuf.Reader to RawSource.
type ringbufSource struct {
	rb     *ringbuf.Reader
	closed atomic.Bool
}

func newRingbufSource(rb *ringbuf.Reader) *ringbufSource {
	return &ringbufSource{rb: rb}
}

func (r *ringbufSource) Next() ([]byte, error) {
	rec, err := r.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, io.EOF
		}
		return nil, err
	}
	// rec.RawSample is owned by the ringbuf reader until the next Read. The
	// mapper copies anything it keeps, so passing the slice is safe.
	return rec.RawSample, nil
}

func (r *ringbufSource) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	return r.rb.Close()
}
