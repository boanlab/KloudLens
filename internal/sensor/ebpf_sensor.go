// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package sensor

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/boanlab/kloudlens/internal/bpf2frame"
)

// bulkStrCacheCap is the userspace hot cache size. The BPF-side
// kl_str_intern dictionary is the authoritative store; this cache is a
// latency optimisation so steady-state ARG_STR_REF resolution stays a
// pure Go map lookup.
const bulkStrCacheCap = 8192

// kernelDict exposes the BPF-side kl_str_intern map for fallback lookups
// when the userspace strCache missed (ringbuf drop on the original
// ARG_RESOURCE frame, decoder restart, cache eviction). The live loader
// wires an ebpfKernelDict; tests inject fakes.
type kernelDict interface {
	Lookup(hash uint64) (string, bool)
}

// strCache is a concurrency-safe bounded hash→string cache that backs
// bpf2frame.Decoder's TypeStrRef resolution. The sensor owns one, shared
// across the crit and bulk pumps. On local miss the cache falls back
// to the BPF kl_str_intern map via the optional kernelDict so rare
// misses still resolve instead of surfacing as "(unresolved)" strings.
type strCache struct {
	mu     sync.Mutex
	m      map[uint64]string
	cap    int
	kernel kernelDict // optional; set by live loader
	// kernelHits / kernelMisses expose the fallback path's hit rate so
	// an operator can tell the intern dictionary apart from the local
	// cache on the /metrics surface.
	kernelHits   atomic.Uint64
	kernelMisses atomic.Uint64
}

func newStrCache(cap int) *strCache {
	return &strCache{m: make(map[uint64]string, cap), cap: cap}
}

// SetKernelDict wires the BPF intern map as a fallback lookup for
// TypeStrRef tags that missed the local cache. Called once by the live
// loader after the BPF collection loads; safe to call with nil to
// unset (tests).
func (c *strCache) SetKernelDict(d kernelDict) {
	c.mu.Lock()
	c.kernel = d
	c.mu.Unlock()
}

// KernelStats returns the (hit, miss) counters for the kernelDict
// fallback path. Surfaced to metrics via EBPFSensor.
func (c *strCache) KernelStats() (hits, misses uint64) {
	return c.kernelHits.Load(), c.kernelMisses.Load()
}

func (c *strCache) Get(h uint64) (string, bool) {
	c.mu.Lock()
	if s, ok := c.m[h]; ok {
		c.mu.Unlock()
		return s, true
	}
	kd := c.kernel
	c.mu.Unlock()
	// Fallback: ask the BPF intern dictionary. Lookup is a syscall, so
	// we only take this path on local miss and cache the result for
	// subsequent lookups.
	if kd != nil {
		if s, ok := kd.Lookup(h); ok {
			c.Put(h, s)
			c.kernelHits.Add(1)
			return s, true
		}
		c.kernelMisses.Add(1)
	}
	return "", false
}

func (c *strCache) Put(h uint64, s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[h]; ok {
		return
	}
	if len(c.m) >= c.cap {
		// Drop one arbitrary entry. Go map iteration order is random,
		// so this approximates a random-eviction policy without the
		// cost of maintaining an LRU list.
		for k := range c.m {
			delete(c.m, k)
			break
		}
	}
	c.m[h] = s
}

// RawSource is the minimum contract an eBPF ring-buffer reader must satisfy.
// It's modeled after cilium/ebpf's ringbuf.Reader: Next blocks for the
// next record and returns it as a byte slice. On shutdown Next returns a
// sentinel error (io.EOF or a package-specific ErrClosed).
//
// The build-tagged live loader (live_linux.go) wires a cilium/ebpf reader
// into this interface. Tests use BytesSource to feed canned records.
type RawSource interface {
	Next() ([]byte, error)
	Close() error
}

// EBPFSensor consumes records from one or more RawSources and dispatches
// them as SyscallEvents. It implements the Sensor interface.
type EBPFSensor struct {
	sources      []RawSource
	extraClosers []io.Closer
	stopped      atomic.Bool
	pairer       *bpf2frame.Pairer

	// decoder resolves TypeStrRef tags against a shared hash→string
	// cache. Both the crit and bulk pumps decode through the same
	// instance so a path first seen on one ring is resolvable on the
	// other. bpf2frame.Decoder serializes cache access internally.
	decoder *bpf2frame.Decoder
	strs    *strCache

	// sampler writes to the kernel's kl_sampling_rate map so the BPF side
	// can throttle bulk-ring emissions without a round-trip through user
	// space. nil on synthetic/test sensors that never loaded a BPF program.
	sampler samplerSink

	// rbDrops reads the kernel's kl_rb_drops per-CPU counter map. nil on
	// synthetic sensors — KernelRingbufDrops returns zeros in that case.
	rbDrops ringbufDropSink

	// Drop counters — incremented from the pump goroutines and read by
	// DropStats for the /metrics surface. DecodeFrame parse failures are
	// almost always a truncated ringbuf record (kernel ringbuf full, reader
	// fell behind); an Unrecognized type tag fails here too.
	framesDropped atomic.Uint64
	framesRead    atomic.Uint64
}

// samplerSink abstracts the BPF sampling-rate map behind a setter. Kept as
// an interface (not a *ebpf.Map) so tests can swap in an in-memory impl
// without pulling the cilium/ebpf dependency into the sensor unit tests.
type samplerSink interface {
	SetBulkSamplingRate(rate uint32) error
}

// RingbufDrops reports summed-across-CPUs bpf_ringbuf_output failure
// counts for each of the eight category rings. Slot-to-field mapping
// mirrors the KL_RB_DROP_* constants in bpf/maps.bpf.h. See the
// bpf/maps.bpf.h block comment for the per-ring rationale.
type RingbufDrops struct {
	Crit         uint64
	BulkFile     uint64
	BulkNet      uint64
	BulkProc     uint64
	BulkFileMeta uint64
	DNS          uint64
	ProcLC       uint64
	SockLC       uint64
}

// Any reports whether any counter is non-zero — used by callers that only
// want to log the breakdown when there's something to log.
func (d RingbufDrops) Any() bool {
	return (d.Crit | d.BulkFile | d.BulkNet | d.BulkProc |
		d.BulkFileMeta | d.DNS | d.ProcLC | d.SockLC) != 0
}

// ringbufDropSink abstracts the kl_rb_drops per-CPU map behind a reader.
type ringbufDropSink interface {
	Read() (RingbufDrops, error)
}

// SetBulkSamplingRate writes `rate` into the kernel's bulk-ring sampling map.
// Contract matches bpf/maps.bpf.h:
//
//	0 or 1 → pass every bulk event (default after load)
//	N (N ≥ 2) → keep 1/N uniformly at random
//	0xFFFFFFFF → drop every bulk event (LevelCriticalOnly)
//
// Caller is typically the downgrade.Controller's onChange hook. Returns
// ErrSamplerUnavailable on test/synthetic sensors that never loaded a map.
func (t *EBPFSensor) SetBulkSamplingRate(rate uint32) error {
	if t.sampler == nil {
		return ErrSamplerUnavailable
	}
	return t.sampler.SetBulkSamplingRate(rate)
}

// ErrSamplerUnavailable is returned by SetBulkSamplingRate when the sensor
// wasn't wired to a BPF collection (replay, unit tests, mock sources).
var ErrSamplerUnavailable = errors.New("sensor: sampling rate map unavailable")

// BulkSamplingDropAll is the sentinel rate value that instructs the BPF
// sampler to drop every bulk-ring event — matches KL_SAMPLE_DROP_ALL in
// bpf/maps.bpf.h. Pair with downgrade.LevelCriticalOnly.
const BulkSamplingDropAll uint32 = 0xFFFFFFFF

// NewEBPFSensor pairs a set of RawSources with the handler side. One source
// per BPF ring buffer is typical (critical + non-critical).
func NewEBPFSensor(sources ...RawSource) *EBPFSensor {
	cache := newStrCache(bulkStrCacheCap)
	return &EBPFSensor{
		sources: sources,
		pairer:  bpf2frame.NewPairer(),
		decoder: bpf2frame.NewDecoder(cache),
		strs:    cache,
	}
}

// AddCloser registers a cleanup callback (BPF collection, attached links,
// etc.) that runs after every RawSource has been closed. Used by LiveEBPF to
// tear down the loaded eBPF objects.
func (t *EBPFSensor) AddCloser(c io.Closer) {
	t.extraClosers = append(t.extraClosers, c)
}

// Start reads records from every source until ctx is done or Stop is called.
// Sources are read concurrently so one slow ringbuf can't stall the others.
func (t *EBPFSensor) Start(ctx context.Context, h Handler) error {
	if h == nil {
		return errors.New("sensor: nil handler")
	}
	if len(t.sources) == 0 {
		return errors.New("sensor: no sources configured")
	}
	errCh := make(chan error, len(t.sources))
	for _, src := range t.sources {
		go func() { errCh <- t.pump(ctx, src, h) }()
	}
	// Wait for the first non-nil error OR ctx.Done.
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (t *EBPFSensor) pump(ctx context.Context, src RawSource, h Handler) error {
	for {
		if t.stopped.Load() {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		raw, err := src.Next()
		if err != nil {
			if errors.Is(err, io.EOF) || t.stopped.Load() {
				return nil
			}
			return err
		}
		t.framesRead.Add(1)
		fr, derr := t.decoder.Decode(raw)
		if derr != nil {
			t.framesDropped.Add(1)
			continue // skip malformed records
		}
		if ev, ok := t.pairer.Merge(fr.Header, fr.Args); ok {
			h(ev)
		}
	}
}

// PendingPairs returns the number of ENTER frames awaiting EXIT — used by
// the /metrics endpoint to surface BPF buffer loss indirectly.
func (t *EBPFSensor) PendingPairs() int {
	if t.pairer == nil {
		return 0
	}
	return t.pairer.Pending()
}

// PairerEvicted returns the running total of ENTER frames the pairer had
// to drop because its pending map hit the cap. Exposed via /metrics as a
// counter so dashboards can alert on sustained eviction pressure (the
// usual signal is BPF ringbuf loss upstream).
func (t *EBPFSensor) PairerEvicted() uint64 {
	if t.pairer == nil {
		return 0
	}
	return t.pairer.Evicted()
}

// DropStats reports how many raw ringbuf frames were read and how many of
// those failed decode (counted as drops here because the event never reached
// the aggregator). The ratio of dropped/read is the daemon's visible proxy
// for kernel-side BPF ringbuf loss: a rising ratio means the reader is
// falling behind the kernel's producer side. Kernel-side ringbuf-full drops
// (records that never surfaced as frames at all) are reported separately by
// KernelRingbufDrops.
func (t *EBPFSensor) DropStats() (read, dropped uint64) {
	return t.framesRead.Load(), t.framesDropped.Load()
}

// KernelRingbufDrops sums the kernel's per-CPU kl_rb_drops counters across
// CPUs. These count bpf_ringbuf_output failures — records the kernel
// produced but had no room to enqueue. Returns a zero-value RingbufDrops on
// synthetic sensors that never bound the map.
func (t *EBPFSensor) KernelRingbufDrops() (RingbufDrops, error) {
	if t.rbDrops == nil {
		return RingbufDrops{}, nil
	}
	return t.rbDrops.Read()
}

// Stop signals every source to close and returns the first close error. Any
// extra closers registered via AddCloser run after the sources drain.
func (t *EBPFSensor) Stop() error {
	t.stopped.Store(true)
	var firstErr error
	for _, src := range t.sources {
		if err := src.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, c := range t.extraClosers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// BytesSource is an in-memory RawSource for tests and replay.
type BytesSource struct {
	records [][]byte
	idx     int
	closed  atomic.Bool
}

// NewBytesSource returns a source that yields `records` in order then EOF.
func NewBytesSource(records [][]byte) *BytesSource {
	return &BytesSource{records: records}
}

// Next returns the next record or io.EOF when the slice is exhausted.
func (b *BytesSource) Next() ([]byte, error) {
	if b.closed.Load() {
		return nil, io.EOF
	}
	if b.idx >= len(b.records) {
		return nil, io.EOF
	}
	out := b.records[b.idx]
	b.idx++
	return out, nil
}

// Close marks the source closed; subsequent Next returns EOF.
func (b *BytesSource) Close() error {
	b.closed.Store(true)
	return nil
}
