// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package bpf2frame decodes raw BPF ring-buffer records into typed Frame
// values. The BPF side emits fixed-layout records into a pair of ring
// buffers (critical / non-critical); this package parses those bytes
// into a neutral `Event` header + decoded `Args` and maps them to the
// `types.SyscallEvent` schema that the frame2intent bridge consumes.
//
// All code here is pure Go and builds/tests on every platform — the
// live ringbuf reader lives in internal/sensor under build tags.
package bpf2frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// EventType codes match the BPF-side enum kl_event_type_t.
const (
	EventTypeUnary        = 0
	EventTypeEnter        = 1
	EventTypeExit         = 2
	EventTypeCompactUnary = 0x13
)

// CompactHeaderSize is the wire length of a compact-frame header. A
// record whose payload starts with EventTypeCompactUnary is 16 bytes of
// compact_event_t followed by variadic args; the Decoder reconstructs
// the full Event by overlaying the per-CPU base mirror.
const CompactHeaderSize = 16

// Argument type tags, little-endian uint32 prefix written by BPF.
const (
	TypeInt        uint32 = iota + 1 // int32
	TypeUInt                         // uint32
	TypeULong                        // uint64
	TypeStr                          // length-prefixed string
	TypeStrArr                       // zero-terminated array of TypeStr
	TypeSource                       // string (proc comm)
	TypeResource                     // string (path / address)
	TypeCurrentDir                   // string
	TypeStrRef                       // 8-byte fnv1a-64 hash; resolves to a
	// // string via the Decoder's strCache
	// // (populated from prior full-string tags)
	TypeCoalescedCount // uint32 — trailer on the first event
	// // emitted after a kernel-side coalesce
	// // window closes. Value is the number of
	// // events the PREVIOUS window collapsed
	// // (N>1 means N-1 events were suppressed).
	TypeCoalescedBytes // uint64 — cumulative bytes across the
	// // coalesced window. r/w only; 0 for
	// // stat/access where bytes are undefined.
	TypeVarintU32 // LEB128-encoded uint32.
	// // Same semantic as TypeUInt; surfaced as
	// // uint32 in the decoded Args slice so
	// // consumers don't care how it was sent.
	TypeVarintU64 // LEB128-encoded uint64. Surfaced as
	// // uint64 in Args.
	TypeCPUSeq // LEB128-encoded uint64 — per-CPU emit counter
	// // from kl_cpu_seq. Appended by every
	// // BPF submit so Decoder can detect
	// // per-CPU record loss independently
	// // of the aggregate ringbuf-lost
	// // counter. Kept separate from
	// // TypeVarintU64 so the decoder can
	// // route it to its per-CPU tracker
	// // without polluting the event's
	// // named Args slice.
)

// ErrVarintTooLong caps LEB128 decoding so a corrupt frame can't send us
// reading forever. u64 fits in ≤10 bytes; anything longer is a desync.
var ErrVarintTooLong = errors.New("tracer: varint exceeds 10 bytes")

// Event is the fixed-size header emitted by the BPF programs before any
// variadic argument payload. Schema v2: EventType / ArgNum / CPUID sit
// at offset 0-3 so the ringbuf reader can dispatch full vs compact
// frames off the first byte. Layout + widths + LE byte order are
// load-bearing — bpf/bpf2frame.bpf.h's struct event_t must stay lockstep.
type Event struct {
	EventType int8
	ArgNum    int8
	CPUID     uint16
	EventID   uint32

	Timestamp uint64

	PidNsID uint32
	MntNsID uint32

	CgroupID uint64

	HostPPID int32
	PPID     int32

	HostPID int32
	HostTID int32

	PID int32
	TID int32

	UID uint32
	GID uint32

	SyscallID int32
	RetVal    int32
}

// ErrStringTooLarge caps per-string payload — BPF side already truncates to
// 2048 bytes; longer means the record is corrupt.
var ErrStringTooLarge = errors.New("tracer: string payload exceeds 2048 bytes")

// ErrUnknownArgType is returned when the tag byte doesn't match any known
// TypeXXX constant — almost always frame desync.
var ErrUnknownArgType = errors.New("tracer: unknown argument type tag")

// ReadEvent reads the fixed header off `r`. Callers pass the remainder of the
// buffer to ReadArgs once they know how many args to expect.
func ReadEvent(r io.Reader) (Event, error) {
	var e Event
	err := binary.Read(r, binary.LittleEndian, &e)
	return e, err
}

// CompactHeader is the 16-byte wire form written by BPF hooks that opt
// into the compact path (currently just kl_emit_rw). Task-identifying
// fields are omitted from the wire; Decoder.Decode reconstructs the
// full Event by overlaying its per-CPU base mirror.
type CompactHeader struct {
	EventType int8
	ArgNum    int8
	CPUID     uint16
	TsDeltaNs uint32
	SyscallID int32
	RetVal    int32
}

// ReadCompactHeader reads the 16-byte compact-frame header. Caller has
// already peeked byte 0 and determined this is a compact record.
func ReadCompactHeader(r io.Reader) (CompactHeader, error) {
	var h CompactHeader
	err := binary.Read(r, binary.LittleEndian, &h)
	return h, err
}

// ReadArg reads a single TypeXXX-prefixed argument with no intern cache.
// Convenience wrapper for unit tests and replay paths that never see
// TypeStrRef. Live decoding uses Decoder.readArg which consults a cache.
func ReadArg(r io.Reader) (any, error) {
	return readArg(r, nil)
}

// ReadArgs pulls up to `argNum` arguments with no intern cache. Live
// decoding goes through Decoder.
func ReadArgs(r io.Reader, argNum int8) ([]any, error) {
	return readArgs(r, argNum, nil)
}

// StrCache is the contract the Decoder uses to resolve TypeStrRef tags
// back into the strings they reference. Implementations must be safe for
// concurrent use — the sensor drives one Decoder per ring buffer reader,
// and multiple pumps can hit Get/Put at the same time.
type StrCache interface {
	// Get returns the previously-Put string for `hash`, or ok=false if
	// the key is absent (cache miss — the BPF side evicted or this is a
	// cold start).
	Get(hash uint64) (string, bool)
	// Put records a hash→string mapping. Called for every full-string
	// tag (TypeStr, TypeResource(), TypeSource(), TypeCurrentDir()) so future
	// TypeStrRef tags can resolve.
	Put(hash uint64, value string)
}

// Decoder parses raw ringbuf bytes into Frames, resolving any embedded
// TypeStrRef tags against a shared hash cache. Decode is safe for
// concurrent use by multiple goroutines — the multi-pump sensor relies
// on this so the crit and bulk rings can share a single decoder (+ the
// shared strCache) for consistent TypeStrRef resolution across rings.
type Decoder struct {
	cache StrCache
	// resolveMisses counts TypeStrRef tags whose hash wasn't in the
	// cache. Atomic so concurrent Decode calls can increment safely.
	resolveMisses atomic.Uint64

	// cpuMu guards cpuSeqLast / cpuSeqGaps / cpuBases. Held only while
	// the per-CPU trackers mutate — readArg / header decode stay
	// lock-free.
	cpuMu sync.Mutex
	// cpuSeqLast: per-CPU last seen seq. Populated from TypeCPUSeq
	// observations; compared against the next one to detect gaps. A
	// gap of N means N records were dropped for THAT CPU before they
	// made it into user space.
	cpuSeqLast map[uint16]uint64
	// cpuSeqGaps is the cumulative sum of per-CPU seq gaps seen so far.
	// Surfaced on /metrics via PerCPUDrops.
	cpuSeqGaps uint64
	// cpuBases mirrors the BPF kl_cpu_base map: every full frame
	// refreshes the CPU's base entry with the task-identifying fields.
	// Compact frames lack those fields on the wire; Decode overlays
	// them from this mirror. Populated by full-frame decodes;
	// compactOrphans counts compact frames received before a base
	// mirror exists (agent startup window, ringbuf desync).
	cpuBases       map[uint16]Event
	compactOrphans uint64
}

// NewDecoder returns a Decoder that resolves TypeStrRef tags through the
// given cache. A nil cache is allowed — TypeStrRef will then resolve to a
// synthetic placeholder and increment the miss counter.
func NewDecoder(cache StrCache) *Decoder {
	return &Decoder{
		cache:      cache,
		cpuSeqLast: map[uint16]uint64{},
		cpuBases:   map[uint16]Event{},
	}
}

// Decode parses one BPF ringbuf record. Byte 0 of the payload is the
// wire event_type: EventTypeCompactUnary (0x13) dispatches to the
// compact-frame reader, which overlays the per-CPU base mirror to
// reconstruct the full Event. Any other value decodes as a full-frame
// 72-byte header.
func (d *Decoder) Decode(raw []byte) (Frame, error) {
	if len(raw) > 0 && raw[0] == EventTypeCompactUnary {
		return d.decodeCompact(raw)
	}
	r := bytes.NewReader(raw)
	hdr, err := ReadEvent(r)
	if err != nil {
		return Frame{}, err
	}
	args, cpuSeq, sawSeq, err := readArgsTracked(r, hdr.ArgNum, d, nil, nil)
	if sawSeq {
		d.observeCPUSeq(hdr.CPUID, cpuSeq)
	}
	// Refresh the per-CPU base mirror from every full frame so
	// subsequent compact frames on the same CPU can reconstruct.
	d.cpuMu.Lock()
	d.cpuBases[hdr.CPUID] = hdr
	d.cpuMu.Unlock()
	if err != nil {
		return Frame{Header: hdr, Args: args}, nil
	}
	return Frame{Header: hdr, Args: args}, nil
}

// decodeCompact reads a 16-byte compact_event_t header, looks up the
// per-CPU base anchor, and synthesizes a full Event by overlaying the
// base's task-identifying fields with the compact header's syscall_id,
// retval, cpu_id, arg_num, and absolute timestamp (base.Timestamp +
// compact.TsDeltaNs()). Frames that arrive before the first base refresh
// on their CPU are counted as orphans and returned as an error — the
// caller treats them as desync and drops them.
func (d *Decoder) decodeCompact(raw []byte) (Frame, error) {
	r := bytes.NewReader(raw)
	ch, err := ReadCompactHeader(r)
	if err != nil {
		return Frame{}, err
	}
	d.cpuMu.Lock()
	base, ok := d.cpuBases[ch.CPUID]
	if !ok {
		d.compactOrphans++
		d.cpuMu.Unlock()
		return Frame{}, fmt.Errorf("compact frame on cpu %d before base refresh", ch.CPUID)
	}
	// Promote base + compact delta back into a full Event.
	hdr := base
	hdr.EventType = EventTypeUnary
	hdr.ArgNum = ch.ArgNum
	hdr.CPUID = ch.CPUID
	hdr.SyscallID = ch.SyscallID
	hdr.RetVal = ch.RetVal
	hdr.Timestamp = base.Timestamp + uint64(ch.TsDeltaNs)
	// Advance the mirror's timestamp so subsequent compact frames
	// delta against the freshest anchor, matching BPF kl_try_fill_compact.
	base.Timestamp = hdr.Timestamp
	d.cpuBases[ch.CPUID] = base
	d.cpuMu.Unlock()

	args, cpuSeq, sawSeq, err := readArgsTracked(r, ch.ArgNum, d, nil, nil)
	if sawSeq {
		d.observeCPUSeq(ch.CPUID, cpuSeq)
	}
	if err != nil {
		return Frame{Header: hdr, Args: args}, nil
	}
	return Frame{Header: hdr, Args: args}, nil
}

// CompactOrphans returns the cumulative count of compact frames seen
// before a per-CPU base was known. Non-zero at steady state points at a
// ringbuf reader that lost sync with the BPF side; typically harmless
// during the first few milliseconds after attach.
func (d *Decoder) CompactOrphans() uint64 {
	d.cpuMu.Lock()
	defer d.cpuMu.Unlock()
	return d.compactOrphans
}

// observeCPUSeq updates the per-CPU sequence tracker. Gaps contribute to
// the PerCPUDrops counter. The first observation on a CPU sets the
// baseline; subsequent ones compute delta = seq - prev - 1 as the drop
// count (zero when seqs are contiguous).
func (d *Decoder) observeCPUSeq(cpuID uint16, seq uint64) {
	d.cpuMu.Lock()
	defer d.cpuMu.Unlock()
	if d.cpuSeqLast == nil {
		d.cpuSeqLast = map[uint16]uint64{}
	}
	prev, known := d.cpuSeqLast[cpuID]
	d.cpuSeqLast[cpuID] = seq
	if !known || seq <= prev {
		// First sighting for this CPU, or a counter reset (agent
		// restart without BPF reload). Don't attribute a gap.
		return
	}
	if seq-prev > 1 {
		d.cpuSeqGaps += seq - prev - 1
	}
}

// ResolveMisses returns the count of TypeStrRef tags seen so far whose
// hash didn't resolve in the cache. Test-friendly accessor; in production
// this feeds a Prometheus counter.
func (d *Decoder) ResolveMisses() uint64 { return d.resolveMisses.Load() }

// PerCPUDrops returns the cumulative count of per-CPU sequence gaps the
// decoder has observed. A non-zero value means records were lost for
// some CPU; combine with the kernel-side kl_rb_drops counter for a
// complete picture of observation loss.
func (d *Decoder) PerCPUDrops() uint64 {
	d.cpuMu.Lock()
	defer d.cpuMu.Unlock()
	return d.cpuSeqGaps
}

// readArg is the cache-aware variant of ReadArg used by the Decoder.
// Passing d==nil degrades TypeStrRef into a synthetic "(unresolved)"
// string so test fixtures don't need a cache wired up.
func readArg(r io.Reader, d *Decoder) (any, error) {
	tag, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	switch tag {
	case TypeInt:
		return readInt32(r)
	case TypeUInt:
		return readUint32(r)
	case TypeULong:
		return readUint64(r)
	case TypeStr, TypeSource, TypeCurrentDir:
		s, err := readString(r)
		if err != nil {
			return s, err
		}
		// Populate the cache even for non-Resource tags so ARG_STR_REFs
		// produced by future hooks (that may intern other tag types)
		// resolve correctly. The BPF side currently only hashes
		// ARG_RESOURCE; this is forward-compatible.
		if d != nil && d.cache != nil && s != "" {
			d.cache.Put(hashStr(s), s)
		}
		return s, nil
	case TypeResource:
		s, err := readString(r)
		if err != nil {
			return s, err
		}
		if d != nil && d.cache != nil && s != "" {
			d.cache.Put(hashStr(s), s)
		}
		return s, nil
	case TypeStrArr:
		return readStringArray(r)
	case TypeStrRef:
		h, err := readUint64(r)
		if err != nil {
			return nil, err
		}
		if d == nil || d.cache == nil {
			if d != nil {
				d.resolveMisses.Add(1)
			}
			return "", nil
		}
		if s, ok := d.cache.Get(h); ok {
			return s, nil
		}
		d.resolveMisses.Add(1)
		return "", nil
	case TypeCoalescedCount:
		return readUint32(r)
	case TypeCoalescedBytes:
		return readUint64(r)
	case TypeVarintU32:
		v, err := readVarint(r, 5)
		if err != nil {
			return nil, err
		}
		return uint32(v), nil // #nosec G115 -- readVarint(r, 5) caps at 5 bytes = 35 bits; callers use this only for uint32 fields
	case TypeVarintU64:
		return readVarint(r, 10)
	case TypeCPUSeq:
		// Decoded as a tagged sentinel type so readArgs can strip it
		// from the returned Args slice and forward the value to the
		// Decoder's per-CPU tracker. Hook-specific mapping code never
		// has to know about the seq tag.
		v, err := readVarint(r, 10)
		if err != nil {
			return nil, err
		}
		return cpuSeqValue(v), nil
	default:
		return nil, fmt.Errorf("%w: 0x%x", ErrUnknownArgType, tag)
	}
}

// cpuSeqValue is the sentinel type returned by readArg for TypeCPUSeq.
// readArgs strips it before returning the caller-visible Args; the value
// is forwarded to the Decoder's per-CPU tracker keyed on the header's
// CPUID. Keeping the type unexported prevents hook code from depending
// on the seq tag.
type cpuSeqValue uint64

func readArgs(r io.Reader, argNum int8, d *Decoder) ([]any, error) {
	args, _, _, err := readArgsTracked(r, argNum, d, nil, nil)
	return args, err
}

// readArgsTracked is the Decoder.Decode-facing variant that routes the
// ARG_CPU_SEQ tag into per-call outputs (seqOut, sawOut) rather than
// touching Decoder state. This keeps multi-goroutine Decode calls from
// stepping on each other's seq observations without a per-call lock.
func readArgsTracked(r io.Reader, argNum int8, d *Decoder, seqOut *uint64, sawOut *bool) ([]any, uint64, bool, error) {
	if argNum <= 0 {
		return nil, 0, false, nil
	}
	out := make([]any, 0, argNum)
	var seq uint64
	var saw bool
	for i := range int(argNum) {
		a, err := readArg(r, d)
		if err != nil {
			if seqOut != nil {
				*seqOut = seq
				*sawOut = saw
			}
			return out, seq, saw, fmt.Errorf("arg %d: %w", i, err)
		}
		if a == nil {
			break
		}
		// Filter out the per-CPU sequence sentinel so it never leaks
		// into the hook-specific arg slice. It still counts toward the
		// advertised ArgNum (BPF's kl_submit_to bumps arg_num when it
		// appends ARG_CPU_SEQ). The caller (Decoder.Decode()) forwards
		// the value to the per-CPU tracker.
		if v, ok := a.(cpuSeqValue); ok {
			seq = uint64(v)
			saw = true
			continue
		}
		out = append(out, a)
	}
	if seqOut != nil {
		*seqOut = seq
		*sawOut = saw
	}
	return out, seq, saw, nil
}

// HashString computes the fnv1a-64 hash the wire format uses as the key
// for TypeStrRef resolution. Exposed because the hash is part of the BPF↔
// userspace contract — callers building fixtures or external resolvers
// need to produce the same value the BPF side does. The algorithm must
// stay byte-identical to kl_fnv1a_buf in bpf/helpers.bpf.h (same offset
// basis, FNV_prime(), 256-byte cap); a divergence silently makes TypeStrRef
// tags unresolvable.
func HashString(s string) uint64 {
	const (
		offsetBasis uint64 = 0xcbf29ce484222325
		fnvPrime    uint64 = 0x100000001b3
	)
	h := offsetBasis
	n := min(len(s), 256)
	for i := range n {
		h ^= uint64(s[i])
		h *= fnvPrime
	}
	return h
}

// hashStr is the package-internal alias kept so existing call sites don't
// churn. New code should use HashString directly.
func hashStr(s string) uint64 { return HashString(s) }

// readVarint decodes a LEB128 unsigned integer, rejecting payloads longer
// than maxBytes (5 for u32, 10 for u64). Must stay byte-compatible with
// kl_put_varint_u{32,64} in bpf/helpers.bpf.h — both sides use continuation-
// bit LEB128 with the low 7 bits of each byte as payload, little-endian.
func readVarint(r io.Reader, maxBytes int) (uint64, error) {
	var v uint64
	var shift uint
	var one [1]byte
	for range maxBytes {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return 0, err
		}
		b := one[0]
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, nil
		}
		shift += 7
	}
	return 0, ErrVarintTooLong
}

// EncodeVarint writes the LEB128 encoding of `v` to `buf`, returning it in
// the slice layout the BPF side produces. Exposed so test fixtures and
// replay tools can construct varint payloads without duplicating the
// continuation-bit loop.
func EncodeVarint(buf []byte, v uint64) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(buf, b)
		}
		buf = append(buf, b|0x80)
	}
}

func readInt32(r io.Reader) (int32, error) {
	var v int32
	err := binary.Read(r, binary.LittleEndian, &v)
	return v, err
}

func readUint32(r io.Reader) (uint32, error) {
	var v uint32
	err := binary.Read(r, binary.LittleEndian, &v)
	return v, err
}

func readUint64(r io.Reader) (uint64, error) {
	var v uint64
	err := binary.Read(r, binary.LittleEndian, &v)
	return v, err
}

func readString(r io.Reader) (string, error) {
	n, err := readUint32(r)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	if n > 2048 {
		return "", ErrStringTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	// Trim trailing NUL bytes BPF left behind.
	last := len(buf) - 1
	for last >= 0 && buf[last] == 0 {
		last--
	}
	return string(buf[:last+1]), nil
}

func readStringArray(r io.Reader) ([]string, error) {
	var out []string
	for {
		tag, err := readUint32(r)
		if err != nil {
			return nil, err
		}
		if tag == 0 {
			return out, nil
		}
		s, err := readString(r)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
}
