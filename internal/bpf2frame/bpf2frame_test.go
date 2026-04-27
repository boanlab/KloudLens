// SPDX-License-Identifier: Apache-2.0

package bpf2frame

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// frameHeader serializes an Event header for test fixtures.
func frameHeader(buf *bytes.Buffer, e Event) {
	if err := binary.Write(buf, binary.LittleEndian, &e); err != nil {
		panic(err)
	}
}

func writeUint32(buf *bytes.Buffer, v uint32) {
	_ = binary.Write(buf, binary.LittleEndian, v)
}

func writeInt32(buf *bytes.Buffer, v int32) {
	_ = binary.Write(buf, binary.LittleEndian, v)
}

func writeResourceArg(buf *bytes.Buffer, s string) {
	writeUint32(buf, TypeResource)
	writeUint32(buf, uint32(len(s)+1))
	buf.WriteString(s)
	buf.WriteByte(0)
}

func writeSourceArg(buf *bytes.Buffer, s string) {
	writeUint32(buf, TypeSource)
	writeUint32(buf, uint32(len(s)+1))
	buf.WriteString(s)
	buf.WriteByte(0)
}

func writeInt32Arg(buf *bytes.Buffer, v int32) {
	writeUint32(buf, TypeInt)
	writeInt32(buf, v)
}

func writeStrArrArg(buf *bytes.Buffer, ss []string) {
	writeUint32(buf, TypeStrArr) // outer dispatch tag
	for _, s := range ss {
		writeUint32(buf, TypeStr) // per-item tag
		writeUint32(buf, uint32(len(s)+1))
		buf.WriteString(s)
		buf.WriteByte(0)
	}
	writeUint32(buf, 0) // terminator
}

func TestReadEventRoundTrip(t *testing.T) {
	src := Event{
		Timestamp: 123456789, HostPID: 4242, HostTID: 4243, HostPPID: 1,
		PID: 4242, TID: 4243, PPID: 1, UID: 1000, GID: 1000,
		PidNsID: 4026531836, MntNsID: 4026531841,
		SyscallID: 59, CPUID: 0, EventType: EventTypeExit, ArgNum: 0,
	}
	var buf bytes.Buffer
	frameHeader(&buf, src)

	got, err := ReadEvent(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != src {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, src)
	}
}

func TestReadArgsMixedTypes(t *testing.T) {
	var buf bytes.Buffer
	writeResourceArg(&buf, "/usr/bin/python3")
	writeStrArrArg(&buf, []string{"python3", "-c", "print('hi')"})
	writeInt32Arg(&buf, -22)
	writeSourceArg(&buf, "python3")

	args, err := ReadArgs(&buf, 4)
	if err != nil {
		t.Fatalf("ReadArgs: %v", err)
	}
	if len(args) != 4 {
		t.Fatalf("want 4 args, got %d: %v", len(args), args)
	}
	if s, _ := args[0].(string); s != "/usr/bin/python3" {
		t.Errorf("arg0: %v", args[0])
	}
	if ss, _ := args[1].([]string); len(ss) != 3 || ss[0] != "python3" {
		t.Errorf("arg1: %v", args[1])
	}
	if v, _ := args[2].(int32); v != -22 {
		t.Errorf("arg2: %v", args[2])
	}
	if s, _ := args[3].(string); s != "python3" {
		t.Errorf("arg3: %v", args[3])
	}
}

func TestReadArgStringTooLarge(t *testing.T) {
	var buf bytes.Buffer
	writeUint32(&buf, TypeStr)
	writeUint32(&buf, 4096) // over the 2048 cap
	if _, err := ReadArg(&buf); err != ErrStringTooLarge {
		t.Fatalf("want ErrStringTooLarge, got %v", err)
	}
}

func TestReadArgUnknownTag(t *testing.T) {
	var buf bytes.Buffer
	writeUint32(&buf, 999)
	_, err := ReadArg(&buf)
	if err == nil {
		t.Fatal("expected error for unknown tag")
	}
}

func TestReadArgEOF(t *testing.T) {
	var buf bytes.Buffer
	// Partial header (2 bytes instead of 4) → underlying io.ReadFull returns
	// io.ErrUnexpectedEOF; readUint32 surfaces it.
	buf.Write([]byte{0x01, 0x00})
	_, err := ReadArg(&buf)
	if err != io.ErrUnexpectedEOF && err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

// mapCache is an in-test StrCache for round-trip tests.
type mapCache struct{ m map[uint64]string }

func (c *mapCache) Get(h uint64) (string, bool) {
	s, ok := c.m[h]
	return s, ok
}
func (c *mapCache) Put(h uint64, s string) { c.m[h] = s }

func writeStrRefArg(buf *bytes.Buffer, h uint64) {
	writeUint32(buf, TypeStrRef)
	_ = binary.Write(buf, binary.LittleEndian, h)
}

// TestHashStringStableExpected pins a handful of known-good fnv1a-64
// digests. If this test breaks, the BPF-side helper must have diverged —
// chase it in bpf/helpers.bpf.h:kl_fnv1a_buf before "fixing" the Go side.
func TestHashStringStableExpected(t *testing.T) {
	cases := []struct {
		s    string
		want uint64
	}{
		{"", 0xcbf29ce484222325},                 // empty → offset basis
		{"a", 0xaf63dc4c8601ec8c},                // canonical fnv1a-64("a")
		{"foobar", 0x85944171f73967e8},           // canonical fnv1a-64("foobar")
		{"/usr/bin/python3", 0x2213180623f2a486}, // pinned; regen via Go if you change the cap
	}
	for _, tc := range cases {
		if got := HashString(tc.s); got != tc.want {
			t.Errorf("HashString(%q)=0x%x want 0x%x", tc.s, got, tc.want)
		}
	}
}

// TestHashStringCappedAt256 verifies the 256-byte truncation — two strings
// that share a 256-byte prefix must hash identically (matches BPF's
// KL_HASH_MAX_BYTES cap).
func TestHashStringCappedAt256(t *testing.T) {
	prefix := bytes.Repeat([]byte("x"), 256)
	a := string(prefix)                                       // exactly 256 bytes
	b := string(prefix) + "-this-tail-is-ignored-by-the-hash" // 256 + suffix
	if HashString(a) != HashString(b) {
		t.Fatalf("256-byte cap violated: HashString(a)=0x%x HashString(b)=0x%x",
			HashString(a), HashString(b))
	}
}

// TestDecoderResolvesStrRefFromPriorResource covers the happy path:
// a TypeResource arg registers the string in the cache, a later
// TypeStrRef with the same hash resolves back to it.
func TestDecoderResolvesStrRefFromPriorResource(t *testing.T) {
	path := "/etc/passwd"
	h := HashString(path)

	var buf bytes.Buffer
	// Frame 1: exec with a full TypeResource (populates cache).
	frameHeader(&buf, Event{SyscallID: 59, HostPID: 1, ArgNum: 1})
	writeResourceArg(&buf, path)
	frame1 := append([]byte(nil), buf.Bytes()...)
	buf.Reset()

	// Frame 2: a subsequent event references the same path via TypeStrRef.
	frameHeader(&buf, Event{SyscallID: 257, HostPID: 1, ArgNum: 1})
	writeStrRefArg(&buf, h)
	frame2 := append([]byte(nil), buf.Bytes()...)

	d := NewDecoder(&mapCache{m: map[uint64]string{}})
	if _, err := d.Decode(frame1); err != nil {
		t.Fatalf("frame1: %v", err)
	}
	fr, err := d.Decode(frame2)
	if err != nil {
		t.Fatalf("frame2: %v", err)
	}
	if len(fr.Args) != 1 {
		t.Fatalf("want 1 arg on resolved frame, got %d", len(fr.Args))
	}
	if s, _ := fr.Args[0].(string); s != path {
		t.Fatalf("resolved arg: got %q want %q", s, path)
	}
	if m := d.ResolveMisses(); m != 0 {
		t.Fatalf("unexpected resolve misses: %d", m)
	}
}

// TestDecoderStrRefMissIncrementsCounter ensures a TypeStrRef for a hash
// that's never been seen resolves to an empty string and bumps the miss
// counter (so the operator dashboard surfaces cache/kernel divergence).
func TestDecoderStrRefMissIncrementsCounter(t *testing.T) {
	var buf bytes.Buffer
	frameHeader(&buf, Event{SyscallID: 257, HostPID: 1, ArgNum: 1})
	writeStrRefArg(&buf, 0xdeadbeef)
	d := NewDecoder(&mapCache{m: map[uint64]string{}})
	fr, err := d.Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.Args) != 1 {
		t.Fatalf("want 1 arg, got %d", len(fr.Args))
	}
	if s, _ := fr.Args[0].(string); s != "" {
		t.Errorf("unresolved arg should be empty, got %q", s)
	}
	if d.ResolveMisses() != 1 {
		t.Errorf("resolve miss counter: got %d want 1", d.ResolveMisses())
	}
}

// TestDecoderCoalescedTrailer verifies the two trailer tags round-trip as
// uint32 / uint64 at the tail of an otherwise normal UNARY event.
// The BPF side appends these after the regular args whenever a coalesce
// window just closed; userspace treats them like any other typed arg.
func TestDecoderCoalescedTrailer(t *testing.T) {
	var buf bytes.Buffer
	frameHeader(&buf, Event{SyscallID: 0, HostPID: 1, ArgNum: 4, EventType: EventTypeUnary})
	writeInt32Arg(&buf, 7) // fd
	// count as ARG_ULONG
	writeUint32(&buf, TypeULong)
	_ = binary.Write(&buf, binary.LittleEndian, uint64(4096))
	// ARG_COALESCED_COUNT
	writeUint32(&buf, TypeCoalescedCount)
	writeUint32(&buf, 42)
	// ARG_COALESCED_BYTES
	writeUint32(&buf, TypeCoalescedBytes)
	_ = binary.Write(&buf, binary.LittleEndian, uint64(172032))

	fr, err := DecodeFrame(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.Args) != 4 {
		t.Fatalf("want 4 args, got %d: %v", len(fr.Args), fr.Args)
	}
	if v, _ := fr.Args[2].(uint32); v != 42 {
		t.Errorf("coalesced count: got %v want 42", fr.Args[2])
	}
	if v, _ := fr.Args[3].(uint64); v != 172032 {
		t.Errorf("coalesced bytes: got %v want 172032", fr.Args[3])
	}
}

// TestVarintRoundTrip cross-checks Go EncodeVarint + readVarint over a
// spread of values that exercise every continuation-byte boundary the BPF
// writer hits (1-byte, 2-byte, 5-byte, 10-byte). A mismatch here means the
// LEB128 loop diverged from kl_put_varint_u64 in bpf/helpers.bpf.h.
func TestVarintRoundTrip(t *testing.T) {
	cases := []uint64{
		0, 1, 127, 128, 16383, 16384,
		0xDEADBEEF,         // straddles u32/u64
		0x7FFFFFFFFFFFFFFF, // near-max signed
		0xFFFFFFFFFFFFFFFF, // full u64
	}
	for _, v := range cases {
		enc := EncodeVarint(nil, v)
		got, err := readVarint(bytes.NewReader(enc), 10)
		if err != nil {
			t.Fatalf("v=0x%x decode: %v", v, err)
		}
		if got != v {
			t.Fatalf("v=0x%x roundtrip: got 0x%x (encoded %d bytes)", v, got, len(enc))
		}
	}
}

// TestVarintTooLong ensures a malicious continuation stream is rejected.
func TestVarintTooLong(t *testing.T) {
	// 11 bytes of 0xFF — every byte has the continuation bit set. readVarint
	// must stop at the caller's cap without chasing the tail.
	payload := bytes.Repeat([]byte{0xFF}, 11)
	_, err := readVarint(bytes.NewReader(payload), 10)
	if err != ErrVarintTooLong {
		t.Fatalf("want ErrVarintTooLong, got %v", err)
	}
}

// TestDecoderVarintArgs checks the dispatch path: both TypeVarintU32 and
// TypeVarintU64 decode to their native Go types, preserving semantics so
// consumers don't see a difference versus the fixed-width encodings.
func TestDecoderVarintArgs(t *testing.T) {
	var buf bytes.Buffer
	frameHeader(&buf, Event{SyscallID: 0, HostPID: 1, ArgNum: 2, EventType: EventTypeUnary})
	// TypeVarintU32 = 12, value 500 → 2 bytes LEB128 (0xF4 0x03)
	writeUint32(&buf, TypeVarintU32)
	buf.Write(EncodeVarint(nil, 500))
	// TypeVarintU64 = 13, value 1<<40 → 6 bytes LEB128
	writeUint32(&buf, TypeVarintU64)
	buf.Write(EncodeVarint(nil, 1<<40))

	fr, err := DecodeFrame(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.Args) != 2 {
		t.Fatalf("want 2 args, got %d: %v", len(fr.Args), fr.Args)
	}
	if v, _ := fr.Args[0].(uint32); v != 500 {
		t.Errorf("varint u32: got %v want 500", fr.Args[0])
	}
	if v, _ := fr.Args[1].(uint64); v != 1<<40 {
		t.Errorf("varint u64: got %v want %d", fr.Args[1], uint64(1<<40))
	}
}

// TestDecodeFrameWithoutCacheFallsThrough verifies the cacheless path
// (DecodeFrame) degrades a TypeStrRef into an empty string without panic
// or error — the fixture-driven tests in the rest of the repo rely on
// this when they don't need ref resolution.
func TestDecodeFrameWithoutCacheFallsThrough(t *testing.T) {
	var buf bytes.Buffer
	frameHeader(&buf, Event{SyscallID: 257, HostPID: 1, ArgNum: 1})
	writeStrRefArg(&buf, 0x1)
	fr, err := DecodeFrame(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.Args) != 1 {
		t.Fatalf("want 1 arg, got %d", len(fr.Args))
	}
	if s, _ := fr.Args[0].(string); s != "" {
		t.Errorf("got %q, want empty", s)
	}
}

// TestDecoderCPUSeqTracksPerCPUGaps feeds a sequence of frames with
// ARG_CPU_SEQ values and asserts the Decoder's per-CPU drop counter
// picks up exactly the missing seqs. Tests both intra-CPU gaps and
// independence between CPUs.
func TestDecoderCPUSeqTracksPerCPUGaps(t *testing.T) {
	d := NewDecoder(nil)

	mkFrame := func(cpu uint16, seq uint64) []byte {
		var buf bytes.Buffer
		// ArgNum=1 because only the CPU_SEQ tag is emitted by BPF in
		// the unit case. The real sensor adds hook-specific args
		// before this one, but the decoder only needs to peel the seq.
		frameHeader(&buf, Event{
			SyscallID: 0, HostPID: 1, ArgNum: 1,
			EventType: EventTypeUnary, CPUID: cpu,
		})
		writeUint32(&buf, TypeCPUSeq)
		buf.Write(EncodeVarint(nil, seq))
		return buf.Bytes()
	}

	// CPU 0: contiguous 1,2 → no gap.
	if _, err := d.Decode(mkFrame(0, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decode(mkFrame(0, 2)); err != nil {
		t.Fatal(err)
	}
	if d.PerCPUDrops() != 0 {
		t.Errorf("no drops expected yet, got %d", d.PerCPUDrops())
	}

	// CPU 0: 2 → 5 means seqs 3 and 4 were lost (gap = 2 drops).
	if _, err := d.Decode(mkFrame(0, 5)); err != nil {
		t.Fatal(err)
	}
	if got := d.PerCPUDrops(); got != 2 {
		t.Errorf("drops after CPU0 gap: got %d want 2", got)
	}

	// CPU 1: first sighting → baseline, no drop attribution.
	if _, err := d.Decode(mkFrame(1, 100)); err != nil {
		t.Fatal(err)
	}
	if got := d.PerCPUDrops(); got != 2 {
		t.Errorf("CPU1 baseline should not add drops: got %d", got)
	}

	// CPU 1: 100 → 103 → gap of 2 on CPU 1.
	if _, err := d.Decode(mkFrame(1, 103)); err != nil {
		t.Fatal(err)
	}
	if got := d.PerCPUDrops(); got != 4 {
		t.Errorf("after CPU1 gap, total drops: got %d want 4", got)
	}

	// Out-of-order (seq goes backwards) → treated as counter reset, no drops.
	if _, err := d.Decode(mkFrame(1, 50)); err != nil {
		t.Fatal(err)
	}
	if got := d.PerCPUDrops(); got != 4 {
		t.Errorf("reset should not increment drops: got %d", got)
	}
}

// TestDecoderCPUSeqDoesNotLeakIntoArgs confirms the CPU_SEQ tag is
// stripped before the caller-visible Args slice. Hook-specific consumers
// must not see it.
func TestDecoderCPUSeqDoesNotLeakIntoArgs(t *testing.T) {
	d := NewDecoder(nil)
	var buf bytes.Buffer
	// Two args total: a regular varint, then the CPU_SEQ sentinel.
	frameHeader(&buf, Event{
		SyscallID: 0, HostPID: 1, ArgNum: 2,
		EventType: EventTypeUnary, CPUID: 3,
	})
	writeUint32(&buf, TypeVarintU32)
	buf.Write(EncodeVarint(nil, 42))
	writeUint32(&buf, TypeCPUSeq)
	buf.Write(EncodeVarint(nil, 7))

	fr, err := d.Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.Args) != 1 {
		t.Fatalf("CPU_SEQ must be stripped; got %d args: %+v", len(fr.Args), fr.Args)
	}
	if v, _ := fr.Args[0].(uint32); v != 42 {
		t.Errorf("visible arg wrong: %v", fr.Args[0])
	}
}

// TestDecoderCompactFrameRoundtripsFromBase feeds a full frame (which
// refreshes the per-CPU base), then a compact frame referencing that
// base, and asserts the reconstructed Event carries the base's task
// fields plus the compact header's syscall_id / retval / delta'd ts.
func TestDecoderCompactFrameRoundtripsFromBase(t *testing.T) {
	d := NewDecoder(nil)

	// 1) Full frame on CPU 5 — establishes the base.
	var base bytes.Buffer
	full := Event{
		EventType: EventTypeUnary, ArgNum: 0, CPUID: 5,
		Timestamp: 1_000_000_000,
		PidNsID:   4026531836, MntNsID: 4026532000,
		HostPPID: 1, PPID: 1,
		HostPID: 4242, HostTID: 4242,
		PID: 4242, TID: 4242,
		UID: 1000, GID: 1000,
		SyscallID: 257,
	}
	frameHeader(&base, full)
	if _, err := d.Decode(base.Bytes()); err != nil {
		t.Fatalf("full decode: %v", err)
	}

	// 2) Compact frame on same CPU, delta = 500 µs, syscall_id=0 (read),
	// retval = 64 (bytes read). ArgNum=0 because we emit no hook args.
	var comp bytes.Buffer
	ch := CompactHeader{
		EventType: EventTypeCompactUnary, ArgNum: 0, CPUID: 5,
		TsDeltaNs: 500_000,
		SyscallID: 0,
		RetVal:    64,
	}
	if err := binary.Write(&comp, binary.LittleEndian, ch); err != nil {
		t.Fatal(err)
	}
	fr, err := d.Decode(comp.Bytes())
	if err != nil {
		t.Fatalf("compact decode: %v", err)
	}

	// Reconstructed header carries the BASE task fields + compact header's
	// syscall_id / retval / ts (base + delta).
	if fr.Header.CPUID != 5 || fr.Header.HostPID != 4242 || fr.Header.PidNsID != full.PidNsID {
		t.Errorf("task fields not overlaid from base: %+v", fr.Header)
	}
	if fr.Header.SyscallID != 0 || fr.Header.RetVal != 64 {
		t.Errorf("compact header fields not applied: syscall=%d retval=%d", fr.Header.SyscallID, fr.Header.RetVal)
	}
	if want := full.Timestamp + 500_000; fr.Header.Timestamp != want {
		t.Errorf("ts reconstruction: got %d want %d", fr.Header.Timestamp, want)
	}
	if fr.Header.EventType != EventTypeUnary {
		t.Errorf("compact should promote to UNARY event_type; got %d", fr.Header.EventType)
	}
}

// TestDecoderCompactFrameWithoutBaseIsOrphan asserts a compact frame
// received before any full frame on that CPU is rejected as desync, and
// the orphan counter advances so the condition stays visible on metrics.
func TestDecoderCompactFrameWithoutBaseIsOrphan(t *testing.T) {
	d := NewDecoder(nil)
	var comp bytes.Buffer
	ch := CompactHeader{
		EventType: EventTypeCompactUnary, ArgNum: 0, CPUID: 9,
		TsDeltaNs: 0, SyscallID: 1, RetVal: 0,
	}
	if err := binary.Write(&comp, binary.LittleEndian, ch); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decode(comp.Bytes()); err == nil {
		t.Fatal("compact-before-base should error")
	}
	if got := d.CompactOrphans(); got != 1 {
		t.Errorf("CompactOrphans = %d, want 1", got)
	}
}

// TestDecoderCompactFramesAdvanceBase asserts successive compact frames
// chain: each compact frame's reconstructed timestamp anchors the next
// one's delta, matching the BPF side's base.timestamp bookkeeping.
func TestDecoderCompactFramesAdvanceBase(t *testing.T) {
	d := NewDecoder(nil)
	var full bytes.Buffer
	frameHeader(&full, Event{
		EventType: EventTypeUnary, CPUID: 2,
		Timestamp: 10_000, HostPID: 100, SyscallID: 1,
	})
	if _, err := d.Decode(full.Bytes()); err != nil {
		t.Fatal(err)
	}
	// Three compact frames with delta=100 each — cumulative ts should
	// climb 10_100, 10_200, 10_300.
	for i, wantTS := range []uint64{10_100, 10_200, 10_300} {
		var comp bytes.Buffer
		ch := CompactHeader{
			EventType: EventTypeCompactUnary, CPUID: 2,
			TsDeltaNs: 100, SyscallID: 0, RetVal: int32(i),
		}
		if err := binary.Write(&comp, binary.LittleEndian, ch); err != nil {
			t.Fatal(err)
		}
		fr, err := d.Decode(comp.Bytes())
		if err != nil {
			t.Fatalf("compact %d: %v", i, err)
		}
		if fr.Header.Timestamp != wantTS {
			t.Errorf("compact %d ts = %d, want %d", i, fr.Header.Timestamp, wantTS)
		}
	}
}
