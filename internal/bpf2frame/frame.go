// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package bpf2frame

// Frame is a single pre-decoded ring-buffer record. Tests emit these
// directly; the live eBPF reader produces them from ringbuf.Record.RawSample.
type Frame struct {
	Header Event
	Args   []any
}

// DecodeFrame parses one raw BPF ringbuf record byte-slice into a Frame.
// Uses a cacheless Decoder — fine for fixtures that don't contain
// TypeStrRef tags (every existing test). The live reader constructs a
// Decoder with a real cache and calls Decoder.Decode directly.
func DecodeFrame(raw []byte) (Frame, error) {
	return NewDecoder(nil).Decode(raw)
}
