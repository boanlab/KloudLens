// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package frametest exposes raw-frame builders used by unit tests across
// the sensor and bpf2frame packages. It must not be imported by production
// code — the helpers write hand-assembled BPF wire bytes and only make
// sense in fixture-driven tests.
package frametest

import (
	"bytes"
	"encoding/binary"

	"github.com/boanlab/kloudlens/internal/bpf2frame"
)

// Header serializes a bpf2frame.Event header for test fixtures in the exact
// byte order the live BPF program emits.
func Header(buf *bytes.Buffer, e bpf2frame.Event) {
	if err := binary.Write(buf, binary.LittleEndian, &e); err != nil {
		panic(err)
	}
}

func writeUint32(buf *bytes.Buffer, v uint32) {
	_ = binary.Write(buf, binary.LittleEndian, v)
}

// ResourceArg appends a TypeResource/string arg matching how the BPF side
// encodes path-style arguments (tag, length-prefixed payload, NUL terminator).
func ResourceArg(buf *bytes.Buffer, s string) {
	writeUint32(buf, bpf2frame.TypeResource)
	writeUint32(buf, uint32(len(s)+1)) // #nosec G115 -- test helper, length is bounded by the caller-supplied string
	buf.WriteString(s)
	buf.WriteByte(0)
}

// SourceArg appends the trailing TypeSource comm/exe string that every BPF
// frame ends with.
func SourceArg(buf *bytes.Buffer, s string) {
	writeUint32(buf, bpf2frame.TypeSource)
	writeUint32(buf, uint32(len(s)+1)) // #nosec G115 -- test helper, length is bounded by the caller-supplied string
	buf.WriteString(s)
	buf.WriteByte(0)
}

// StrArrArg appends a TypeStrArr outer tag followed by per-item TypeStr
// records and the zero terminator the decoder expects.
func StrArrArg(buf *bytes.Buffer, ss []string) {
	writeUint32(buf, bpf2frame.TypeStrArr)
	for _, s := range ss {
		writeUint32(buf, bpf2frame.TypeStr)
		writeUint32(buf, uint32(len(s)+1)) // #nosec G115 -- test helper, length is bounded by the caller-supplied string
		buf.WriteString(s)
		buf.WriteByte(0)
	}
	writeUint32(buf, 0)
}
