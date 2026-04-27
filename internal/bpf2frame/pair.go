// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package bpf2frame

import (
	"sync"
	"sync/atomic"

	"github.com/boanlab/kloudlens/pkg/types"
)

// Pairer merges split BPF ENTER/EXIT tracepoint frames back into a single
// mapped event. The BPF side fires sys_enter_* with the syscall arguments
// (path, flags, addr, …) but RetVal=0, then sys_exit_* with the resolved
// RetVal (fd / -errno) but no args. The aggregator needs both halves to
// correlate an open with its fd, so we stash the ENTER frame keyed by
// (HostTID, SyscallID()) and fold in the EXIT RetVal when it arrives.
//
// Frames that are already self-contained (UNARY, or EXIT carrying its own
// args because the caller pre-merged — e.g. unit tests, replay fixtures)
// pass through untouched so existing tests keep working.
type Pairer struct {
	mu      sync.Mutex
	pending map[int64]pendingFrame
	maxSize int
	evicted atomic.Uint64
}

type pendingFrame struct {
	hdr  Event
	args []any
}

// NewPairer returns a Pairer with a default 64K slot cap. When the cap is
// exceeded the oldest-looking half is dropped (pseudo-random via map order)
// so a thread that gets killed between enter and exit can't leak memory
// indefinitely.
func NewPairer() *Pairer {
	return &Pairer{pending: map[int64]pendingFrame{}, maxSize: 65536}
}

// Merge consumes one decoded frame and returns the SyscallEvent it produces,
// along with ok=true if an event should be dispatched. ENTER frames stash
// silently (ok=false); EXIT frames pop their partner and dispatch the merged
// result; UNARY frames dispatch directly.
func (p *Pairer) Merge(hdr Event, args []any) (types.SyscallEvent, bool) {
	switch hdr.EventType {
	case EventTypeEnter:
		// Opportunistic pairing: only stash frames that actually carry args.
		// An ENTER with no args gives us nothing the EXIT doesn't already
		// have, so we skip stashing (keeps the pending map small).
		if len(args) == 0 {
			return types.SyscallEvent{}, false
		}
		key := int64(hdr.HostTID)<<32 | int64(hdr.SyscallID)
		p.mu.Lock()
		if len(p.pending) >= p.maxSize {
			// Drop one arbitrary entry to make room. Long-lived threads
			// that never EXIT eventually evict.
			for k := range p.pending {
				delete(p.pending, k)
				break
			}
			p.evicted.Add(1)
		}
		p.pending[key] = pendingFrame{hdr: hdr, args: args}
		p.mu.Unlock()
		return types.SyscallEvent{}, false

	case EventTypeExit:
		key := int64(hdr.HostTID)<<32 | int64(hdr.SyscallID)
		p.mu.Lock()
		pf, ok := p.pending[key]
		if ok {
			delete(p.pending, key)
		}
		p.mu.Unlock()
		if !ok {
			// Either the ENTER was dropped on a full ring buffer, or the
			// caller pre-merged the frame (tests, replay). Map directly.
			return Map(hdr, args), true
		}
		// Carry ENTER's args (they hold the path/flags) but take EXIT's
		// RetVal so open→fd, socket→fd all resolve correctly. Keep
		// ENTER's timestamp since that's when the syscall began.
		merged := pf.hdr
		merged.RetVal = hdr.RetVal
		mergedArgs := pf.args
		// Some syscalls (close, other unary forms) carry args on EXIT too;
		// prefer ENTER's args when present, fall back to EXIT's.
		if len(mergedArgs) == 0 {
			mergedArgs = args
		}
		return Map(merged, mergedArgs), true

	default:
		// UNARY or unrecognized — dispatch directly.
		return Map(hdr, args), true
	}
}

// Pending returns the number of stashed ENTER frames awaiting their EXIT.
// Useful for tests and drop-rate metrics.
func (p *Pairer) Pending() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

// Evicted returns the running total of ENTER frames dropped because the
// pending map hit its cap. A rising counter means threads are exiting (or
// being killed) between enter and exit faster than we can pair them —
// typically a BPF ringbuf loss signal rather than a real pairing bug.
func (p *Pairer) Evicted() uint64 {
	return p.evicted.Load()
}
