// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package sensor is the kernel-facing event source. A Sensor emits
// types.SyscallEvent values drawn from eBPF ring buffers (live) or from
// replayed raw bytes (mock / fixture). The package owns only the acquisition
// concern — decoding lives in internal/bpf2frame, routing in internal/frame2intent.
package sensor

import (
	"context"
	"errors"
	"sync"

	"github.com/boanlab/kloudlens/internal/bpf2frame"
	"github.com/boanlab/kloudlens/pkg/types"
)

// Handler is invoked for each fully-decoded SyscallEvent. The ingest bridge
// wraps it to route events into the intent aggregator; tests install their own.
type Handler func(types.SyscallEvent)

// Sensor is the event source abstraction. Production builds wire this to an
// eBPF ring-buffer reader; tests use MockSensor.
type Sensor interface {
	// Start begins producing events. Blocks until ctx is done or Stop is
	// called. Returns non-nil on unrecoverable init failure.
	Start(ctx context.Context, h Handler) error
	// Stop signals the sensor to drain and shut down.
	Stop() error
}

// ErrNotSupported is returned by platform-gated sensors (e.g. eBPF on non-
// Linux) to indicate the caller should pick a different implementation.
var ErrNotSupported = errors.New("sensor: implementation not supported on this platform")

// MockSensor is a drop-in Sensor for unit and integration tests. Push frames
// via Feed, and Start blocks until Stop or ctx cancellation.
type MockSensor struct {
	mu     sync.Mutex
	frames chan bpf2frame.Frame
	done   chan struct{}
	closed bool
	pairer *bpf2frame.Pairer
}

// NewMockSensor returns a fresh mock with an unbounded-ish buffered channel.
func NewMockSensor(bufSize int) *MockSensor {
	if bufSize <= 0 {
		bufSize = 1024
	}
	return &MockSensor{
		frames: make(chan bpf2frame.Frame, bufSize),
		done:   make(chan struct{}),
		pairer: bpf2frame.NewPairer(),
	}
}

// Feed pushes a synthetic frame. Safe to call concurrently with Start.
func (m *MockSensor) Feed(f bpf2frame.Frame) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	select {
	case m.frames <- f:
	default:
		// If the buffer is full we drop; real sensors also drop under
		// pressure and the downgrade package handles the summary path.
	}
}

// Start pumps frames through bpf2frame.Map into the handler. Returns when ctx is
// done or Stop is called.
func (m *MockSensor) Start(ctx context.Context, h Handler) error {
	if h == nil {
		return errors.New("sensor: nil handler")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.done:
			return nil
		case fr, ok := <-m.frames:
			if !ok {
				return nil
			}
			if ev, ok := m.pairer.Merge(fr.Header, fr.Args); ok {
				h(ev)
			}
		}
	}
}

// Stop closes the frame channel and signals Start to return.
func (m *MockSensor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	close(m.done)
	close(m.frames)
	return nil
}
