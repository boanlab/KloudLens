// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build !linux

package sensor

// LiveEBPF returns ErrNotSupported on non-Linux builds so callers can fall
// back to a replay or mock tracer at startup.
func LiveEBPF() (*EBPFSensor, error) { return nil, ErrNotSupported() }

// LiveEBPFWith mirrors the Linux loader signature; non-Linux returns
// ErrNotSupported so callers pick a replay or mock path.
func LiveEBPFWith(LiveOptions) (*EBPFSensor, error) { return nil, ErrNotSupported() }
