// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/boanlab/kloudlens/internal/downgrade"
	"github.com/boanlab/kloudlens/internal/sensor"
)

// usageSource is the narrow slice of pipeline stats the supervisor needs.
// Pipeline.Counters satisfies it. Tests feed scripted usage through a
// stub so the whole sampling-rate map sync can be exercised without an
// ebpf sensor.
type usageSource interface {
	Counters() (syscalls, intents, framesRead, framesDropped uint64, ringbufUsage float64)
}

// bulkSampler is the subset of sensor.EBPFSensor the supervisor pokes
// on each level transition. Satisfied by *sensor.EBPFSensor and the
// fake used in the unit test.
type bulkSampler interface {
	SetBulkSamplingRate(rate uint32) error
}

// runDowngradeSupervisor loops until ctx is done, feeding ringbuf usage
// into ctrl on every tick. On any level transition it pushes the
// matching sampling rate into the sensor's BPF map — CriticalOnly maps
// to sensor.BulkSamplingDropAll so the kernel side actually drops bulk
// events rather than just skipping user-space decode.
//
// logW is the audit destination for level transitions. A nil logW
// silences the log (useful in tests that assert on the sensor side only).
func runDowngradeSupervisor(
	ctx context.Context,
	interval time.Duration,
	ctrl *downgrade.Controller,
	src usageSource,
	sink bulkSampler,
	logW io.Writer,
) {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	applyLevel(ctrl.Level(), sink, logW)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _, _, _, usage := src.Counters()
			changed, tr := ctrl.Observe(usage)
			if !changed {
				continue
			}
			if logW != nil {
				fmt.Fprintf(logW, "kloudlens: downgrade %s→%s (%s)\n", tr.From, tr.To, tr.Reason)
			}
			applyLevel(tr.To, sink, logW)
		}
	}
}

// applyLevel pushes the sampling rate for `lvl` into the sensor. A
// nil sink (dry-run / test without BPF) is a no-op. ErrSamplerUnavailable
// is tolerated — it just means this build isn't running against a real
// map, which is already the case in dev clusters.
func applyLevel(lvl downgrade.Level, sink bulkSampler, logW io.Writer) {
	if sink == nil {
		return
	}
	rate := samplingRateForLevel(lvl)
	err := sink.SetBulkSamplingRate(rate)
	if err == nil || errors.Is(err, sensor.ErrSamplerUnavailable) {
		return
	}
	if logW != nil {
		fmt.Fprintf(logW, "kloudlens: downgrade: sampling_rate=%d failed: %v\n", rate, err)
	}
}

// samplingRateForLevel maps a downgrade.Level to the value the BPF
// sampler map expects. See sensor.SetBulkSamplingRate for the contract.
func samplingRateForLevel(lvl downgrade.Level) uint32 {
	switch lvl {
	case downgrade.LevelNormal:
		return 1
	case downgrade.LevelSampled:
		return 2
	case downgrade.LevelHeavilySampled:
		return 10
	case downgrade.LevelCriticalOnly:
		return sensor.BulkSamplingDropAll
	default:
		return 1
	}
}
