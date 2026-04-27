// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package baseline

import (
	"hash/fnv"
	"math"

	"github.com/boanlab/kloudlens/pkg/types"
)

// CountMinSketch is a fixed-memory approximate frequency counter. Estimate(x)
// is ≥ true count but never less (no false negatives). Used by the baseline
// engine for syscall / path rarity scoring
type CountMinSketch struct {
	width uint32
	depth uint32
	rows  [][]uint32
	total uint64
	seeds []uint32
}

// NewCountMinSketch returns a sketch tuned for (eps, delta): width ≈ e/eps,
// depth ≈ ln(1/delta). Pass (0.001, 0.001) for a reasonable default.
func NewCountMinSketch(eps, delta float64) *CountMinSketch {
	if eps <= 0 || eps >= 1 {
		eps = 0.001
	}
	if delta <= 0 || delta >= 1 {
		delta = 0.001
	}
	width := uint32(math.Ceil(math.E / eps))
	depth := uint32(math.Ceil(math.Log(1.0 / delta)))
	return newSketch(width, depth)
}

// NewCountMinSketchDims lets tests pin exact dimensions.
func NewCountMinSketchDims(width, depth uint32) *CountMinSketch {
	return newSketch(width, depth)
}

func newSketch(width, depth uint32) *CountMinSketch {
	if width < 1 {
		width = 1
	}
	if depth < 1 {
		depth = 1
	}
	rows := make([][]uint32, depth)
	for i := range rows {
		rows[i] = make([]uint32, width)
	}
	seeds := make([]uint32, depth)
	for i := uint32(0); i < depth; i++ {
		// Deterministic, orthogonal enough for fnv1a seeding.
		seeds[i] = 0x9E3779B9 + i*0x85EBCA6B
	}
	return &CountMinSketch{width: width, depth: depth, rows: rows, seeds: seeds}
}

// Add increments the count for key.
func (c *CountMinSketch) Add(key string) {
	c.AddN(key, 1)
}

// AddN adds n to the count for key.
func (c *CountMinSketch) AddN(key string, n uint32) {
	if n == 0 {
		return
	}
	c.total += uint64(n)
	for i := uint32(0); i < c.depth; i++ {
		idx := c.hash(key, i) % c.width
		// Saturate rather than wrap on overflow.
		if c.rows[i][idx] > ^uint32(0)-n {
			c.rows[i][idx] = ^uint32(0)
			continue
		}
		c.rows[i][idx] += n
	}
}

// Estimate returns min over all rows of the counter for key.
func (c *CountMinSketch) Estimate(key string) uint32 {
	var min uint32 = ^uint32(0)
	for i := uint32(0); i < c.depth; i++ {
		idx := c.hash(key, i) % c.width
		if c.rows[i][idx] < min {
			min = c.rows[i][idx]
		}
	}
	return min
}

// Total returns the number of Add calls made (exact).
func (c *CountMinSketch) Total() uint64 { return c.total }

// Merge folds `other` into c cell-wise (saturating). Both sketches must share
// the same dims and seeds — `NewCountMinSketch(eps, delta)` with identical
// arguments always produces compatible sketches. Mismatched sketches would
// silently shift hash buckets, so we reject rather than guess.
func (c *CountMinSketch) Merge(other *CountMinSketch) error {
	if other == nil {
		return nil
	}
	if c.width != other.width || c.depth != other.depth {
		return &cmsMergeErr{reason: "dims differ"}
	}
	for i := uint32(0); i < c.depth; i++ {
		if c.seeds[i] != other.seeds[i] {
			return &cmsMergeErr{reason: "seeds differ"}
		}
	}
	for i := uint32(0); i < c.depth; i++ {
		for j := uint32(0); j < c.width; j++ {
			a, b := c.rows[i][j], other.rows[i][j]
			if a > ^uint32(0)-b {
				c.rows[i][j] = ^uint32(0)
				continue
			}
			c.rows[i][j] = a + b
		}
	}
	c.total += other.total
	return nil
}

type cmsMergeErr struct{ reason string }

func (e *cmsMergeErr) Error() string { return "baseline: CMS merge refused — " + e.reason }

// RelativeFrequency returns estimate/total, or 0 when total=0.
func (c *CountMinSketch) RelativeFrequency(key string) float64 {
	if c.total == 0 {
		return 0
	}
	return float64(c.Estimate(key)) / float64(c.total)
}

func (c *CountMinSketch) hash(key string, row uint32) uint32 {
	h := fnv.New32a()
	var seed [4]byte
	s := c.seeds[row]
	seed[0] = types.ByteShift(s, 0)
	seed[1] = types.ByteShift(s, 8)
	seed[2] = types.ByteShift(s, 16)
	seed[3] = types.ByteShift(s, 24)
	_, _ = h.Write(seed[:])
	_, _ = h.Write([]byte(key))
	return h.Sum32()
}
