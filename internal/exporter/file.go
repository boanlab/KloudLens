// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package exporter

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// FileOptions tunes the per-worker sharded NDJSON file sink (plan
// "File (sharded)" — Fluent Bit / Vector sidecar path).
type FileOptions struct {
	Dir         string // directory to shard under
	Shards      int    // number of active files
	MaxBytes    int64  // rotate when current file exceeds this size
	RetainFiles int    // keep this many rotated files per shard (LRU)
	BufSize     int    // bufio buffer size per shard
	Sync        bool   // fsync on every Flush
}

// FileClient writes IntentEvents as newline-delimited JSON into a set of
// sharded files. intent_id % shards decides which shard — stable mapping
// so downstream readers see a consistent partition.
type FileClient struct {
	opts    FileOptions
	shards  []*fileShard
	sent    atomic.Uint64
	mu      sync.Mutex
	lastErr error
}

type fileShard struct {
	mu      sync.Mutex
	dir     string
	idx     int
	file    *os.File
	w       *bufio.Writer
	written int64
	opts    *FileOptions
}

// OpenFileSink creates `Shards` NDJSON files under Dir.
func OpenFileSink(opts FileOptions) (*FileClient, error) {
	if opts.Dir == "" {
		return nil, errors.New("file sink: empty dir")
	}
	if opts.Shards <= 0 {
		opts.Shards = 4
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 128 << 20 // 128 MB
	}
	if opts.RetainFiles <= 0 {
		opts.RetainFiles = 4
	}
	if opts.BufSize <= 0 {
		opts.BufSize = 64 << 10
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, err
	}
	c := &FileClient{opts: opts, shards: make([]*fileShard, opts.Shards)}
	for i := 0; i < opts.Shards; i++ {
		s := &fileShard{dir: opts.Dir, idx: i, opts: &c.opts}
		if err := s.rotate(); err != nil {
			return nil, err
		}
		c.shards[i] = s
	}
	return c, nil
}

// Submit writes the event to its shard's current file.
func (c *FileClient) Submit(e types.IntentEvent) {
	line, err := json.Marshal(e)
	if err != nil {
		c.setErr(err)
		return
	}
	shard := c.shards[pickShard(e.IntentID, len(c.shards))]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.written+int64(len(line))+1 > c.opts.MaxBytes {
		if err := shard.rotate(); err != nil {
			c.setErr(err)
			return
		}
	}
	if _, err := shard.w.Write(line); err != nil {
		c.setErr(err)
		return
	}
	if err := shard.w.WriteByte('\n'); err != nil {
		c.setErr(err)
		return
	}
	shard.written += int64(len(line)) + 1
	c.sent.Add(1)
}

// Close flushes and closes all shards.
func (c *FileClient) Close() error {
	var firstErr error
	for _, s := range c.shards {
		s.mu.Lock()
		if s.w != nil {
			if err := s.w.Flush(); err != nil && firstErr == nil {
				firstErr = err
			}
			if c.opts.Sync {
				_ = s.file.Sync()
			}
			if err := s.file.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
			s.w = nil
			s.file = nil
		}
		s.mu.Unlock()
	}
	return firstErr
}

// Stats returns (sent, lastErr).
func (c *FileClient) Stats() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent.Load(), c.lastErr
}

func (c *FileClient) setErr(err error) {
	c.mu.Lock()
	c.lastErr = err
	c.mu.Unlock()
}

func (s *fileShard) rotate() error {
	if s.w != nil {
		_ = s.w.Flush()
	}
	if s.file != nil {
		_ = s.file.Close()
	}
	ts := time.Now().UTC().Format("20060102T150405.000000000")
	name := fmt.Sprintf("shard-%02d-%s.ndjson", s.idx, ts)
	p := filepath.Join(s.dir, name)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- p is derived from s.dir (operator-configured) + a shard filename we just generated
	if err != nil {
		return err
	}
	s.file = f
	s.w = bufio.NewWriterSize(f, s.opts.BufSize)
	s.written = 0
	return s.cleanup()
}

// cleanup keeps the newest `RetainFiles` rotated files for this shard.
func (s *fileShard) cleanup() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	prefix := fmt.Sprintf("shard-%02d-", s.idx)
	var matches []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); len(n) >= len(prefix) && n[:len(prefix)] == prefix {
			matches = append(matches, n)
		}
	}
	if len(matches) <= s.opts.RetainFiles {
		return nil
	}
	// newest by name (timestamp in filename) — trim the oldest.
	// ReadDir returns sorted; manual stable sort not required.
	drop := matches[:len(matches)-s.opts.RetainFiles]
	for _, n := range drop {
		_ = os.Remove(filepath.Join(s.dir, n))
	}
	return nil
}

func pickShard(id string, n int) int {
	if n <= 1 {
		return 0
	}
	var h uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= 16777619
	}
	return int(h % uint32(n)) // #nosec G115 -- n is the shard count, configured ≤ 256
}
