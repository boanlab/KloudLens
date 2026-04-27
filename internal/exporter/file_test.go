// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package exporter

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boanlab/kloudlens/pkg/types"
)

func TestFileSinkShardsAndRotates(t *testing.T) {
	dir := t.TempDir()
	c, err := OpenFileSink(FileOptions{Dir: dir, Shards: 2, MaxBytes: 256, RetainFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		c.Submit(types.IntentEvent{
			IntentID:   string(rune('a' + i)),
			Kind:       "FileRead",
			Attributes: map[string]string{"path": "/etc/x"},
		})
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// at least 2 shards exist — and rotations may have kicked in.
	files, _ := filepath.Glob(filepath.Join(dir, "shard-*.ndjson"))
	if len(files) < 2 {
		t.Fatalf("got %d files, expected >= 2", len(files))
	}
	// every line should be valid JSON with the IntentEvent fields.
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		s := bufio.NewScanner(fh)
		for s.Scan() {
			var got types.IntentEvent
			if err := json.Unmarshal(s.Bytes(), &got); err != nil {
				t.Errorf("%s: %v (line %q)", f, err, s.Text())
			}
			if got.Kind != "FileRead" {
				t.Errorf("kind = %q", got.Kind)
			}
		}
		_ = fh.Close()
	}
	sent, _ := c.Stats()
	if sent != 10 {
		t.Errorf("sent = %d, want 10", sent)
	}
}

func TestFileSinkShardingIsStable(t *testing.T) {
	// Call twice and capture — can't compare the two calls in one expression
	// without tripping staticcheck SA4000 (identical operands).
	a := pickShard("abc", 4)
	b := pickShard("abc", 4)
	if a != b {
		t.Fatal("pickShard should be deterministic")
	}
	counts := map[int]int{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		counts[pickShard(id, 4)]++
	}
	if len(counts) < 2 {
		t.Fatalf("distribution too narrow: %v", counts)
	}
}

func TestFileSinkStripsEmptyDir(t *testing.T) {
	if _, err := OpenFileSink(FileOptions{}); err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestFileSinkJSONLMatchesInput(t *testing.T) {
	dir := t.TempDir()
	c, _ := OpenFileSink(FileOptions{Dir: dir, Shards: 1})
	c.Submit(types.IntentEvent{IntentID: "zz", Kind: "FileWrite", Attributes: map[string]string{"path": "/x"}})
	_ = c.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "shard-*.ndjson"))
	if len(files) != 1 {
		t.Fatalf("got %d files", len(files))
	}
	data, _ := os.ReadFile(files[0])
	if !strings.Contains(string(data), `"kind":"FileWrite"`) {
		t.Errorf("missing kind in %q", data)
	}
}
