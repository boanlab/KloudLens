// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"
)

func TestUUIDv7Shape(t *testing.T) {
	id := UUIDv7()
	if len(id) != 36 {
		t.Fatalf("len=%d id=%s", len(id), id)
	}
	parts := strings.Split(id, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		t.Fatalf("bad segmentation: %s", id)
	}
	// Version nibble is the first char of parts[2].
	if parts[2][0] != '7' {
		t.Fatalf("not v7: %s", id)
	}
	// Variant: first byte of parts[3] high nibble ∈ {8,9,a,b}
	if !strings.ContainsRune("89ab", rune(parts[3][0])) {
		t.Fatalf("bad variant: %s", id)
	}
	// All-hex check
	raw := strings.ReplaceAll(id, "-", "")
	if _, err := hex.DecodeString(raw); err != nil {
		t.Fatalf("not hex: %v", err)
	}
}

func TestUUIDv7Unique(t *testing.T) {
	seen := make(map[string]bool, 2048)
	for i := range 2048 {
		id := UUIDv7()
		if seen[id] {
			t.Fatalf("duplicate %s at %d", id, i)
		}
		seen[id] = true
	}
}

func TestUUIDv7Monotonic(t *testing.T) {
	prev := UUIDv7()
	for range 8000 {
		cur := UUIDv7()
		if cur <= prev {
			t.Fatalf("not monotonic: prev=%s cur=%s", prev, cur)
		}
		prev = cur
	}
}

func TestUUIDv7Concurrent(t *testing.T) {
	const goroutines = 8
	const each = 256
	results := make(chan string, goroutines*each)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				results <- UUIDv7()
			}
		}()
	}
	wg.Wait()
	close(results)
	seen := make(map[string]bool)
	for id := range results {
		if seen[id] {
			t.Fatalf("duplicate id %s under concurrency", id)
		}
		seen[id] = true
	}
}
