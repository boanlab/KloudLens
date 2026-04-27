// SPDX-License-Identifier: Apache-2.0

package interning

import (
	"sync"
	"testing"
	"time"
)

func TestInternSameStringStableID(t *testing.T) {
	in := New(Config{})
	id1, firstDef := in.Intern("/usr/bin/bash")
	if !firstDef {
		t.Fatal("first intern should mark isNewDef")
	}
	id2, secondDef := in.Intern("/usr/bin/bash")
	if id1 != id2 {
		t.Fatalf("stable id expected: %d vs %d", id1, id2)
	}
	if secondDef {
		t.Fatal("second intern should not emit def")
	}
	// Drain the def channel
	select {
	case d := <-in.Definitions():
		if d.ID != id1 || d.Value != "/usr/bin/bash" {
			t.Fatalf("def mismatch: %+v", d)
		}
	default:
		t.Fatal("expected definition event")
	}
}

func TestInternMultipleStringsHaveDistinctIDs(t *testing.T) {
	in := New(Config{})
	ids := map[uint32]string{}
	for _, s := range []string{"/a", "/b", "/c", "pod-xyz", "1.2.3.4:443"} {
		id, _ := in.Intern(s)
		if id == 0 {
			t.Fatalf("collision flagged for clean input %q", s)
		}
		if prior, ok := ids[id]; ok {
			t.Fatalf("id %d reused for %q and %q", id, prior, s)
		}
		ids[id] = s
	}
	// Drain definitions
	for range ids {
		<-in.Definitions()
	}
}

func TestInternEmptyStringYieldsZero(t *testing.T) {
	in := New(Config{})
	id, _ := in.Intern("")
	if id != 0 {
		t.Fatalf("empty string should return 0 id; got %d", id)
	}
}

func TestPurgeEvictsIdleEntries(t *testing.T) {
	var current time.Time
	in := New(Config{TTL: 1 * time.Second, Clock: func() time.Time { return current }})
	current = time.Unix(100, 0)
	in.Intern("x")
	current = time.Unix(102, 0) // 2s later
	n := in.Purge()
	if n != 1 {
		t.Fatalf("expected 1 purged, got %d", n)
	}
	// After purge, reintern produces a new definition.
	id, isNew := in.Intern("x")
	if id == 0 || !isNew {
		t.Fatalf("expected reintern after purge; got id=%d isNew=%v", id, isNew)
	}
}

func TestMetricsHitMissCount(t *testing.T) {
	in := New(Config{})
	in.Intern("a")
	in.Intern("a")
	in.Intern("b")
	m := in.Metrics()
	// misses = 2 initial unique, hits = 1 repeat
	if m.Misses != 2 {
		t.Fatalf("misses=%d", m.Misses)
	}
	if m.Hits != 1 {
		t.Fatalf("hits=%d", m.Hits)
	}
	if m.Size != 2 {
		t.Fatalf("size=%d", m.Size)
	}
}

func TestConcurrentInternUnique(t *testing.T) {
	in := New(Config{DefChan: make(chan Definition, 4096)})
	var wg sync.WaitGroup
	ids := sync.Map{}
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 64; i++ {
				s := "s-" + itoa(g*1000+i)
				id, _ := in.Intern(s)
				if id == 0 {
					t.Errorf("unexpected collision for %q", s)
					return
				}
				if prev, loaded := ids.LoadOrStore(id, s); loaded && prev.(string) != s {
					t.Errorf("id reused: %d → %q then %q", id, prev, s)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestDefinitionDropWhenChannelBacklogs(t *testing.T) {
	// channel cap=0 guarantees the first send drops.
	in := New(Config{DefChan: make(chan Definition)})
	id, isNew := in.Intern("abc")
	if id != 0 || isNew {
		t.Fatalf("expected drop (id=0, isNew=false), got id=%d isNew=%v", id, isNew)
	}
	// Next call should re-attempt since we rolled back.
	sink := make(chan Definition, 1)
	in2 := New(Config{DefChan: sink})
	id2, isNew2 := in2.Intern("abc")
	if id2 == 0 || !isNew2 {
		t.Fatal("with capacity should produce definition")
	}
	if (<-sink).Value != "abc" {
		t.Fatal("def content")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
