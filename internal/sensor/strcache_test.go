// SPDX-License-Identifier: Apache-2.0

package sensor

import "testing"

// fakeKernelDict is a deterministic in-process stand-in for the BPF
// kl_str_intern map. Lookup hits return the canned (hash, string) pairs
// and bump a call counter so tests can assert the fallback path ran.
type fakeKernelDict struct {
	entries map[uint64]string
	calls   int
}

func (f *fakeKernelDict) Lookup(h uint64) (string, bool) {
	f.calls++
	s, ok := f.entries[h]
	return s, ok
}

func TestStrCacheFallsBackToKernelDict(t *testing.T) {
	c := newStrCache(8)
	kd := &fakeKernelDict{entries: map[uint64]string{0xabc: "/etc/passwd"}}
	c.SetKernelDict(kd)

	// First lookup: local miss → kernelDict hit → result cached.
	s, ok := c.Get(0xabc)
	if !ok || s != "/etc/passwd" {
		t.Fatalf("Get(0xabc) = %q,%v; want /etc/passwd,true", s, ok)
	}
	if kd.calls != 1 {
		t.Errorf("kernelDict calls = %d, want 1", kd.calls)
	}
	hits, _ := c.KernelStats()
	if hits != 1 {
		t.Errorf("kernelHits = %d, want 1", hits)
	}

	// Second lookup: cached locally → no kernelDict call.
	if s2, ok := c.Get(0xabc); !ok || s2 != "/etc/passwd" {
		t.Fatalf("second Get didn't hit local cache: %q,%v", s2, ok)
	}
	if kd.calls != 1 {
		t.Errorf("kernelDict called again after cache hit: %d", kd.calls)
	}
}

func TestStrCacheKernelMissCountsAndReturnsFalse(t *testing.T) {
	c := newStrCache(8)
	kd := &fakeKernelDict{entries: map[uint64]string{}}
	c.SetKernelDict(kd)

	if s, ok := c.Get(0xdeadbeef); ok {
		t.Fatalf("Get should miss: got %q,%v", s, ok)
	}
	_, misses := c.KernelStats()
	if misses != 1 {
		t.Errorf("kernelMisses = %d, want 1", misses)
	}
}

// TestStrCacheFallbackIsOptional confirms the no-kernel-dict path
// works — Get returns false on miss without panicking.
func TestStrCacheFallbackIsOptional(t *testing.T) {
	c := newStrCache(4)
	if _, ok := c.Get(1); ok {
		t.Error("Get should miss when no kernelDict is wired")
	}
	if h, m := c.KernelStats(); h != 0 || m != 0 {
		t.Errorf("kernel stats should stay zero without a wired dict: hits=%d misses=%d", h, m)
	}
}

// TestStrCacheUnsetKernelDict verifies SetKernelDict(nil) unhooks the
// fallback — useful for tests that recycle a cache across scenarios.
func TestStrCacheUnsetKernelDict(t *testing.T) {
	c := newStrCache(4)
	kd := &fakeKernelDict{entries: map[uint64]string{42: "x"}}
	c.SetKernelDict(kd)
	if _, ok := c.Get(42); !ok {
		t.Fatal("expected kernelDict hit")
	}
	c.SetKernelDict(nil)
	// 43 is absent everywhere and the kernelDict is unhooked, so Get
	// must miss without panicking on a nil interface.
	if _, ok := c.Get(43); ok {
		t.Error("unset kernelDict should stop fallback lookups")
	}
}
