// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package peers

import "testing"

func TestExactMatchReturnsOwner(t *testing.T) {
	r := NewRegistry()
	r.ObserveBind("10.0.0.5:8080", 100, "cont-server", 1)

	p, ok := r.Lookup("10.0.0.5:8080")
	if !ok {
		t.Fatal("exact bind must resolve")
	}
	if p.ContainerID != "cont-server" || p.PID != 100 {
		t.Errorf("owner = %+v", p)
	}
}

func TestWildcardBindMatchesAnyIPWithSamePort(t *testing.T) {
	r := NewRegistry()
	r.ObserveBind("0.0.0.0:5432", 200, "cont-db", 1)

	for _, dst := range []string{
		"10.0.0.5:5432",
		"127.0.0.1:5432",
		"192.168.1.3:5432",
	} {
		p, ok := r.Lookup(dst)
		if !ok {
			t.Errorf("wildcard lookup %q should resolve", dst)
			continue
		}
		if p.ContainerID != "cont-db" {
			t.Errorf("lookup %q: container = %q", dst, p.ContainerID)
		}
	}

	if _, ok := r.Lookup("10.0.0.5:6543"); ok {
		t.Error("wildcard must not match a different port")
	}
}

func TestExactMatchWinsOverWildcard(t *testing.T) {
	r := NewRegistry()
	// Two containers bind the same port: one wildcard, one specific IP.
	r.ObserveBind("0.0.0.0:9000", 10, "cont-wild", 1)
	r.ObserveBind("10.0.0.5:9000", 20, "cont-specific", 2)

	p, ok := r.Lookup("10.0.0.5:9000")
	if !ok {
		t.Fatal("must resolve")
	}
	if p.ContainerID != "cont-specific" {
		t.Errorf("got %q, want cont-specific (exact wins over wildcard)", p.ContainerID)
	}

	// A different IP still hits the wildcard binding.
	p2, ok := r.Lookup("10.0.0.6:9000")
	if !ok || p2.ContainerID != "cont-wild" {
		t.Errorf("fallback to wildcard failed: ok=%v peer=%+v", ok, p2)
	}
}

func TestObserveExitDropsOwnedEntries(t *testing.T) {
	r := NewRegistry()
	r.ObserveBind("10.0.0.5:8080", 100, "cont-a", 1)
	r.ObserveBind("10.0.0.5:8081", 100, "cont-a", 2)
	r.ObserveBind("0.0.0.0:9000", 200, "cont-b", 3)
	if r.Size() != 3 {
		t.Fatalf("pre-exit size = %d, want 3", r.Size())
	}

	r.ObserveExit(100)
	if r.Size() != 1 {
		t.Errorf("post-exit size = %d, want 1", r.Size())
	}
	if _, ok := r.Lookup("10.0.0.5:8080"); ok {
		t.Error("entry for exited pid must be gone")
	}
	if _, ok := r.Lookup("127.0.0.1:9000"); !ok {
		t.Error("surviving container entry must still resolve")
	}
}

func TestEmptyAddrIgnored(t *testing.T) {
	r := NewRegistry()
	r.ObserveBind("", 1, "x", 0)
	if r.Size() != 0 {
		t.Error("empty address should be ignored")
	}
	if _, ok := r.Lookup(""); ok {
		t.Error("empty lookup should miss")
	}
}

func TestMalformedAddrIgnored(t *testing.T) {
	r := NewRegistry()
	r.ObserveBind("notaddr", 1, "x", 0)
	r.ObserveBind("1.2.3.4:", 1, "x", 0)
	if r.Size() != 0 {
		t.Errorf("malformed addrs should not populate registry (size=%d)", r.Size())
	}
}

func TestMaxCapEvictsSamePIDOldest(t *testing.T) {
	r := NewRegistry()
	r.SetMax(2)
	r.ObserveBind("10.0.0.5:8000", 100, "c", 1)
	r.ObserveBind("10.0.0.5:8001", 100, "c", 2)
	// Next bind from same PID should evict the oldest entry, not refuse.
	r.ObserveBind("10.0.0.5:8002", 100, "c", 3)
	if r.Size() != 2 {
		t.Errorf("size = %d, want 2 (cap respected)", r.Size())
	}
	if _, ok := r.Lookup("10.0.0.5:8000"); ok {
		t.Error("oldest entry should have been evicted")
	}
	if _, ok := r.Lookup("10.0.0.5:8002"); !ok {
		t.Error("newest entry should be present")
	}
}

func TestLookupMissReturnsZeroValue(t *testing.T) {
	r := NewRegistry()
	r.ObserveBind("10.0.0.5:8080", 100, "cont-server", 1)

	p, ok := r.Lookup("10.0.0.6:8080")
	if ok {
		t.Errorf("miss lookup should return ok=false, got %+v", p)
	}
}

func TestIPv6BracketedFormat(t *testing.T) {
	r := NewRegistry()
	// Mapper emits IPv4 today; this guards the bracketed parser
	// so future AF_INET6 support doesn't silently bypass the registry.
	r.ObserveBind("[::1]:443", 100, "cont-v6", 1)
	p, ok := r.Lookup("[::1]:443")
	if !ok {
		t.Fatal("bracketed IPv6 exact lookup should resolve")
	}
	if p.ContainerID != "cont-v6" {
		t.Errorf("owner = %q", p.ContainerID)
	}
}
