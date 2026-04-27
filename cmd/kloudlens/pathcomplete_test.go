// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import "testing"

type fakeCWD map[int32]string

func (f fakeCWD) Lookup(pid int32) (string, string, bool) {
	cwd, ok := f[pid]
	if !ok {
		return "", "", false
	}
	return cwd, "/", true
}

func TestPathCompleterAbsolutePassThrough(t *testing.T) {
	c := &PathCompleter{CWD: fakeCWD{}}
	got := c.Complete(42, "/etc/hosts")
	if got != "/etc/hosts" {
		t.Fatalf("absolute path should pass through, got %q", got)
	}
	r, d := c.Stats()
	if r != 0 || d != 0 {
		t.Errorf("absolute path must not touch counters: resolved=%d dropped=%d", r, d)
	}
}

func TestPathCompleterJoinsCWD(t *testing.T) {
	c := &PathCompleter{CWD: fakeCWD{123: "/workspace"}}
	got := c.Complete(123, ".git/config")
	if got != "/workspace/.git/config" {
		t.Fatalf("want /workspace/.git/config, got %q", got)
	}
	if r, _ := c.Stats(); r != 1 {
		t.Errorf("resolved counter: want 1, got %d", r)
	}
}

func TestPathCompleterCleansDotSegments(t *testing.T) {
	c := &PathCompleter{CWD: fakeCWD{7: "/a/b"}}
	got := c.Complete(7, "../c/./d")
	if got != "/a/c/d" {
		t.Fatalf("want cleaned /a/c/d, got %q", got)
	}
}

func TestPathCompleterDropsOnMissingCWD(t *testing.T) {
	c := &PathCompleter{CWD: fakeCWD{}}
	got := c.Complete(999, "relative.txt")
	if got != "" {
		t.Fatalf("want '' when CWD lookup fails, got %q", got)
	}
	if _, d := c.Stats(); d != 1 {
		t.Errorf("dropped counter: want 1, got %d", d)
	}
}

func TestPathCompleterDropsOnNilCWD(t *testing.T) {
	c := &PathCompleter{}
	if got := c.Complete(1, "foo"); got != "" {
		t.Fatalf("nil CWD must drop relatives, got %q", got)
	}
	if _, d := c.Stats(); d != 1 {
		t.Errorf("dropped counter: want 1, got %d", d)
	}
}

func TestPathCompleterEmptyInput(t *testing.T) {
	c := &PathCompleter{CWD: fakeCWD{1: "/x"}}
	if got := c.Complete(1, ""); got != "" {
		t.Fatalf("empty input must stay empty, got %q", got)
	}
	if r, d := c.Stats(); r != 0 || d != 0 {
		t.Errorf("empty input must not touch counters: resolved=%d dropped=%d", r, d)
	}
}

func TestPathCompleterNilReceiverSafe(t *testing.T) {
	var c *PathCompleter
	if got := c.Complete(1, "foo"); got != "" {
		t.Fatalf("nil completer must return '', got %q", got)
	}
	r, d := c.Stats()
	if r != 0 || d != 0 {
		t.Errorf("nil completer stats must be zero: resolved=%d dropped=%d", r, d)
	}
}
