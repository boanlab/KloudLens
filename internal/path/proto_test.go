// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package path

import (
	"testing"

	"github.com/boanlab/kloudlens/pkg/types"
)

// TestResolvedPathProtoRoundTrip locks in that every field of the
// hand-maintained types.ResolvedPath survives a types → pb → types round
// trip unchanged. The wire schema (protobuf/event.proto) and the
// internal struct must stay byte-for-byte equivalent on every field —
// forgetting one leaves external subscribers reading a zero while the
// internal journal still has the value, silently degrading replay.
func TestResolvedPathProtoRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   types.ResolvedPath
	}{
		{
			name: "resolved with host translation",
			in: types.ResolvedPath{
				ContainerAbs:    "/etc/passwd",
				HostAbs:         "/var/lib/docker/overlay2/abc/merged/etc/passwd",
				Inode:           4242,
				DevMajor:        8,
				DevMinor:        1,
				MountID:         "mnt-7",
				FollowedSymlink: true,
			},
		},
		{
			name: "unresolved with hint",
			in: types.ResolvedPath{
				PathUnresolved:   true,
				UnresolvedReason: ReasonFdTableMiss,
				DentryHint:       "...passwd",
			},
		},
		{
			name: "zero value",
			in:   types.ResolvedPath{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := ToProto(&tc.in)
			got := FromProto(wire)
			if got != tc.in {
				t.Fatalf("round-trip mismatch:\n in = %+v\n out = %+v", tc.in, got)
			}
		})
	}
}

// TestResolvedPathProtoNilBehavior documents the nil-guards on both
// directions: a nil input must not panic, and ToProto(nil) must return
// nil (not an empty message) so callers can use the nil/non-nil
// distinction to mean "no resolution attempted" without ambiguity.
func TestResolvedPathProtoNilBehavior(t *testing.T) {
	if got := ToProto(nil); got != nil {
		t.Errorf("ToProto(nil) = %+v, want nil", got)
	}
	got := FromProto(nil)
	if got != (types.ResolvedPath{}) {
		t.Errorf("FromProto(nil) = %+v, want zero value", got)
	}
}
