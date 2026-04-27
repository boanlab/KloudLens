// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package path

import (
	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"
)

// ToProto converts the internal ResolvedPath (hand-maintained mirror in
// pkg/types) into the generated protobuf.ResolvedPath wire message. Callers
// that ship resolutions over gRPC use this; callers that only journal
// locally keep the plain struct and never touch protobuf.
//
// A zero-valued input still returns a non-nil message so downstream
// match logic can distinguish "no resolution attempted" (nil) from
// "resolution attempted and came back empty" (all-zero non-nil).
func ToProto(rp *types.ResolvedPath) *protobuf.ResolvedPath {
	if rp == nil {
		return nil
	}
	return &protobuf.ResolvedPath{
		ContainerAbs:     rp.ContainerAbs,
		HostAbs:          rp.HostAbs,
		Inode:            rp.Inode,
		DevMajor:         rp.DevMajor,
		DevMinor:         rp.DevMinor,
		MountId:          rp.MountID,
		FollowedSymlink:  rp.FollowedSymlink,
		PathUnresolved:   rp.PathUnresolved,
		UnresolvedReason: rp.UnresolvedReason,
		DentryHint:       rp.DentryHint,
	}
}

// FromProto is the inverse: wire → internal struct. Used on the pull
// side (aggregator / replay tools) so event consumers can match against
// the same Reason* tokens the producer set.
func FromProto(p *protobuf.ResolvedPath) types.ResolvedPath {
	if p == nil {
		return types.ResolvedPath{}
	}
	return types.ResolvedPath{
		ContainerAbs:     p.GetContainerAbs(),
		HostAbs:          p.GetHostAbs(),
		Inode:            p.GetInode(),
		DevMajor:         p.GetDevMajor(),
		DevMinor:         p.GetDevMinor(),
		MountID:          p.GetMountId(),
		FollowedSymlink:  p.GetFollowedSymlink(),
		PathUnresolved:   p.GetPathUnresolved(),
		UnresolvedReason: p.GetUnresolvedReason(),
		DentryHint:       p.GetDentryHint(),
	}
}
