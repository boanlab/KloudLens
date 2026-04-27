// SPDX-License-Identifier: Apache-2.0

package enricher

import "testing"

func TestContainerIDFromCgroup(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "k8s containerd",
			in:   "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod792d3666_27e4_4566_a0ca_1352c69ed8b4.slice/cri-containerd-731d23c40ccdcda5c3d197c22b34dd91f3af76986424255400b18cd4bf135451.scope",
			want: "731d23c40ccdcda5c3d197c22b34dd91f3af76986424255400b18cd4bf135451",
		},
		{
			name: "plain containerd scope",
			in:   "0::/system.slice/containerd-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope",
			want: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			name: "docker scope",
			in:   "0::/docker-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.scope",
			want: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
		{
			name: "cgroup-v1 docker/<id>",
			in:   "12:pids:/docker/7f7c0000ffff7f7c0000ffff7f7c0000ffff7f7c0000ffff7f7c0000ffff",
			want: "7f7c0000ffff7f7c0000ffff7f7c0000ffff7f7c0000ffff7f7c0000ffff",
		},
		{
			name: "crio scope",
			in:   "0::/kubepods.slice/crio-ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100.scope",
			want: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
		},
		{name: "systemd user slice (non-container)", in: "0::/user.slice/user-1000.slice/session-214.scope", want: ""},
		{name: "empty", in: "", want: ""},
		{name: "root", in: "0::/", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ContainerIDFromCgroup(tc.in)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestContainerIDFromCgroupFile(t *testing.T) {
	file := "12:freezer:/\n" +
		"11:blkio:/system.slice\n" +
		"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/cri-containerd-cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d.scope\n"
	got := ContainerIDFromCgroupFile(file)
	if got != "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d" {
		t.Fatalf("got %q", got)
	}
}

func TestPodUIDFromCgroup(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "besteffort pod",
			in:   "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod792d3666_27e4_4566_a0ca_1352c69ed8b4.slice/cri-containerd-abc.scope",
			want: "792d3666_27e4_4566_a0ca_1352c69ed8b4",
		},
		{
			name: "burstable pod",
			in:   "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podcc66aaff_8877_1111_2222_333344445555.slice/cri-containerd-xyz.scope",
			want: "cc66aaff_8877_1111_2222_333344445555",
		},
		{
			name: "guaranteed pod (no qos sub-slice)",
			in:   "0::/kubepods.slice/kubepods-pod11112222_3333_4444_5555_666677778888.slice/cri-containerd-abc.scope",
			want: "11112222_3333_4444_5555_666677778888",
		},
		{name: "non-kubepods", in: "0::/docker-abc.scope", want: ""},
		{name: "empty", in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PodUIDFromCgroup(tc.in)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
