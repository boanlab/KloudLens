// SPDX-License-Identifier: Apache-2.0

package sensor

import "testing"

// Pkg 28: the BPF filter keys on (pid_ns<<32)|mnt_ns — the CLI surface has
// to decode "pidNS:mntNS,pidNS:mntNS" into exactly that layout or the live
// loader will write unreachable keys into st_skip_ns_map.
func TestParseNSList(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantLen int
		wantKey uint64 // check first entry's Uint64 packing
	}{
		{"", 0, 0},
		{" ", 0, 0},
		{"4026531835:4026531840", 1, (uint64(4026531835) << 32) | uint64(4026531840)},
		{"1:2,3:4", 2, (uint64(1) << 32) | uint64(2)},
		{" 10:20 , 30:40 ", 2, (uint64(10) << 32) | uint64(20)},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseNSList(tc.in)
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len=%d want %d", len(got), tc.wantLen)
			}
			if tc.wantLen > 0 && got[0].Uint64() != tc.wantKey {
				t.Fatalf("key=%#x want %#x", got[0].Uint64(), tc.wantKey)
			}
		})
	}
}

func TestParseNSListRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"1",             // no colon
		":2",            // missing pidNS
		"1:",            // missing mntNS
		"abc:2",         // non-numeric
		"1:xyz",         // non-numeric
		"99999999999:1", // overflows uint32
	} {
		if _, err := ParseNSList(bad); err == nil {
			t.Errorf("ParseNSList(%q) should have errored", bad)
		}
	}
}

// Mode is what the loader uses to decide toggle_map[0]: target=1,
// else=0. Also verifies TargetNS wins when both slices are set.
func TestLiveOptionsMode(t *testing.T) {
	if got := (LiveOptions{}).Mode(); got != "all" {
		t.Errorf("default mode=%q want all", got)
	}
	if got := (LiveOptions{TargetNS: []NSKey{{1, 2}}}).Mode(); got != "target" {
		t.Errorf("target mode=%q", got)
	}
	if got := (LiveOptions{ExceptNS: []NSKey{{3, 4}}}).Mode(); got != "except" {
		t.Errorf("except mode=%q", got)
	}
	both := LiveOptions{TargetNS: []NSKey{{1, 2}}, ExceptNS: []NSKey{{3, 4}}}
	if got := both.Mode(); got != "target" {
		t.Errorf("both-set: mode=%q want target (TargetNS must win)", got)
	}
}

func TestNSKeyUint64Packing(t *testing.T) {
	k := NSKey{PidNS: 0x11223344, MntNS: 0xAABBCCDD}
	want := uint64(0x11223344)<<32 | uint64(0xAABBCCDD)
	if got := k.Uint64(); got != want {
		t.Fatalf("pack=%#x want %#x", got, want)
	}
}
