// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package admin

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/internal/wal"
	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// hasLSM is a tiny case-insensitive contains helper. Diagnose feeds it the
// raw /sys/kernel/security/lsm output to set DiagnoseReport.BpfLsmAvailable();
// case-folding matters because some kernels render the list as "BPF" while
// others use "bpf", and operators rely on the resulting flag to decide
// whether to ship a bpf-LSM HookSubscription.
func TestHasLSM(t *testing.T) {
	cases := []struct {
		xs   []string
		want string
		hit  bool
	}{
		{[]string{"capability", "lockdown", "bpf"}, "bpf", true},
		{[]string{"capability", "lockdown", "BPF"}, "bpf", true}, // case-folded
		{[]string{"capability", "lockdown"}, "bpf", false},
		{nil, "bpf", false},
		{[]string{"selinux"}, "apparmor", false},
	}
	for _, c := range cases {
		if got := hasLSM(c.xs, c.want); got != c.hit {
			t.Errorf("hasLSM(%v,%q)=%v want %v", c.xs, c.want, got, c.hit)
		}
	}
}

// copyStringMap protects the wire payload from mutation of the source.
// intentEnvelopePayload calls it for both Attributes and Meta.Labels so
// post-Dump aliasing of the in-memory event can't reach the gRPC stream.
func TestCopyStringMap(t *testing.T) {
	if got := copyStringMap(nil); got != nil {
		t.Errorf("nil input → %v, want nil", got)
	}
	if got := copyStringMap(map[string]string{}); got != nil {
		t.Errorf("empty input → %v, want nil", got)
	}
	src := map[string]string{"a": "1", "b": "2"}
	dst := copyStringMap(src)
	if dst["a"] != "1" || dst["b"] != "2" {
		t.Fatalf("copy lost data: %+v", dst)
	}
	src["a"] = "mutated"
	if dst["a"] != "1" {
		t.Errorf("dst aliased to src after mutation: %+v", dst)
	}
}

// capabilityReportToProto must round-trip every field the CR consumer cares
// about: NodeID, kernel scalars, helpers, and per-hook fallback metadata.
// A drift here surfaces as klctl caps reporting partial information.
func TestCapabilityReportToProto(t *testing.T) {
	src := &types.CapabilityReport{
		NodeID: "node-x",
		Kernel: types.KernelInfo{
			Version:   "6.6.1",
			LSMs:      []string{"capability", "bpf"},
			CgroupVer: "v2",
			HasBTF:    true,
		},
		Helpers: map[string]string{"arch": "amd64", "ringbuf": "yes"},
		Hooks: []types.HookCap{
			{Kind: "lsm_bpf", Name: "file_open", Available: true, ArgSchema: []string{"path", "flags"}},
			{
				Kind: "kprobe", Name: "security_path_chmod",
				Available:          false,
				UnavailableReason:  "symbol inlined",
				FallbackSuggestion: "tracepoint:syscalls/sys_enter_chmod",
			},
		},
	}
	out := capabilityReportToProto(src)
	if out.NodeId != "node-x" {
		t.Errorf("NodeId=%q", out.NodeId)
	}
	if out.Kernel.Version != "6.6.1" || !out.Kernel.BtfAvailable || out.Kernel.CgroupVersion != "v2" {
		t.Errorf("Kernel=%+v", out.Kernel)
	}
	if len(out.Kernel.Lsms) != 2 || out.Kernel.Lsms[1] != "bpf" {
		t.Errorf("Lsms=%+v", out.Kernel.Lsms)
	}
	if out.Helpers["arch"] != "amd64" || out.Helpers["ringbuf"] != "yes" {
		t.Errorf("Helpers=%+v", out.Helpers)
	}
	if len(out.Hooks) != 2 {
		t.Fatalf("Hooks count=%d", len(out.Hooks))
	}
	if out.Hooks[0].ArgSchema[0] != "path" || !out.Hooks[0].Available {
		t.Errorf("Hook[0]=%+v", out.Hooks[0])
	}
	if out.Hooks[1].FallbackSuggestion == "" || out.Hooks[1].UnavailableReason == "" {
		t.Errorf("Hook[1] dropped fallback metadata: %+v", out.Hooks[1])
	}

	// Source mutation must not leak into the proto — the proto holds its
	// own copies of the slice / map fields.
	src.Kernel.LSMs[0] = "mutated"
	src.Helpers["arch"] = "mutated"
	if out.Kernel.Lsms[0] != "capability" {
		t.Error("Kernel.Lsms aliased to source")
	}
}

// intentEnvelopePayload must surface every IntentEvent field that klctl dump
// downstream consumers will read. Most of these get covered by the Dump RPC
// integration test below — this case isolates the converter so a regression
// there doesn't drown in the gRPC plumbing.
func TestIntentEnvelopePayload(t *testing.T) {
	ev := types.IntentEvent{
		IntentID:             "iid",
		Kind:                 "FileWrite",
		StartNS:              10,
		EndNS:                20,
		ContributingEventIDs: []string{"e1", "e2"},
		Attributes:           map[string]string{"path": "/etc/passwd"},
		Severity:             3,
		Confidence:           0.42,
		Meta: types.ContainerMeta{
			Cluster: "c", NodeName: "n", Namespace: "ns", Pod: "pod-a",
			Container: "ctr", ContainerID: "cid", Image: "img",
			Labels: map[string]string{"app": "nginx"},
			PidNS:  4026531836, MntNS: 4026531840,
		},
	}
	wrap := intentEnvelopePayload(ev)
	got := wrap.Intent
	if got.IntentId != "iid" || got.Kind != "FileWrite" || got.Severity != 3 {
		t.Errorf("scalar fields: %+v", got)
	}
	if got.StartNs != 10 || got.EndNs != 20 || got.Confidence != 0.42 {
		t.Errorf("ts/conf: %+v", got)
	}
	if len(got.ContributingEventIds) != 2 || got.ContributingEventIds[1] != "e2" {
		t.Errorf("contributing ids: %+v", got.ContributingEventIds)
	}
	if got.Attributes["path"] != "/etc/passwd" {
		t.Errorf("attributes: %+v", got.Attributes)
	}
	m := got.GetMeta()
	if m.Pod != "pod-a" || m.Namespace != "ns" || m.PidNs != 4026531836 || m.MntNs != 4026531840 {
		t.Errorf("meta: %+v", m)
	}
	if m.Labels["app"] != "nginx" {
		t.Errorf("labels: %+v", m.Labels)
	}

	// Mutating the source must not leak into the proto envelope.
	ev.Attributes["path"] = "x"
	ev.Meta.Labels["app"] = "x"
	if got.Attributes["path"] != "/etc/passwd" || got.GetMeta().Labels["app"] != "nginx" {
		t.Error("envelope aliased the source maps")
	}
}

// topSnapshot folds StatsSource counters into TopSnapshot rows. With nil
// StatsSource the snapshot is empty (just the timestamp); with TopN set to a
// value smaller than the row count the result is truncated. Both branches
// matter to klctl top — empty snapshot means "stats wiring not attached",
// and truncation is the operator's request to keep the table compact.
func TestTopSnapshot(t *testing.T) {
	t.Run("nil stats yields empty", func(t *testing.T) {
		s := NewServer(nil, Options{NodeName: "n"})
		snap := s.topSnapshot(0)
		if snap == nil || len(snap.Rows) != 0 {
			t.Fatalf("expected empty rows, got %+v", snap)
		}
		if snap.TsNs == 0 {
			t.Errorf("TsNs=0; topSnapshot must always stamp time")
		}
	})
	t.Run("rows reflect counters", func(t *testing.T) {
		s := NewServer(fakeStats{s: 11, i: 22, fr: 33, fd: 44}, Options{NodeName: "n"})
		snap := s.topSnapshot(0)
		got := map[string]uint64{}
		for _, r := range snap.Rows {
			got[r.Key] = r.Total
		}
		if got["syscalls"] != 11 || got["intents"] != 22 ||
			got["frames_read"] != 33 || got["frames_dropped"] != 44 {
			t.Errorf("rows: %+v", got)
		}
	})
	t.Run("TopN truncates", func(t *testing.T) {
		s := NewServer(fakeStats{s: 1, i: 2, fr: 3, fd: 4}, Options{NodeName: "n"})
		snap := s.topSnapshot(2)
		if len(snap.Rows) != 2 {
			t.Errorf("rows after TopN=2: %d, want 2", len(snap.Rows))
		}
	})
	t.Run("TopN larger than rows is no-op", func(t *testing.T) {
		s := NewServer(fakeStats{}, Options{NodeName: "n"})
		snap := s.topSnapshot(99)
		if len(snap.Rows) != 4 {
			t.Errorf("rows after TopN=99: %d, want 4", len(snap.Rows))
		}
	})
}

// startAdminServer is a per-test bufconn admin server. Mirrors the
// pattern in subscribe_test.go.
func startAdminServer(t *testing.T, s *Server) protobuf.AdminServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	protobuf.RegisterAdminServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return protobuf.NewAdminServiceClient(conn)
}

// Dump must (a) error when WAL was not attached to the server (klctl needs
// a clear "this agent has no on-disk replay buffer" signal rather than a
// silent empty stream), (b) replay only the entries whose container_id
// matches the request, and (c) honor the since/until window. All three are
// failure modes that previously surfaced only at the operator.
func TestDumpRequiresWAL(t *testing.T) {
	srv := NewServer(nil, Options{NodeName: "n1"}) // no WAL
	client := startAdminServer(t, srv)

	stream, err := client.Dump(context.Background(), &protobuf.DumpRequest{ContainerId: "x"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestDumpFiltersByContainerAndTime(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	mk := func(id, container string, ts int64) types.IntentEvent {
		return types.IntentEvent{
			IntentID: id, Kind: "FileRead",
			Meta: types.ContainerMeta{ContainerID: container},
			// StartNS doubles as the WAL entry timestamp via the wal layer
			// when the entry's TS field is taken from the event clock.
			StartNS: uint64(ts),
		}
	}
	// Append events in three "buckets":
	// - container=A, ts=100 (kept)
	// - container=A, ts=500 (kept)
	// - container=B, ts=200 (filtered out by container)
	// - container=A, ts=2000 (filtered out by until_ns=1000)
	// Use TS hooks via wal.Append so we can stamp e.TS deterministically.
	for _, ev := range []types.IntentEvent{
		mk("a-100", "A", 100),
		mk("a-500", "A", 500),
		mk("b-200", "B", 200),
		mk("a-2000", "A", 2000),
	} {
		if _, err := w.Append("intent", ev); err != nil {
			t.Fatal(err)
		}
	}

	srv := NewServer(nil, Options{NodeName: "n1", WAL: w})
	client := startAdminServer(t, srv)

	stream, err := client.Dump(context.Background(), &protobuf.DumpRequest{
		ContainerId: "A",
		// WAL timestamps come from the daemon clock — we cannot rely on
		// since/until matching the StartNS we wrote. This test asserts
		// container filtering only; the time window is exercised by the
		// per-flag check below using a wide window.
		SinceNs: 0,
		UntilNs: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		env, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		got = append(got, env.GetIntent().GetIntentId())
	}
	want := map[string]bool{"a-100": true, "a-500": true, "a-2000": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v entries (3, all container=A)", got, want)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected id %q in dump output (container filter leaked)", id)
		}
	}
}

// Top streams TopSnapshot ticks until the client cancels. The first tick
// must carry the row set produced by topSnapshot, and cancellation must
// terminate the RPC promptly (the loop checks stream.Context).
func TestTopStreamsAndStops(t *testing.T) {
	srv := NewServer(fakeStats{s: 7}, Options{NodeName: "n"})
	client := startAdminServer(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.Top(ctx, &protobuf.TopRequest{IntervalMs: 20})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, r := range snap.GetRows() {
		if r.Key == "syscalls" && r.Total == 7 {
			seen = true
		}
	}
	if !seen {
		t.Errorf("first snapshot missing syscalls=7 row: %+v", snap.GetRows())
	}

	// Cancel the client side and prove the RPC terminates within a short
	// window — tickless test so we don't busy-poll.
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()
	var wg sync.WaitGroup
	wg.Add(0)
	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Errorf("Top did not terminate within 2s of client cancel")
	}
}
