// SPDX-License-Identifier: Apache-2.0

package exporter

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// mockServer records every IntentEvent received on the stream so tests
// can assert on the exact wire payload.
type mockServer struct {
	protobuf.UnimplementedIntentExporterServer

	mu  sync.Mutex
	got []*protobuf.IntentEvent
}

func (m *mockServer) Stream(srv protobuf.IntentExporter_StreamServer) error {
	for {
		ev, err := srv.Recv()
		if err == io.EOF {
			return srv.SendAndClose(&protobuf.StreamAck{Received: uint64(len(m.got))})
		}
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.got = append(m.got, ev)
		m.mu.Unlock()
	}
}

func (m *mockServer) events() []*protobuf.IntentEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*protobuf.IntentEvent, len(m.got))
	copy(out, m.got)
	return out
}

func startBufconnServer(t *testing.T) (*mockServer, *bufconn.Listener, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	mock := &mockServer{}
	protobuf.RegisterIntentExporterServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()
	return mock, lis, func() { srv.Stop() }
}

// newBufconnClient creates a GRPCClient whose Dial goes over bufconn.
// The exporter package's public API requires a TCP address — we swap
// the dial implementation here by hand-rolling a client that uses the
// bufconn listener's Dial method.
func newBufconnClient(t *testing.T, lis *bufconn.Listener) *GRPCClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &GRPCClient{
		addr:   "bufconn",
		queue:  make(chan *protobuf.IntentEvent, 16),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(c.done)
		conn, err := grpc.NewClient(
			"passthrough:bufconn",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
		)
		if err != nil {
			c.setErr(err)
			return
		}
		defer func() { _ = conn.Close() }()
		client := protobuf.NewIntentExporterClient(conn)
		_ = c.streamOnce(ctx, client)
	}()
	return c
}

func TestGRPCClientShipsIntents(t *testing.T) {
	mock, lis, stop := startBufconnServer(t)
	defer stop()

	c := newBufconnClient(t, lis)
	defer func() { _ = c.Close() }()

	// Give the stream time to establish before pumping.
	time.Sleep(50 * time.Millisecond)

	c.Submit(types.IntentEvent{
		IntentID: "i1", Kind: "FileRead",
		StartNS: 1, EndNS: 2,
		Attributes: map[string]string{"path": "/etc/passwd"},
		Meta:       types.ContainerMeta{Pod: "nginx", Namespace: "default", PidNS: 4026531836},
		Confidence: 0.9,
	})
	c.Submit(types.IntentEvent{
		IntentID: "i2", Kind: "NetworkExchange",
		StartNS: 3, EndNS: 4,
		Attributes: map[string]string{"peer": "10.0.0.1:443"},
	})

	// Wait until both events land (or time out).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sent, _, _ := c.Stats(); sent >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = c.Close()

	got := mock.events()
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	if got[0].IntentId != "i1" || got[0].Kind != "FileRead" {
		t.Errorf("event 0: id=%q kind=%q", got[0].IntentId, got[0].Kind)
	}
	if got[0].Attributes["path"] != "/etc/passwd" {
		t.Errorf("attributes lost: %+v", got[0].Attributes)
	}
	if got[0].Meta.GetPod() != "nginx" || got[0].Meta.GetPidNs() != 4026531836 {
		t.Errorf("meta lost: %+v", got[0].Meta)
	}
	if got[0].Confidence != 0.9 {
		t.Errorf("confidence lost: %v", got[0].Confidence)
	}
	if got[1].IntentId != "i2" || got[1].Attributes["peer"] != "10.0.0.1:443" {
		t.Errorf("event 1: %+v", got[1])
	}
}

func TestGRPCClientDropOnFullQueue(t *testing.T) {
	// No server — dial will fail / queue will back up. Build the client
	// manually so we can keep the queue tiny without exposing the
	// internal field via the public API.
	c := &GRPCClient{
		addr:   "nowhere.invalid:65535",
		queue:  make(chan *protobuf.IntentEvent, 2),
		cancel: func() {},
		done:   make(chan struct{}),
	}
	// Pump 5 items through a 2-slot queue; at least 3 must be dropped.
	for range 5 {
		c.Submit(types.IntentEvent{IntentID: "x", Kind: "FileRead"})
	}
	if _, dropped, _ := c.Stats(); dropped < 3 {
		t.Fatalf("expected >=3 drops, got %d", dropped)
	}
}

func TestToProtoRoundTripAttributes(t *testing.T) {
	src := types.IntentEvent{
		IntentID:   "abc",
		Kind:       "FileWrite",
		Attributes: map[string]string{"k": "v"},
		Meta:       types.ContainerMeta{Labels: map[string]string{"app": "nginx"}},
	}
	out := toProto(src)
	if out.IntentId != "abc" || out.Attributes["k"] != "v" {
		t.Fatalf("attr: %+v", out)
	}
	if out.Meta.GetLabels()["app"] != "nginx" {
		t.Fatalf("meta labels: %+v", out.Meta)
	}
	// Mutating the source map must not affect the emitted proto — copy
	// semantics protect the collector from live-agent updates racing.
	src.Attributes["k"] = "mutated"
	src.Meta.Labels["app"] = "mutated"
	if out.Attributes["k"] != "v" || out.Meta.GetLabels()["app"] != "nginx" {
		t.Fatalf("maps weren't copied: %+v / %+v", out.Attributes, out.Meta.Labels)
	}
}
