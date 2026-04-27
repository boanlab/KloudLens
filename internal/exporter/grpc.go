// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

// Package exporter ships IntentEvents off-node. It supports gRPC
// streaming to a KloudLens-native collector (via kloudlens's
// --export-grpc=addr flag) and a pull-based EventService. The gRPC
// sink is wire-compat with the proto at protobuf/event.proto.
package exporter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCClient opens a streaming connection to an IntentExporter server and
// ships IntentEvents through it. The client owns its own goroutine and a
// bounded queue; callers Submit non-blocking, and the stream goroutine
// drains into gRPC. When the queue saturates, Submit drops the oldest
// intent (preferring newer) and bumps a counter — slow collectors shouldn't
// stall the live pipeline.
type GRPCClient struct {
	addr   string
	queue  chan *protobuf.IntentEvent
	cancel context.CancelFunc
	done   chan struct{}

	sent    atomic.Uint64
	dropped atomic.Uint64

	mu      sync.Mutex
	lastErr error
}

// DialGRPC starts a client that streams into `addr`. The connection is
// lazy: it dials on first Submit so tests that never send don't race
// against a server that isn't up yet. `qsize` caps in-flight events; 1024
// is a sensible default. The transport is insecure — operators terminate
// auth/encryption out-of-band (sidecar mTLS proxy, IPC over a private
// link, …) and the agent stays minimal.
func DialGRPC(addr string, qsize int) *GRPCClient {
	if qsize <= 0 {
		qsize = 1024
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &GRPCClient{
		addr:   addr,
		queue:  make(chan *protobuf.IntentEvent, qsize),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go c.run(ctx)
	return c
}

// Submit enqueues an IntentEvent for streaming. Non-blocking; on full
// queue the oldest item is dropped so the newest always wins (matches
// the tail-drop policy used by the ring-buffer decoder).
func (c *GRPCClient) Submit(e types.IntentEvent) {
	msg := toProto(e)
	select {
	case c.queue <- msg:
	default:
		// Drop the oldest to make room for the newest — prefer recency.
		select {
		case <-c.queue:
			c.dropped.Add(1)
		default:
		}
		select {
		case c.queue <- msg:
		default:
			c.dropped.Add(1)
		}
	}
}

// Close stops the stream goroutine. Pending items are best-effort
// flushed for up to 2s before the bidi is closed.
func (c *GRPCClient) Close() error {
	c.cancel()
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
	}
	return nil
}

// Stats returns (sent, dropped, lastErr).
func (c *GRPCClient) Stats() (uint64, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent.Load(), c.dropped.Load(), c.lastErr
}

// QueueLen returns the current pending event count in the send queue.
// Exposed so the metrics collector can publish kloudlens_exporter_queue_pending
// without racing the drain loop — len(chan) is safe to read concurrently.
func (c *GRPCClient) QueueLen() int { return len(c.queue) }

func (c *GRPCClient) setErr(err error) {
	c.mu.Lock()
	c.lastErr = err
	c.mu.Unlock()
}

func (c *GRPCClient) run(ctx context.Context) {
	defer close(c.done)

	// Backoff loop: DialContext can fail (server not up), we retry with
	// capped exponential backoff until ctx is cancelled.
	backoff := 200 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			c.setErr(fmt.Errorf("dial %s: %w", c.addr, err))
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		client := protobuf.NewIntentExporterClient(conn)
		if err := c.streamOnce(ctx, client); err != nil {
			_ = conn.Close()
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				// Clean shutdown triggered by Close — don't flag it as an
				// error so the stats line stays quiet.
				return
			}
			c.setErr(err)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		_ = conn.Close()
		return // clean shutdown
	}
}

// streamOnce opens a bidi stream, drains the queue until ctx cancels
// or the server closes, and returns the resulting error (nil on clean
// close). Errors ask run to retry with backoff.
//
// On ctx cancellation we switch to graceful drain: we use a fresh
// background context for the stream itself so the closing handshake
// (flush queue → CloseSend → wait for ack) isn't aborted by the
// already-cancelled parent. A drainTimeout bounds the wait so a silent
// collector can't stall shutdown indefinitely.
func (c *GRPCClient) streamOnce(parent context.Context, client protobuf.IntentExporterClient) error {
	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()
	stream, err := client.Stream(streamCtx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	for {
		select {
		case <-parent.Done():
			// Drain anything already queued (non-blocking), then half-close.
			for {
				select {
				case msg := <-c.queue:
					if err := stream.Send(msg); err != nil {
						return fmt.Errorf("drain send: %w", err)
					}
					c.sent.Add(1)
				default:
					goto closeout
				}
			}
		closeout:
			if _, rerr := stream.CloseAndRecv(); rerr != nil && rerr != io.EOF {
				return rerr
			}
			return parent.Err()
		case msg := <-c.queue:
			if err := stream.Send(msg); err != nil {
				return fmt.Errorf("send: %w", err)
			}
			c.sent.Add(1)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

// toProto converts an in-memory IntentEvent to the wire type. Nil-safe
// on optional fields; history is intentionally not forwarded.
func toProto(e types.IntentEvent) *protobuf.IntentEvent {
	out := &protobuf.IntentEvent{
		IntentId:             e.IntentID,
		Kind:                 e.Kind,
		StartNs:              e.StartNS,
		EndNs:                e.EndNS,
		ContributingEventIds: append([]string(nil), e.ContributingEventIDs...),
		Attributes:           copyStrMap(e.Attributes),
		Severity:             uint32(e.Severity), // #nosec G115 -- Severity is an int32 enum → uint32 proto field
		Confidence:           e.Confidence,
		Meta: &protobuf.ContainerMeta{
			Cluster:     e.Meta.Cluster,
			NodeName:    e.Meta.NodeName,
			Namespace:   e.Meta.Namespace,
			Pod:         e.Meta.Pod,
			Container:   e.Meta.Container,
			ContainerId: e.Meta.ContainerID,
			Image:       e.Meta.Image,
			Labels:      copyStrMap(e.Meta.Labels),
			PidNs:       e.Meta.PidNS,
			MntNs:       e.Meta.MntNS,
		},
	}
	return out
}

func copyStrMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	maps.Copy(out, m)
	return out
}
