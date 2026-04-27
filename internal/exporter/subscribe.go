// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package exporter

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/boanlab/kloudlens/internal/wal"
	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"
)

// SubscribeServer is the pull-side EventService: collectors connect with
// a durable cursor and either stream from the WAL (resume) or live-tail
// new events. Ack commits a cursor per consumer_id.
type SubscribeServer struct {
	protobuf.UnimplementedEventServiceServer

	wal     *wal.WAL
	snap    SnapshotProvider
	nodeID  string
	liveSeq atomic.Uint64
	// walAppendErr counts WAL append failures from OnLiveIntent /
	// SubmitDeviation / SubmitSyscall. Callers silently drop the event
	// when the WAL rejects the write (Closed segment, full disk, etc.);
	// without this counter the loss would be invisible to operators.
	// Surfaced on /metrics as kloudlens_wal_append_errors_total.
	walAppendErr atomic.Uint64
	// droppedAccum absorbs per-listener `dropped` counts when a listener
	// disconnects, so fan-out overflow stays visible as a monotonic
	// counter on /metrics even across subscriber churn. Live listeners'
	// current counts are added on top by SubscriberDropped.
	droppedAccum atomic.Uint64
	mu           sync.Mutex
	cursors      map[string]*protobuf.Cursor // consumer_id → committed cursor
	listeners    []*liveChan                 // fan-out to live subscribers

	// Typed-stream RPC fan-outs. Kept separate from listeners so the
	// compiler rejects mismatched payload types at channel level.
	graph            GraphSource
	devListeners     []*devChan
	rawListeners     []*rawChan
	sessionListeners map[string][]*sessChan
}

// SnapshotProvider returns the current agent state for
// EventService.Snapshot / RESET_TO_SNAPSHOT.
type SnapshotProvider interface {
	DumpSessions() []*protobuf.GraphEdge
	DumpLifecycle() []*protobuf.ContainerLifecycleEvent
}

// NewSubscribeServer wires up the pull-side server against an open WAL.
// `nodeID` is stamped into cursors so cross-node clients can disambiguate.
func NewSubscribeServer(w *wal.WAL, snap SnapshotProvider, nodeID string) *SubscribeServer {
	return &SubscribeServer{
		wal:     w,
		snap:    snap,
		nodeID:  nodeID,
		cursors: map[string]*protobuf.Cursor{},
	}
}

// Submit implements the pipeline's IntentSink interface by forwarding
// every emitted IntentEvent to OnLiveIntent (WAL append + live fan-out).
func (s *SubscribeServer) Submit(ev types.IntentEvent) { s.OnLiveIntent(ev) }

// OnLiveIntent is called by the pipeline whenever a new intent is emitted.
// We (a) append to the WAL, (b) fan-out to any live subscribers.
func (s *SubscribeServer) OnLiveIntent(ev types.IntentEvent) {
	seq, err := s.wal.Append("intent", ev)
	if err != nil {
		s.walAppendErr.Add(1)
		return
	}
	s.liveSeq.Store(seq)

	env := &protobuf.EventEnvelope{
		Cursor:  &protobuf.Cursor{NodeId: s.nodeID, Stream: "intent", Seq: seq},
		Payload: &protobuf.EventEnvelope_Intent{Intent: toProto(ev)},
	}
	s.mu.Lock()
	for _, l := range s.listeners {
		select {
		case l.ch <- env:
		default:
			l.dropped.Add(1)
		}
	}
	s.mu.Unlock()
}

// Subscribe streams events starting from request.Cursor.Seq. If the
// cursor is expired, on_expired decides RESET_TO_LIVE / _SNAPSHOT / FAIL.
func (s *SubscribeServer) Subscribe(req *protobuf.SubscribeRequest, stream protobuf.EventService_SubscribeServer) error {
	streams := req.GetStreams()
	if len(streams) == 0 {
		streams = []string{"intent"}
	}
	// replay phase
	fromSeq := uint64(0)
	if c := req.GetCursor(); c != nil {
		fromSeq = c.Seq
	}
	for _, st := range streams {
		err := s.wal.ReadFrom(fromSeq, st, func(e wal.Entry) error {
			env := entryToEnvelope(e, s.nodeID)
			if env == nil {
				return nil
			}
			if !envelopePassesFilter(env, req.GetFilter()) {
				return nil
			}
			return stream.Send(env)
		})
		if errors.Is(err, wal.ErrCursorExpired) {
			switch req.GetOnExpired() {
			case protobuf.OnExpiredPolicy_RESET_TO_LIVE:
				// fall through to live tail
			case protobuf.OnExpiredPolicy_RESET_TO_SNAPSHOT:
				if err := s.sendSnapshot(stream); err != nil {
					return err
				}
			default:
				return fmt.Errorf("cursor expired at seq %d", fromSeq)
			}
		} else if err != nil {
			return err
		}
	}
	// live tail
	qsize := int(req.GetFlowControlWindow())
	if qsize <= 0 {
		qsize = 256
	}
	lc := &liveChan{ch: make(chan *protobuf.EventEnvelope, qsize)}
	s.mu.Lock()
	s.listeners = append(s.listeners, lc)
	s.mu.Unlock()
	defer s.removeListener(lc)

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case env := <-lc.ch:
			if !envelopePassesFilter(env, req.GetFilter()) {
				continue
			}
			if err := stream.Send(env); err != nil {
				return err
			}
		}
	}
}

// Ack commits a cursor for the named consumer.
func (s *SubscribeServer) Ack(_ context.Context, req *protobuf.AckRequest) (*protobuf.AckResponse, error) {
	s.mu.Lock()
	s.cursors[req.GetConsumerId()] = req.GetCursor()
	s.mu.Unlock()
	return &protobuf.AckResponse{}, nil
}

// Snapshot sends a consistent dump of current state, then the caller
// can open Subscribe with a fresh cursor to live-tail from there.
func (s *SubscribeServer) Snapshot(_ *protobuf.SnapshotRequest, stream protobuf.EventService_SnapshotServer) error {
	return s.sendSnapshot(stream)
}

func (s *SubscribeServer) sendSnapshot(stream protobuf.EventService_SnapshotServer) error {
	if s.snap == nil {
		return nil
	}
	for _, ed := range s.snap.DumpSessions() {
		env := &protobuf.EventEnvelope{
			Cursor:  &protobuf.Cursor{NodeId: s.nodeID, Stream: "graph-edge"},
			Payload: &protobuf.EventEnvelope_GraphEdge{GraphEdge: ed},
		}
		if err := stream.Send(env); err != nil {
			return err
		}
	}
	for _, lf := range s.snap.DumpLifecycle() {
		env := &protobuf.EventEnvelope{
			Cursor:  &protobuf.Cursor{NodeId: s.nodeID, Stream: "lifecycle"},
			Payload: &protobuf.EventEnvelope_Lifecycle{Lifecycle: lf},
		}
		if err := stream.Send(env); err != nil {
			return err
		}
	}
	return nil
}

func (s *SubscribeServer) removeListener(lc *liveChan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, l := range s.listeners {
		if l == lc {
			s.droppedAccum.Add(l.dropped.Load())
			s.listeners = append(s.listeners[:i], s.listeners[i+1:]...)
			return
		}
	}
}

// WALAppendErrors returns the running count of WAL append failures from
// OnLiveIntent / SubmitDeviation. Safe for concurrent readers.
func (s *SubscribeServer) WALAppendErrors() uint64 { return s.walAppendErr.Load() }

// SubscriberCount returns the live listener count per stream type:
// envelope = protobuf.Subscribe(), deviation = SubscribeDeviations(), session =
// SubscribeSession (flattened across the by-session-id bucket map).
// Point-in-time gauge — zero for a stream with no current consumers.
// Mirrors the aggregator's kloudlens_aggregator_subscribers_active so
// agent-side and cluster-side fan-out have symmetric subscriber gauges.
func (s *SubscribeServer) SubscriberCount() (envelope, deviation, session int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	envelope = len(s.listeners)
	deviation = len(s.devListeners)
	for _, bucket := range s.sessionListeners {
		session += len(bucket)
	}
	return envelope, deviation, session
}

// SubscriberDropped returns the monotonic count of envelopes that the
// live fan-out had to drop because a subscriber's per-connection queue
// was full at send time. The sum spans all three listener types —
// envelope Subscribe, typed SubscribeDeviations, SubscribeSession — so
// one series covers every consumer shape. Monotonic across subscriber
// disconnects: on removeListener/removeDevListener/removeSessionListener
// the dying listener's count is folded into droppedAccum before the
// liveChan goes away.
func (s *SubscribeServer) SubscriberDropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := s.droppedAccum.Load()
	for _, l := range s.listeners {
		total += l.dropped.Load()
	}
	for _, l := range s.devListeners {
		total += l.dropped.Load()
	}
	for _, bucket := range s.sessionListeners {
		for _, l := range bucket {
			total += l.dropped.Load()
		}
	}
	return total
}

// CursorOf returns the last committed cursor for a consumer (test helper).
func (s *SubscribeServer) CursorOf(consumerID string) *protobuf.Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cursors[consumerID]
	if !ok {
		return nil
	}
	return c
}

type liveChan struct {
	ch      chan *protobuf.EventEnvelope
	dropped atomic.Uint64
}

func passesFilter(e wal.Entry, f *protobuf.EventFilter) bool {
	if f == nil {
		return true
	}
	env := entryToEnvelope(e, "")
	if env == nil {
		return true
	}
	return envelopePassesFilter(env, f)
}

// entryToEnvelope builds a typed EventEnvelope from a WAL entry by routing on
// the stream tag. Returns nil for entries that have no typed payload — a
// deviation / raw row with a missing payload pointer (corrupt file) or a
// stream the Subscribe API doesn't surface.
func entryToEnvelope(e wal.Entry, nodeID string) *protobuf.EventEnvelope {
	cursor := &protobuf.Cursor{NodeId: nodeID, Stream: e.Stream, Seq: e.Seq}
	switch e.Stream {
	case "deviation":
		if e.Deviation == nil {
			return nil
		}
		return &protobuf.EventEnvelope{
			Cursor:  cursor,
			Payload: &protobuf.EventEnvelope_Deviation{Deviation: deviationToProto(*e.Deviation)},
		}
	case "raw":
		if e.Syscall == nil {
			return nil
		}
		return &protobuf.EventEnvelope{
			Cursor:  cursor,
			Payload: &protobuf.EventEnvelope_RawSyscall{RawSyscall: syscallEventToProto(*e.Syscall)},
		}
	default:
		return &protobuf.EventEnvelope{
			Cursor:  cursor,
			Payload: &protobuf.EventEnvelope_Intent{Intent: toProto(e.Event)},
		}
	}
}

func envelopePassesFilter(env *protobuf.EventEnvelope, f *protobuf.EventFilter) bool {
	if f == nil {
		return true
	}
	if iv := env.GetIntent(); iv != nil {
		if len(f.GetKinds()) > 0 && !slices.Contains(f.GetKinds(), iv.GetKind()) {
			return false
		}
		if iv.GetMeta() != nil {
			if len(f.GetNamespaces()) > 0 && !slices.Contains(f.GetNamespaces(), iv.GetMeta().GetNamespace()) {
				return false
			}
			if len(f.GetPods()) > 0 && !slices.Contains(f.GetPods(), iv.GetMeta().GetPod()) {
				return false
			}
		}
		if f.GetMinSeverity() > 0 && iv.GetSeverity() < f.GetMinSeverity() {
			return false
		}
		return true
	}
	if dv := env.GetDeviation(); dv != nil {
		// min_severity has no deviation analogue (DeviationEvent carries a
		// score, not a severity); leave it to the typed SubscribeDeviations
		// RPC. Kind/namespace/pod are shared with intents, so reuse them.
		if len(f.GetKinds()) > 0 && !slices.Contains(f.GetKinds(), dv.GetKind()) {
			return false
		}
		if dv.GetMeta() != nil {
			if len(f.GetNamespaces()) > 0 && !slices.Contains(f.GetNamespaces(), dv.GetMeta().GetNamespace()) {
				return false
			}
			if len(f.GetPods()) > 0 && !slices.Contains(f.GetPods(), dv.GetMeta().GetPod()) {
				return false
			}
		}
		return true
	}
	if rs := env.GetRawSyscall(); rs != nil {
		// For the raw stream, EventFilter.kinds matches against either the
		// syscall name or the category; operators typically specify one or
		// the other per rule, so this catches both.
		if kinds := f.GetKinds(); len(kinds) > 0 {
			if !slices.Contains(kinds, rs.GetSyscallName()) && !slices.Contains(kinds, rs.GetCategory()) {
				return false
			}
		}
		if rs.GetMeta() != nil {
			if len(f.GetNamespaces()) > 0 && !slices.Contains(f.GetNamespaces(), rs.GetMeta().GetNamespace()) {
				return false
			}
			if len(f.GetPods()) > 0 && !slices.Contains(f.GetPods(), rs.GetMeta().GetPod()) {
				return false
			}
		}
		if f.GetMinSeverity() > 0 && rs.GetSeverity() < f.GetMinSeverity() {
			return false
		}
		return true
	}
	return true
}
