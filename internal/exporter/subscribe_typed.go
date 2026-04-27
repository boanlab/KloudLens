// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package exporter

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/boanlab/kloudlens/internal/wal"
	"github.com/boanlab/kloudlens/pkg/types"
	"github.com/boanlab/kloudlens/protobuf"
)

// GraphSource is the narrow read-only view of the Session Graph that the
// typed-stream RPCs need. *graph.Store satisfies it without modification;
// tests can pass a stub. Keeping the interface here (rather than importing
// internal/graph directly) avoids an exporter→graph dependency cycle when
// graph later adopts types from this package for on-wire shapes.
type GraphSource interface {
	Lineage(nodeID string) []string
	Peers(nodeID string) []string
	Touches(nodeID string) []string
	Reaches(nodeID string, maxDepth int) []string
}

// SetGraph wires a GraphSource for QueryGraph. Passing nil disables the RPC
// (returns an error to callers). Safe to call while the server is running —
// new RPCs see the updated value, in-flight calls keep the pointer they got.
func (s *SubscribeServer) SetGraph(g GraphSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.graph = g
}

// SubmitDeviation is the DeviationSink contract: Pipeline.emitDeviation calls
// this for every DeviationEvent produced by the Detector. The server appends
// the event to the WAL under the "deviation" stream (so envelope-API clients
// can resume by cursor) and then fans out to both the typed SubscribeDeviations
// listeners and the generic Subscribe envelope listeners.
func (s *SubscribeServer) SubmitDeviation(ev types.DeviationEvent) {
	seq := uint64(0)
	if s.wal != nil {
		if n, err := s.wal.AppendDeviation(ev); err == nil {
			seq = n
			s.liveSeq.Store(seq)
		} else {
			s.walAppendErr.Add(1)
		}
	}
	proto := deviationToProto(ev)
	env := &protobuf.EventEnvelope{
		Cursor:  &protobuf.Cursor{NodeId: s.nodeID, Stream: "deviation", Seq: seq},
		Payload: &protobuf.EventEnvelope_Deviation{Deviation: proto},
	}
	s.mu.Lock()
	for _, l := range s.devListeners {
		select {
		case l.ch <- proto:
		default:
			l.dropped.Add(1)
		}
	}
	for _, l := range s.listeners {
		select {
		case l.ch <- env:
		default:
			l.dropped.Add(1)
		}
	}
	s.mu.Unlock()
}

// SubmitSyscall is the RawSink contract: Pipeline.Handle calls this for
// every raw SyscallEvent when --enable-raw-stream is set. The server
// appends the event to the WAL under the "raw" stream (so envelope-API
// clients can resume by cursor) and then fans out to both the typed
// SubscribeRaw listeners and the generic Subscribe envelope listeners.
func (s *SubscribeServer) SubmitSyscall(ev types.SyscallEvent) {
	seq := uint64(0)
	if s.wal != nil {
		if n, err := s.wal.AppendSyscall(ev); err == nil {
			seq = n
			s.liveSeq.Store(seq)
		} else {
			s.walAppendErr.Add(1)
		}
	}
	proto := syscallEventToProto(ev)
	env := &protobuf.EventEnvelope{
		Cursor:  &protobuf.Cursor{NodeId: s.nodeID, Stream: "raw", Seq: seq},
		Payload: &protobuf.EventEnvelope_RawSyscall{RawSyscall: proto},
	}
	s.mu.Lock()
	for _, l := range s.rawListeners {
		select {
		case l.ch <- proto:
		default:
			l.dropped.Add(1)
		}
	}
	for _, l := range s.listeners {
		select {
		case l.ch <- env:
		default:
			l.dropped.Add(1)
		}
	}
	s.mu.Unlock()
}

// OnLiveGraphEdge is called by Pipeline whenever a new edge is added to the
// Session Graph. The server fans out to any SubscribeSession consumers whose
// session_id matches edge.SessionID. Edges without a session_id are dropped
// here (host-scoped edges have no subscriber). If the edge also belongs in
// the Subscribe live-tail envelope, that path is handled by the
// existing OnLiveIntent/WAL plumbing — this hook is for the session-scoped
// RPC only.
func (s *SubscribeServer) OnLiveGraphEdge(e types.GraphEdge) {
	if e.SessionID == "" {
		return
	}
	proto := graphEdgeToProto(e)
	update := &protobuf.SessionUpdate{Edge: proto, SessionId: e.SessionID}
	s.mu.Lock()
	listeners := s.sessionListeners[e.SessionID]
	for _, l := range listeners {
		select {
		case l.ch <- update:
		default:
			l.dropped.Add(1)
		}
	}
	s.mu.Unlock()
}

// OnSessionClosed tells any SubscribeSession listeners that the named
// session has ended. It emits a terminal SessionUpdate{closed=true} and
// closes the fan-out channels so the server-side handler drops out of its
// select loop cleanly. Safe to call with no listeners attached.
func (s *SubscribeServer) OnSessionClosed(sessionID string) {
	if sessionID == "" {
		return
	}
	s.mu.Lock()
	listeners := s.sessionListeners[sessionID]
	delete(s.sessionListeners, sessionID)
	s.mu.Unlock()
	term := &protobuf.SessionUpdate{Closed: true, SessionId: sessionID}
	for _, l := range listeners {
		// Best-effort: if the subscriber is backed up past the queue, the
		// terminal signal falls back to channel-close, which the handler
		// reads as EOF and returns.
		select {
		case l.ch <- term:
		default:
		}
		close(l.ch)
	}
}

// SubscribeIntents is the typed complement to Subscribe(streams=["intent"]).
// WAL replay from req.Cursor works the same way; the difference is that the
// response stream is IntentEvent directly, without cursor envelopes.
// Expired-cursor policies map as in Subscribe.
func (s *SubscribeServer) SubscribeIntents(req *protobuf.IntentStreamRequest, stream protobuf.EventService_SubscribeIntentsServer) error {
	fromSeq := uint64(0)
	if c := req.GetCursor(); c != nil {
		fromSeq = c.GetSeq()
	}
	err := s.wal.ReadFrom(fromSeq, "intent", func(e wal.Entry) error {
		if !passesFilter(e, req.GetFilter()) {
			return nil
		}
		return stream.Send(toProto(e.Event))
	})
	if errors.Is(err, wal.ErrCursorExpired) {
		switch req.GetOnExpired() {
		case protobuf.OnExpiredPolicy_RESET_TO_LIVE, protobuf.OnExpiredPolicy_RESET_TO_SNAPSHOT:
			// SnapshotRequest path only exists on the envelope API; for the
			// typed intent stream we treat both reset variants as
			// "continue to live tail" — the client can issue a separate
			// QueryGraph / Snapshot call if it needs a backfill.
		default:
			return fmt.Errorf("subscribe-intents: cursor expired at seq %d", fromSeq)
		}
	} else if err != nil {
		return err
	}
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
			iv := env.GetIntent()
			if iv == nil {
				continue
			}
			if !envelopePassesFilter(env, req.GetFilter()) {
				continue
			}
			if err := stream.Send(iv); err != nil {
				return err
			}
		}
	}
}

// SubscribeDeviations is live-only. Until deviations land in a WAL stream
// there is no replay; late joiners start from the first deviation emitted
// after their Subscribe call. Client filters on kind/score/namespace/pod
// are applied server-side so bandwidth scales with matches, not with the
// raw deviation rate.
func (s *SubscribeServer) SubscribeDeviations(req *protobuf.DeviationStreamRequest, stream protobuf.EventService_SubscribeDeviationsServer) error {
	qsize := int(req.GetFlowControlWindow())
	if qsize <= 0 {
		qsize = 256
	}
	lc := &devChan{ch: make(chan *protobuf.DeviationEvent, qsize)}
	s.mu.Lock()
	s.devListeners = append(s.devListeners, lc)
	s.mu.Unlock()
	defer s.removeDevListener(lc)
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case dv := <-lc.ch:
			if !deviationMatches(dv, req) {
				continue
			}
			if err := stream.Send(dv); err != nil {
				return err
			}
		}
	}
}

// SubscribeRaw is the typed raw-syscall tail — live-only, no cursor. The
// rate is much higher than the intent stream, so the daemon only fans out
// events here when it was started with --enable-raw-stream. Clients that
// need durable replay should use Subscribe(streams=["raw"]) which pulls
// from the WAL.
func (s *SubscribeServer) SubscribeRaw(req *protobuf.RawStreamRequest, stream protobuf.EventService_SubscribeRawServer) error {
	qsize := int(req.GetFlowControlWindow())
	if qsize <= 0 {
		qsize = 256
	}
	lc := &rawChan{ch: make(chan *protobuf.SyscallEvent, qsize)}
	s.mu.Lock()
	s.rawListeners = append(s.rawListeners, lc)
	s.mu.Unlock()
	defer s.removeRawListener(lc)
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case sc := <-lc.ch:
			if !rawMatches(sc, req) {
				continue
			}
			if err := stream.Send(sc); err != nil {
				return err
			}
		}
	}
}

// QueryGraph dispatches to the underlying GraphSource. Unary; the result
// set is bounded by the store's session caps (max edges per session), so
// no streaming variant is needed.
func (s *SubscribeServer) QueryGraph(ctx context.Context, req *protobuf.GraphQuery) (*protobuf.GraphSnapshot, error) {
	_ = ctx
	s.mu.Lock()
	g := s.graph
	s.mu.Unlock()
	if g == nil {
		return nil, fmt.Errorf("query-graph: graph source not configured")
	}
	var ids []string
	switch req.GetQuery() {
	case "lineage":
		ids = g.Lineage(req.GetNodeId())
	case "peers":
		ids = g.Peers(req.GetNodeId())
	case "touches":
		ids = g.Touches(req.GetNodeId())
	case "reaches":
		depth := int(req.GetMaxDepth())
		if depth <= 0 {
			depth = 3
		}
		ids = g.Reaches(req.GetNodeId(), depth)
	default:
		return nil, fmt.Errorf("query-graph: unknown query %q (want lineage|peers|touches|reaches)", req.GetQuery())
	}
	return &protobuf.GraphSnapshot{NodeId: req.GetNodeId(), Query: req.GetQuery(), ResultIds: ids}, nil
}

// SubscribeSession streams edges scoped to a single session. The stream
// terminates with SessionUpdate{closed=true} when the session is purged,
// after which the server closes its fan-out channel and this handler
// returns nil to the client.
func (s *SubscribeServer) SubscribeSession(req *protobuf.SessionStreamRequest, stream protobuf.EventService_SubscribeSessionServer) error {
	sid := req.GetSessionId()
	if sid == "" {
		return fmt.Errorf("subscribe-session: session_id required")
	}
	qsize := int(req.GetFlowControlWindow())
	if qsize <= 0 {
		qsize = 256
	}
	lc := &sessChan{ch: make(chan *protobuf.SessionUpdate, qsize)}
	s.mu.Lock()
	if s.sessionListeners == nil {
		s.sessionListeners = map[string][]*sessChan{}
	}
	s.sessionListeners[sid] = append(s.sessionListeners[sid], lc)
	s.mu.Unlock()
	defer s.removeSessionListener(sid, lc)
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case upd, ok := <-lc.ch:
			if !ok {
				return nil
			}
			if err := stream.Send(upd); err != nil {
				return err
			}
			if upd.GetClosed() {
				return nil
			}
		}
	}
}

// Internal channel types for the typed-stream fan-outs. Separate from
// liveChan so the compiler catches mismatched payload types at
// channel-type level.
type devChan struct {
	ch      chan *protobuf.DeviationEvent
	dropped atomic.Uint64
}

type rawChan struct {
	ch      chan *protobuf.SyscallEvent
	dropped atomic.Uint64
}

type sessChan struct {
	ch      chan *protobuf.SessionUpdate
	dropped atomic.Uint64
}

func (s *SubscribeServer) removeDevListener(lc *devChan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, l := range s.devListeners {
		if l == lc {
			s.droppedAccum.Add(l.dropped.Load())
			s.devListeners = append(s.devListeners[:i], s.devListeners[i+1:]...)
			return
		}
	}
}

func (s *SubscribeServer) removeRawListener(lc *rawChan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, l := range s.rawListeners {
		if l == lc {
			s.droppedAccum.Add(l.dropped.Load())
			s.rawListeners = append(s.rawListeners[:i], s.rawListeners[i+1:]...)
			return
		}
	}
}

func (s *SubscribeServer) removeSessionListener(sid string, lc *sessChan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.sessionListeners[sid]
	for i, l := range list {
		if l == lc {
			s.droppedAccum.Add(l.dropped.Load())
			list = append(list[:i], list[i+1:]...)
			if len(list) == 0 {
				delete(s.sessionListeners, sid)
			} else {
				s.sessionListeners[sid] = list
			}
			return
		}
	}
}

// deviationMatches applies kind/score/namespace/pod filters.
func deviationMatches(dv *protobuf.DeviationEvent, req *protobuf.DeviationStreamRequest) bool {
	if dv == nil {
		return false
	}
	if kinds := req.GetKinds(); len(kinds) > 0 && !slices.Contains(kinds, dv.GetKind()) {
		return false
	}
	if req.GetMinScore() > 0 && dv.GetDeviationScore() < req.GetMinScore() {
		return false
	}
	if m := dv.GetMeta(); m != nil {
		if ns := req.GetNamespaces(); len(ns) > 0 && !slices.Contains(ns, m.GetNamespace()) {
			return false
		}
		if pods := req.GetPods(); len(pods) > 0 && !slices.Contains(pods, m.GetPod()) {
			return false
		}
	} else if len(req.GetNamespaces())+len(req.GetPods()) > 0 {
		return false
	}
	return true
}

// rawMatches applies the syscall / category / namespace / pod include-list.
func rawMatches(sc *protobuf.SyscallEvent, req *protobuf.RawStreamRequest) bool {
	if sc == nil {
		return false
	}
	if sys := req.GetSyscalls(); len(sys) > 0 && !slices.Contains(sys, sc.GetSyscallName()) {
		return false
	}
	if cats := req.GetCategories(); len(cats) > 0 && !slices.Contains(cats, sc.GetCategory()) {
		return false
	}
	if m := sc.GetMeta(); m != nil {
		if ns := req.GetNamespaces(); len(ns) > 0 && !slices.Contains(ns, m.GetNamespace()) {
			return false
		}
		if pods := req.GetPods(); len(pods) > 0 && !slices.Contains(pods, m.GetPod()) {
			return false
		}
	} else if len(req.GetNamespaces())+len(req.GetPods()) > 0 {
		return false
	}
	return true
}

func deviationToProto(d types.DeviationEvent) *protobuf.DeviationEvent {
	return &protobuf.DeviationEvent{
		DeviationId:      d.DeviationID,
		ProfileId:        d.ProfileID,
		Kind:             d.Kind,
		DeviationScore:   d.DeviationScore,
		Evidence:         d.Evidence,
		RelatedIntentIds: append([]string(nil), d.RelatedIntentIDs...),
		Meta:             containerMetaToProto(d.Meta),
	}
}

func graphEdgeToProto(e types.GraphEdge) *protobuf.GraphEdge {
	return &protobuf.GraphEdge{
		EdgeId:     e.EdgeID,
		Kind:       e.Kind,
		SrcNode:    e.SrcNode,
		DstNode:    e.DstNode,
		TsNs:       e.TSNS,
		SessionId:  e.SessionID,
		Attributes: copyStrMap(e.Attributes),
	}
}

func containerMetaToProto(m types.ContainerMeta) *protobuf.ContainerMeta {
	return &protobuf.ContainerMeta{
		Cluster:     m.Cluster,
		NodeName:    m.NodeName,
		Namespace:   m.Namespace,
		Pod:         m.Pod,
		Container:   m.Container,
		ContainerId: m.ContainerID,
		Image:       m.Image,
		Labels:      copyStrMap(m.Labels),
		PidNs:       m.PidNS,
		MntNs:       m.MntNS,
	}
}

func syscallEventToProto(e types.SyscallEvent) *protobuf.SyscallEvent {
	args := make([]*protobuf.SyscallArg, 0, len(e.Args))
	for _, a := range e.Args {
		args = append(args, &protobuf.SyscallArg{
			Name:  a.Name,
			Type:  a.Type,
			Value: a.Value,
			Raw:   append([]byte(nil), a.Raw...),
		})
	}
	return &protobuf.SyscallEvent{
		TimestampNs: e.TimestampNS,
		EventId:     e.EventID,
		CpuId:       e.CPUID,
		HostPid:     e.HostPID,
		HostTid:     e.HostTID,
		HostPpid:    e.HostPPID,
		Pid:         e.PID,
		Tid:         e.TID,
		Uid:         e.UID,
		Gid:         e.GID,
		Comm:        e.Comm,
		ExePath:     e.ExePath,
		SyscallId:   e.SyscallID,
		SyscallName: e.SyscallName,
		Args:        args,
		Retval:      e.RetVal,
		Retcode:     e.RetCode,
		DurationNs:  e.DurationNS,
		Category:    e.Category,
		Operation:   e.Operation,
		Resource:    e.Resource,
		Severity:    uint32(e.Severity), // #nosec G115 -- Severity is an int32 enum → uint32 proto field
		Meta:        containerMetaToProto(e.Meta),
	}
}
