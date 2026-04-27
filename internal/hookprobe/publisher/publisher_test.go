// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package publisher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// fakeAPIServer mimics the narrow slice of kube apiserver behavior the
// Publisher uses: GET nodecapabilities/<name>, POST collection, PUT status
// subresource. Concurrency-safe so tests can race multiple Run calls.
type fakeAPIServer struct {
	mu      sync.Mutex
	objects map[string]*fakeObj
	rv      int
	// recorded request log (method + URL path) in call order — tests assert
	// on the exact sequence (GET→POST→GET→PUT for cold start, GET→PUT for
	// warm).
	calls []string
	// hooks tests install to fail a specific request type
	failGetOnce   bool
	failPutOnce   bool
	postConflict  bool
	getReturns500 bool
}

type fakeObj struct {
	Metadata struct {
		Name            string `json:"name"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Spec   map[string]any `json:"spec,omitempty"`
	Status map[string]any `json:"status,omitempty"`
}

func newFakeAPIServer() (*fakeAPIServer, *httptest.Server) {
	f := &fakeAPIServer{objects: map[string]*fakeObj{}}
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	return f, srv
}

func (f *fakeAPIServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)

	// collection endpoint
	if r.URL.Path == basePath && r.Method == http.MethodPost {
		if f.postConflict {
			f.postConflict = false
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		var in fakeObj
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.rv++
		in.Metadata.ResourceVersion = formatRV(f.rv)
		obj := in
		f.objects[in.Metadata.Name] = &obj
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(obj)
		return
	}

	// per-object: /<base>/<name> or /<base>/<name>/status
	parts := strings.TrimPrefix(r.URL.Path, basePath+"/")
	name, rest, _ := strings.Cut(parts, "/")
	isStatus := rest == "status"
	if name == "" {
		name = parts
	}

	switch r.Method {
	case http.MethodGet:
		if f.failGetOnce {
			f.failGetOnce = false
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		if f.getReturns500 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		obj, ok := f.objects[name]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(obj)
	case http.MethodPut:
		if !isStatus {
			http.Error(w, "only status subresource supported", http.StatusMethodNotAllowed)
			return
		}
		if f.failPutOnce {
			f.failPutOnce = false
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		var in fakeObj
		_ = json.NewDecoder(r.Body).Decode(&in)
		obj, ok := f.objects[name]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		obj.Status = in.Status
		f.rv++
		obj.Metadata.ResourceVersion = formatRV(f.rv)
		_ = json.NewEncoder(w).Encode(obj)
	default:
		http.Error(w, "unexpected", http.StatusBadRequest)
	}
}

func formatRV(i int) string {
	return "rv-" + string(rune('0'+i%10)) + string(rune('0'+(i/10)%10))
}

func (f *fakeAPIServer) currentObject(t *testing.T, name string) *fakeObj {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[name]
	if !ok {
		t.Fatalf("object %q not found in fake apiserver", name)
	}
	return obj
}

func (f *fakeAPIServer) callSequence() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func sampleReport() *types.CapabilityReport {
	return &types.CapabilityReport{
		NodeID: "node-a",
		Kernel: types.KernelInfo{
			Version:   "6.6.0",
			LSMs:      []string{"lockdown", "capability", "bpf"},
			CgroupVer: "v2",
			HasBTF:    true,
		},
		Helpers: map[string]string{
			"arch":         "amd64",
			"bpf_fentry":   "yes",
			"kprobe_multi": "no",
		},
		Hooks: []types.HookCap{
			{Kind: "syscall_tracepoint", Name: "sys_enter_execve", Available: true},
			{Kind: "lsm_bpf", Name: "bprm_check_security", Available: false, UnavailableReason: "bpf not in LSM list"},
			{Kind: "kprobe", Name: "security_bprm_check", Available: true},
		},
	}
}

// newPublisher centralizes the httptest wiring — tests care about behavior,
// not the fact that we have to unset TokenFile to skip real auth.
func newPublisher(t *testing.T, srv *httptest.Server, reportFn func() (*types.CapabilityReport, error)) *Publisher {
	t.Helper()
	return &Publisher{
		APIServer:  srv.URL,
		NodeName:   "node-a",
		Interval:   10 * time.Millisecond,
		Report:     reportFn,
		HTTPClient: srv.Client(),
		// TokenFile and CAFile intentionally left zero — setAuth skips
		// when TokenFile=="", and we pre-provide HTTPClient so buildClient
		// isn't invoked.
	}
}

func TestPublisher_ColdStartCreatesAndPutsStatus(t *testing.T) {
	fake, srv := newFakeAPIServer()
	defer srv.Close()
	p := newPublisher(t, srv, func() (*types.CapabilityReport, error) { return sampleReport(), nil })

	if err := p.publishOnce(context.Background()); err != nil {
		t.Fatalf("publishOnce: %v", err)
	}

	// Call order must be: GET (404) → POST (create) → GET (fetch RV) → PUT status.
	got := fake.callSequence()
	want := []string{
		"GET " + basePath + "/node-a",
		"POST " + basePath,
		"GET " + basePath + "/node-a",
		"PUT " + basePath + "/node-a/status",
	}
	if !equalStrings(got, want) {
		t.Fatalf("call sequence mismatch\n got=%v\nwant=%v", got, want)
	}

	obj := fake.currentObject(t, "node-a")
	if obj.Status["kernel"] != "6.6.0" {
		t.Errorf("status.kernel = %v, want 6.6.0", obj.Status["kernel"])
	}
	if obj.Status["bpfLSM"] != true {
		t.Errorf("status.bpfLSM = %v, want true (bpf in LSMs)", obj.Status["bpfLSM"])
	}
	if obj.Status["cgroupV2"] != true {
		t.Errorf("status.cgroupV2 = %v, want true", obj.Status["cgroupV2"])
	}
	if obj.Status["btf"] != true {
		t.Errorf("status.btf = %v, want true", obj.Status["btf"])
	}
	// The one unavailable hook should surface in degraded list.
	degraded, _ := obj.Status["degraded"].([]any)
	if len(degraded) != 1 || degraded[0] != "lsm_bpf:bprm_check_security" {
		t.Errorf("status.degraded = %v, want [lsm_bpf:bprm_check_security]", degraded)
	}
}

func TestPublisher_WarmPathSkipsCreate(t *testing.T) {
	fake, srv := newFakeAPIServer()
	defer srv.Close()
	// Pre-seed: the CR already exists from a prior run.
	fake.objects["node-a"] = &fakeObj{
		Metadata: struct {
			Name            string `json:"name"`
			ResourceVersion string `json:"resourceVersion"`
		}{Name: "node-a", ResourceVersion: "rv-01"},
		Spec: map[string]any{"node": "node-a"},
	}
	p := newPublisher(t, srv, func() (*types.CapabilityReport, error) { return sampleReport(), nil })
	if err := p.publishOnce(context.Background()); err != nil {
		t.Fatalf("publishOnce: %v", err)
	}
	got := fake.callSequence()
	want := []string{
		"GET " + basePath + "/node-a",
		"PUT " + basePath + "/node-a/status",
	}
	if !equalStrings(got, want) {
		t.Fatalf("call sequence mismatch\n got=%v\nwant=%v", got, want)
	}
}

func TestPublisher_PostConflictIsBenign(t *testing.T) {
	fake, srv := newFakeAPIServer()
	defer srv.Close()
	// Simulate two agents racing to create — one loses POST with 409.
	// Next loop will just GET + PUT; the first publishOnce should not
	// return an error.
	fake.postConflict = true
	// A background sidecar "wins" the race and creates the object.
	go func() {
		time.Sleep(5 * time.Millisecond)
		fake.mu.Lock()
		fake.rv++
		fake.objects["node-a"] = &fakeObj{
			Metadata: struct {
				Name            string `json:"name"`
				ResourceVersion string `json:"resourceVersion"`
			}{Name: "node-a", ResourceVersion: formatRV(fake.rv)},
			Spec: map[string]any{"node": "node-a"},
		}
		fake.mu.Unlock()
	}()
	p := newPublisher(t, srv, func() (*types.CapabilityReport, error) { return sampleReport(), nil })
	// publishOnce: GET(404) → POST(409, benign) → GET(success after race) → PUT.
	// The intermediate GET may race; retry until the status is set.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		err := p.publishOnce(context.Background())
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fake.mu.Lock()
	obj := fake.objects["node-a"]
	fake.mu.Unlock()
	if obj == nil || obj.Status["kernel"] == nil {
		t.Fatalf("status never got published — object=%+v", obj)
	}
}

func TestPublisher_GetError_Surfaces(t *testing.T) {
	fake, srv := newFakeAPIServer()
	defer srv.Close()
	fake.getReturns500 = true
	p := newPublisher(t, srv, func() (*types.CapabilityReport, error) { return sampleReport(), nil })
	err := p.publishOnce(context.Background())
	if err == nil {
		t.Fatalf("expected error from GET 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q should include status code", err.Error())
	}
}

func TestPublisher_ReportErrorPropagates(t *testing.T) {
	_, srv := newFakeAPIServer()
	defer srv.Close()
	boom := func() (*types.CapabilityReport, error) { return nil, io.ErrUnexpectedEOF }
	p := newPublisher(t, srv, boom)
	err := p.publishOnce(context.Background())
	if err == nil {
		t.Fatalf("expected Report error to propagate")
	}
	if !strings.Contains(err.Error(), "report") {
		t.Errorf("error should mention 'report', got %q", err.Error())
	}
}

func TestPublisher_RunPublishesOnTick(t *testing.T) {
	fake, srv := newFakeAPIServer()
	defer srv.Close()

	var count int
	var mu sync.Mutex
	report := func() (*types.CapabilityReport, error) {
		mu.Lock()
		count++
		mu.Unlock()
		return sampleReport(), nil
	}

	p := newPublisher(t, srv, report)
	p.Interval = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	// Expect at least the initial publish + one more on the 20ms tick.
	mu.Lock()
	c := count
	mu.Unlock()
	if c < 2 {
		t.Errorf("expected ≥2 Report calls during 80ms run with 20ms interval, got %d", c)
	}

	obj := fake.currentObject(t, "node-a")
	if obj.Status["kernel"] != "6.6.0" {
		t.Errorf("status.kernel = %v", obj.Status["kernel"])
	}
}

func TestPublisher_RequiresNodeNameAndReport(t *testing.T) {
	t.Run("missing NodeName", func(t *testing.T) {
		p := &Publisher{Report: func() (*types.CapabilityReport, error) { return sampleReport(), nil }}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := p.Run(ctx); err == nil {
			t.Fatalf("expected error when NodeName is empty")
		}
	})
	t.Run("missing Report", func(t *testing.T) {
		p := &Publisher{NodeName: "n"}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := p.Run(ctx); err == nil {
			t.Fatalf("expected error when Report is nil")
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
