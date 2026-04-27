// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package e2e

import (
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

// ----------------------------------------------------------------------------
// Smoke tier (always runs, no kernel involvement)
// ----------------------------------------------------------------------------

// TestE2E_SmokeNoBPF: the always-on smoke test. Runs kloudlens with
// --no-ebpf so it exercises the full Go-side wiring (flag parsing,
// pipeline construction, output writer, graceful --duration shutdown)
// without requiring root. A regression in main.go that broke the
// startup sequence would surface here even on hosts without sudo.
func TestE2E_SmokeNoBPF(t *testing.T) {
	a := startAgent(t, agentOpts{
		UseSudo:  false,
		Args:     []string{"--no-ebpf"},
		Duration: 2 * time.Second,
	})
	intents, stderr := a.wait(t)

	// With --no-ebpf nothing emits intents — the assertion is that the
	// process started, declared readiness, and exited cleanly.
	if !strings.Contains(stderr, "kloudlens: running") {
		t.Errorf("startup banner missing — stderr was:\n%s", stderr)
	}
	if !strings.Contains(stderr, "kloudlens: final ") {
		t.Errorf("shutdown summary missing — stderr was:\n%s", stderr)
	}
	if len(intents) != 0 {
		t.Errorf("--no-ebpf must not emit intents; got %d:\n%s", len(intents), dumpIntents(intents))
	}
}

// TestE2E_SmokeRejectsBadOutputPath: drive the JSONL writer by feeding
// kloudlens an invalid output path; --output must reject the file
// gracefully (exit non-zero) rather than panic. Guards the operator-facing
// CLI surface — a confusing crash would surface as "kloudlens just dies on
// startup".
func TestE2E_SmokeRejectsBadOutputPath(t *testing.T) {
	requireLinux(t)
	bin := binPath(t)

	cmd := exec.Command(bin,
		"--no-ebpf",
		"--duration=1s",
		"--stats-every=0",
		"--output=/nonexistent-dir/intents.jsonl",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for invalid --output, got success\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "intents.jsonl") &&
		!strings.Contains(string(out), "no such file") &&
		!strings.Contains(string(out), "open ") {
		t.Errorf("error message should mention the failed path; got:\n%s", out)
	}
}

// TestE2E_AgentStatsLineWritten asserts the daemon's periodic stats line
// surfaces on stderr when --stats-every is enabled. Operators rely on this
// line to confirm the agent is actually consuming the ringbuf — a regression
// where the goroutine stalled would leave the line absent.
func TestE2E_AgentStatsLineWritten(t *testing.T) {
	requireLinux(t)
	bin := binPath(t)
	cmd := exec.Command(bin,
		"--no-ebpf",
		"--duration=2s",
		"--stats-every=200ms",
		"--output="+filepath.Join(t.TempDir(), "out.jsonl"),
	)
	out, _ := cmd.CombinedOutput()
	// At least one mid-run stats line plus the final summary.
	if strings.Count(string(out), "kloudlens: ") < 2 {
		t.Errorf("expected ≥2 kloudlens log lines, got:\n%s", out)
	}
	// Stats line shape: includes "syscalls=" "intents=" "agg=" tokens.
	if !strings.Contains(string(out), "intents=") {
		t.Errorf("stats line missing 'intents=' token:\n%s", out)
	}
}

// ----------------------------------------------------------------------------
// eBPF tier: real kernel hooks. Skipped when sudo or BPF load is unavailable.
// ----------------------------------------------------------------------------
//
// Design note: assertions here check *patterns* rather than specific triggers.
// During the agent's first ~1s it opens hundreds of /sys/kernel/tracing files
// during BPF setup, which can saturate the crit ringbuf and drop short-lived
// trigger events. We instead verify that the kernel→BPF→user pipeline is
// alive end-to-end:
//
// - intents land in the JSONL stream
// - the expected kind diversity appears (ProcessStart, FileRead(), etc.)
// - every intent carries a well-formed schema (intent_id, timestamps, meta)
// - namespace stamping fires for at least some events
//
// These assertions catch the regressions e2e is meant to catch (BPF object
// drift, JSONL writer path, aggregator emission) without depending on the
// kernel's scheduling of any single short-lived trigger process.

// TestE2E_BPFEmitsAnyIntents: with real eBPF loaded, the agent must observe
// the constant background syscall traffic on the host and emit *some*
// intents. Zero intents would mean the kernel→BPF→ringbuf→user path is
// broken end-to-end — the kind of regression that no unit test can catch.
func TestE2E_BPFEmitsAnyIntents(t *testing.T) {
	requireSudo(t)
	a := startAgent(t, agentOpts{
		UseSudo:  true,
		Args:     []string{"--enrich=proc", "--node=e2e"},
		Duration: 10 * time.Second,
	})
	// Add some trigger noise so the test doesn't depend purely on what
	// other processes happen to be doing on the dev host.
	go backgroundTriggers(t, 8*time.Second)

	intents, stderr := a.wait(t)
	if len(intents) == 0 {
		t.Fatalf("agent emitted zero intents over 10s with active trigger noise — pipeline appears dead.\nstderr:\n%s", stderr)
	}
	t.Logf("observed %d intents over the run window", len(intents))
}

// TestE2E_BPFEmitsExpectedKinds: across the run window the agent should
// emit at least one intent from the expected aggregator kind set. The
// kernel→aggregator pipeline has multiple emit paths (process / file /
// socket); the test fails if NONE of them produced output, which would
// indicate the dispatcher is broken end-to-end.
//
// We log the full distribution so diagnostics are visible even when the
// test passes — operators can see which paths fired during this run.
func TestE2E_BPFEmitsExpectedKinds(t *testing.T) {
	requireSudo(t)
	a := startAgent(t, agentOpts{
		UseSudo:  true,
		Args:     []string{"--enrich=proc"},
		Duration: 20 * time.Second,
	})
	go backgroundTriggers(t, 18*time.Second)

	intents, stderr := a.wait(t)
	if len(intents) == 0 {
		t.Fatalf("no intents emitted in 20s with active triggers — aggregator dispatch is broken.\nstderr:\n%s", stderr)
	}
	kinds := map[string]int{}
	for _, ev := range intents {
		kinds[ev.Kind]++
	}
	expected := []string{"ProcessStart", "FileRead", "FileWrite", "FileAccess", "FileReadWrite", "NetworkExchange", "DNSAnswer"}
	matched := 0
	for _, k := range expected {
		if kinds[k] > 0 {
			matched++
		}
	}
	if matched == 0 {
		t.Errorf("none of the expected intent kinds %v appeared; got %v", expected, kinds)
	}
	t.Logf("kind distribution: %v (matched %d/%d expected kinds)", kinds, matched, len(expected))
}

// TestE2E_BPFIntentSchemaShape: every intent the JSONL writer emits must
// carry the schema downstream consumers (klctl, aggregator, exporters)
// expect — intent_id is non-empty, the timestamps make sense, kind is one
// of the known set, and the meta block is present even when its fields are
// zero-valued. This guards the wire contract end-to-end: a regression in
// emit that dropped a field would silently corrupt every downstream sink.
func TestE2E_BPFIntentSchemaShape(t *testing.T) {
	requireSudo(t)
	a := startAgent(t, agentOpts{
		UseSudo:  true,
		Args:     []string{"--enrich=proc"},
		Duration: 14 * time.Second,
	})
	go backgroundTriggers(t, 12*time.Second)

	intents, stderr := a.wait(t)
	if len(intents) == 0 {
		t.Fatalf("no intents emitted; stderr:\n%s", stderr)
	}
	knownKinds := map[string]bool{
		"ProcessStart": true, "FileRead": true, "FileWrite": true,
		"FileReadWrite": true, "FileAccess": true, "NetworkExchange": true,
		"DNSAnswer": true,
		// Cap and other kinds the aggregator may add in the future are
		// allowed via the explicit checked set below; an unknown kind
		// fails the test so silent drift surfaces.
	}
	bad := 0
	for i, ev := range intents {
		if ev.IntentID == "" {
			t.Errorf("intent[%d] has empty intent_id: %+v", i, ev)
			bad++
		}
		if ev.Kind == "" {
			t.Errorf("intent[%d] has empty kind", i)
			bad++
		} else if !knownKinds[ev.Kind] {
			t.Errorf("intent[%d] has unexpected kind=%q (drift in aggregator emit set?)", i, ev.Kind)
			bad++
		}
		// Timestamps may be zero for synthesized intents, but must not be reversed.
		if ev.EndNS != 0 && ev.StartNS != 0 && ev.EndNS < ev.StartNS {
			t.Errorf("intent[%d] has end_ns=%d < start_ns=%d", i, ev.EndNS, ev.StartNS)
			bad++
		}
		if bad > 5 {
			t.Logf("(stopping schema check after 5 failures of %d intents)", len(intents))
			break
		}
	}
	if bad == 0 {
		t.Logf("validated %d intents — all schema-compliant", len(intents))
	}
	_ = stderr
}

// TestE2E_BPFNamespaceStamping: confirm at least one observed intent
// carries a non-zero (pid_ns, mnt_ns) pair — the BPF should_monitor
// helper reads namespaces from task_struct, the aggregator copies them
// into ContainerMeta, and the writer marshals them as meta.pidns/mntns.
// Zero everywhere would mean the chain broke at one of those steps.
//
// The host shell's namespace numbers are 4026531xxx; container namespaces
// are higher. We accept either — the assertion is just "namespace fields
// flowed through, value > 0".
func TestE2E_BPFNamespaceStamping(t *testing.T) {
	requireSudo(t)
	a := startAgent(t, agentOpts{
		UseSudo:  true,
		Args:     []string{"--enrich=proc"},
		Duration: 14 * time.Second,
	})
	go backgroundTriggers(t, 12*time.Second)

	intents, stderr := a.wait(t)
	if len(intents) == 0 {
		t.Fatalf("no intents emitted; stderr:\n%s", stderr)
	}
	var pidNS, mntNS uint32
	for _, ev := range intents {
		if ev.Meta.PidNS != 0 {
			pidNS = ev.Meta.PidNS
		}
		if ev.Meta.MntNS != 0 {
			mntNS = ev.Meta.MntNS
		}
		if pidNS != 0 && mntNS != 0 {
			break
		}
	}
	if pidNS == 0 {
		t.Errorf("no intent carried a non-zero meta.pidns — namespace stamping appears broken across %d intents", len(intents))
	}
	if mntNS == 0 {
		t.Errorf("no intent carried a non-zero meta.mntns")
	}
	t.Logf("observed sample namespaces: pidns=%d mntns=%d (over %d intents)", pidNS, mntNS, len(intents))
}

// TestE2E_BPFFilePathAttribution: the BPF file hooks must pass the open
// path through the str-cache and aggregator into intent.attributes.path.
// Some intents will have an empty path (close-without-open, evicted str
// cache), but the aggregate must include at least one File* intent with
// a non-empty path — otherwise the path-resolution chain is broken.
func TestE2E_BPFFilePathAttribution(t *testing.T) {
	requireSudo(t)
	a := startAgent(t, agentOpts{
		UseSudo:  true,
		Args:     []string{"--enrich=proc"},
		Duration: 14 * time.Second,
	})
	go backgroundTriggers(t, 12*time.Second)

	intents, stderr := a.wait(t)
	pathCount := 0
	var sample string
	for _, ev := range intents {
		if !strings.HasPrefix(ev.Kind, "File") {
			continue
		}
		if p := ev.Attributes["path"]; p != "" {
			pathCount++
			if sample == "" {
				sample = p
			}
		}
	}
	if pathCount == 0 {
		t.Fatalf("no File* intent carried a non-empty path attribute over %d total intents — path attribution appears broken.\nstderr:\n%s",
			len(intents), stderr)
	}
	t.Logf("%d File* intents carried a path attribute (e.g. %q)", pathCount, sample)
}

// TestE2E_BPFProcessExecAttributes: backgroundTriggers runs ~80
// /usr/bin/which invocations through the kernel during the window, so the
// exec hook must catch at least one and surface it as a ProcessStart with
// an absolute attributes.binary. Zero ProcessStart intents = exec hook
// or aggregator finalize-exec path is broken; that's a regression worth
// failing on rather than skipping past.
func TestE2E_BPFProcessExecAttributes(t *testing.T) {
	requireSudo(t)
	a := startAgent(t, agentOpts{
		UseSudo:  true,
		Args:     []string{"--enrich=proc"},
		Duration: 14 * time.Second,
	})
	go backgroundTriggers(t, 12*time.Second)

	intents, stderr := a.wait(t)
	var seen []types.IntentEvent
	for _, ev := range intents {
		if ev.Kind == "ProcessStart" {
			seen = append(seen, ev)
		}
	}
	if len(seen) == 0 {
		t.Fatalf("no ProcessStart intents over a window with ~80 /usr/bin/which triggers — exec hook or FinalizeExec path is broken.\nobserved %d intents of other kinds: %v\nstderr:\n%s",
			len(intents), kindCounts(intents), stderr)
	}
	withBinary := 0
	for _, ev := range seen {
		bin := ev.Attributes["binary"]
		if bin == "" {
			continue
		}
		if !strings.HasPrefix(bin, "/") {
			t.Errorf("ProcessStart binary not absolute: %q", bin)
			continue
		}
		withBinary++
	}
	if withBinary == 0 {
		t.Errorf("of %d ProcessStart intents, none had a non-empty binary attribute", len(seen))
	}
	t.Logf("%d/%d ProcessStart intents had a /-rooted binary attribute", withBinary, len(seen))
}

// TestE2E_BPFNetworkConnect: ~40 TCP connects to a localhost listener
// during the window. The agent must catch at least one and surface it
// as a NetworkExchange with a non-empty peer attribute. Zero
// NetworkExchange = the socket connect hook or aggregator emitSock path
// is broken — fail rather than skip.
func TestE2E_BPFNetworkConnect(t *testing.T) {
	requireSudo(t)
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := lis.Addr().String()

	a := startAgent(t, agentOpts{
		UseSudo:  true,
		Args:     []string{"--enrich=proc"},
		Duration: 14 * time.Second,
	})
	go backgroundTriggers(t, 12*time.Second)
	// Dedicated connect loop on top of backgroundTriggers' own connects so
	// we get a deterministic burst against the listener we control.
	go func() {
		time.Sleep(2 * time.Second)
		for i := 0; i < 40; i++ {
			c, err := net.DialTimeout("tcp4", addr, time.Second)
			if err != nil {
				return
			}
			_ = c.Close()
			time.Sleep(150 * time.Millisecond)
		}
	}()

	intents, stderr := a.wait(t)
	var nx []types.IntentEvent
	for _, ev := range intents {
		if ev.Kind == "NetworkExchange" {
			nx = append(nx, ev)
		}
	}
	if len(nx) == 0 {
		t.Fatalf("no NetworkExchange intents over a window with ~40 localhost connects — socket connect hook or aggregator emitSock path is broken.\nobserved %d intents of other kinds: %v\nstderr:\n%s",
			len(intents), kindCounts(intents), stderr)
	}
	withPeer := 0
	for _, ev := range nx {
		if ev.Attributes["peer"] != "" {
			withPeer++
		}
	}
	if withPeer == 0 {
		t.Errorf("of %d NetworkExchange intents, none carried a peer attribute", len(nx))
	}
	t.Logf("%d/%d NetworkExchange intents had a peer attribute", withPeer, len(nx))
}

// ----------------------------------------------------------------------------
// Trigger helpers
// ----------------------------------------------------------------------------

// kindCounts is a tiny helper that summarizes which Intent kinds appeared
// and how many of each — used in failure messages so the operator can see
// which dispatch path silently dropped events without rerunning with -v.
func kindCounts(intents []types.IntentEvent) map[string]int {
	out := map[string]int{}
	for _, ev := range intents {
		out[ev.Kind]++
	}
	return out
}

// backgroundTriggers feeds steady, varied syscall traffic into the kernel
// for `dur` so the agent's hooks have something to observe. Every trigger
// is from a child process with its own TGID, giving the aggregator clean
// keys per emission. We mix file I/O, exec, and network connect because
// each routes through a different aggregator key class, so the variety
// gives every kind path a chance to fire.
func backgroundTriggers(t *testing.T, dur time.Duration) {
	t.Helper()
	end := time.Now().Add(dur)
	dir := t.TempDir()

	// Tiny localhost listener so the network triggers actually have a
	// peer to talk to. Closed when this helper returns.
	lis, lerr := net.Listen("tcp4", "127.0.0.1:0")
	if lerr == nil {
		defer lis.Close()
		go func() {
			for {
				c, aerr := lis.Accept()
				if aerr != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	for i := 0; time.Now().Before(end); i++ {
		// File I/O — open + write + close + read in a short shell script.
		// Spawned via /bin/sh so we cycle through new TGIDs each iteration.
		path := filepath.Join(dir, fmt.Sprintf("trigger-%d", i))
		_ = exec.Command("sh", "-c",
			fmt.Sprintf("echo hello > %q && cat %q > /dev/null", path, path),
		).Run()
		// Exec — /usr/bin/which reads PATH and writes one line of stdout,
		// giving the BPF hook a few syscalls to attach state to. Pure
		// /bin/true exits before the exec_exit hook can finalize state on
		// some kernels, so we use /usr/bin/which as a more reliable
		// exec-pulse generator.
		_ = exec.Command("/usr/bin/which", "true").Run()
		// Network — a one-shot connect+close. With ringbuf pressure on
		// the crit ring the socket hooks can drop these on early
		// iterations, so we keep the cadence going across the whole
		// window.
		if lis != nil {
			c, derr := net.DialTimeout("tcp4", lis.Addr().String(), 200*time.Millisecond)
			if derr == nil {
				_ = c.Close()
			}
		}
		time.Sleep(120 * time.Millisecond)
	}
}
