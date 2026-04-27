// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"testing"
	"time"

	"github.com/boanlab/kloudlens/pkg/types"
)

func findKind(cs []types.Correlation, kind string) *types.Correlation {
	for i := range cs {
		if cs[i].Kind == kind {
			return &cs[i]
		}
	}
	return nil
}

func TestFileWrittenThenExecuted(t *testing.T) {
	current := time.Unix(100, 0)
	d := New(Config{Window: 10 * time.Second, Clock: func() time.Time { return current }})

	d.RecordFileWrite(42, "/tmp/payload", 0xBEEF, current)
	current = current.Add(2 * time.Second)
	out := d.CheckExec(42, "/tmp/payload", 0xBEEF, current)

	c := findKind(out, KindFileWrittenThenExecuted)
	if c == nil {
		t.Fatalf("expected %s, got %+v", KindFileWrittenThenExecuted, out)
	}
	if c.RefID != "/tmp/payload" {
		t.Fatalf("refid: %s", c.RefID)
	}
}

func TestFileWrittenThenExecutedMatchByInodeAlone(t *testing.T) {
	current := time.Unix(0, 0)
	d := New(Config{Window: 30 * time.Second, Clock: func() time.Time { return current }})
	d.RecordFileWrite(1, "/var/tmp/orig", 777, current)
	// Exec via different path (maybe renamed) but same inode still correlates.
	out := d.CheckExec(1, "/var/tmp/moved", 777, current)
	if findKind(out, KindFileWrittenThenExecuted) == nil {
		t.Fatalf("inode-based match missing: %+v", out)
	}
}

func TestFileWrittenThenExecutedWindowExpiry(t *testing.T) {
	current := time.Unix(0, 0)
	d := New(Config{Window: 5 * time.Second, Clock: func() time.Time { return current }})
	d.RecordFileWrite(1, "/tmp/a", 1, current)
	current = current.Add(10 * time.Second)
	out := d.CheckExec(1, "/tmp/a", 1, current)
	if len(out) != 0 {
		t.Fatalf("expected no correlation after window expiry, got %+v", out)
	}
}

func TestConnectAfterDNS(t *testing.T) {
	current := time.Unix(0, 0)
	d := New(Config{Window: 30 * time.Second, Clock: func() time.Time { return current }})
	d.RecordDNSAnswer("1.2.3.4", "evil.example", current)
	current = current.Add(3 * time.Second)
	out := d.CheckConnect(5, "1.2.3.4", current)
	if len(out) != 1 || out[0].Kind != KindConnectAfterDNS {
		t.Fatalf("expected connect_after_dns, got %+v", out)
	}
	if out[0].RefID != "1.2.3.4" {
		t.Fatalf("ref: %s", out[0].RefID)
	}
}

func TestConnectAfterDNSNegative(t *testing.T) {
	now := time.Unix(0, 0)
	d := New(Config{Window: 10 * time.Second, Clock: func() time.Time { return now }})
	d.RecordDNSAnswer("1.2.3.4", "good.example", now)
	out := d.CheckConnect(5, "9.9.9.9", now)
	if len(out) != 0 {
		t.Fatalf("mismatched IP should not correlate: %+v", out)
	}
}

func TestExecAfterChmodX(t *testing.T) {
	current := time.Unix(0, 0)
	d := New(Config{Window: 10 * time.Second, Clock: func() time.Time { return current }})
	d.RecordChmodX("/tmp/dropper.sh", current)
	current = current.Add(time.Second)
	out := d.CheckExec(1, "/tmp/dropper.sh", 0, current)
	if findKind(out, KindExecAfterChmodX) == nil {
		t.Fatalf("expected %s, got %+v", KindExecAfterChmodX, out)
	}
}

func TestReadSensitiveBeforeSend(t *testing.T) {
	current := time.Unix(0, 0)
	d := New(Config{Window: 30 * time.Second, Clock: func() time.Time { return current }})
	d.RecordSensitiveRead(7, "/var/log/app.log", current) // ignored (not sensitive)
	d.RecordSensitiveRead(7, "/etc/shadow", current)
	current = current.Add(5 * time.Second)
	out := d.CheckNetworkSend(7, current)
	if len(out) != 1 || out[0].Kind != KindReadSensitiveBeforeSend {
		t.Fatalf("expected read_sensitive_before_send, got %+v", out)
	}
	if out[0].RefID != "/etc/shadow" {
		t.Fatalf("ref: %s", out[0].RefID)
	}
}

func TestReadSensitiveBeforeSendIgnoresNonSensitive(t *testing.T) {
	now := time.Unix(0, 0)
	d := New(Config{Clock: func() time.Time { return now }})
	d.RecordSensitiveRead(1, "/tmp/harmless.txt", now)
	out := d.CheckNetworkSend(1, now)
	if len(out) != 0 {
		t.Fatalf("non-sensitive read should not trigger: %+v", out)
	}
}

func TestPrivilegeEscalationWindow(t *testing.T) {
	current := time.Unix(0, 0)
	d := New(Config{Window: 10 * time.Second, Clock: func() time.Time { return current }})
	d.RecordSetuidRoot(99, current)
	current = current.Add(2 * time.Second)
	if findKind(d.CheckExec(99, "/bin/cat", 0, current), KindPrivEscalationWindow) == nil {
		t.Fatalf("priv esc missing on exec")
	}
	if findKind(d.CheckConnect(99, "1.1.1.1", current), KindPrivEscalationWindow) == nil {
		t.Fatalf("priv esc missing on connect")
	}
	if findKind(d.CheckNetworkSend(99, current), KindPrivEscalationWindow) == nil {
		t.Fatalf("priv esc missing on send")
	}
}

func TestPrivilegeEscalationWindowExpires(t *testing.T) {
	current := time.Unix(0, 0)
	d := New(Config{Window: 5 * time.Second, Clock: func() time.Time { return current }})
	d.RecordSetuidRoot(3, current)
	current = current.Add(20 * time.Second)
	if findKind(d.CheckExec(3, "/bin/ls", 0, current), KindPrivEscalationWindow) != nil {
		t.Fatalf("priv esc should have expired")
	}
}

func TestEnabledGateDisablesHeuristic(t *testing.T) {
	now := time.Unix(0, 0)
	d := New(Config{
		Window:  10 * time.Second,
		Enabled: map[string]bool{KindConnectAfterDNS: true}, // only DNS→connect enabled
		Clock:   func() time.Time { return now },
	})
	d.RecordFileWrite(1, "/tmp/x", 1, now)
	if out := d.CheckExec(1, "/tmp/x", 1, now); len(out) != 0 {
		t.Fatalf("disabled heuristic fired: %+v", out)
	}
	d.RecordDNSAnswer("1.1.1.1", "q", now)
	if out := d.CheckConnect(1, "1.1.1.1", now); len(out) != 1 {
		t.Fatalf("enabled heuristic missing: %+v", out)
	}
}

func TestSizesAndLazySweep(t *testing.T) {
	current := time.Unix(0, 0)
	d := New(Config{Window: 5 * time.Second, Clock: func() time.Time { return current }})
	d.RecordFileWrite(1, "/tmp/a", 1, current)
	d.RecordDNSAnswer("1.2.3.4", "q", current)
	d.RecordChmodX("/tmp/b", current)
	d.RecordSensitiveRead(1, "/etc/shadow", current)
	d.RecordSetuidRoot(1, current)
	if sz := d.Sizes(); sz.Writes != 1 || sz.DNS != 1 || sz.ChmodX != 1 || sz.SensReadsPids != 1 || sz.SetuidRoots != 1 {
		t.Fatalf("sizes: %+v", sz)
	}
	current = current.Add(30 * time.Second)
	sz := d.Sizes()
	if sz.Writes != 0 || sz.DNS != 0 || sz.ChmodX != 0 || sz.SensReadsPids != 0 || sz.SetuidRoots != 0 {
		t.Fatalf("expected all swept, got: %+v", sz)
	}
}

// TestEnabledFromNames asserts the policy-list → Config.Enabled mapping
// honors nil (all on) vs empty (all off) vs named-subset semantics.
// HookSubscription.Spec.Enrichment.Correlations is parse-validated via
// KnownKinds, so this helper only has to preserve the three-state
// interpretation the Detector already uses internally.
func TestEnabledFromNames(t *testing.T) {
	if got := EnabledFromNames(nil); got != nil {
		t.Errorf("nil slice should map to nil (all enabled), got %v", got)
	}
	empty := EnabledFromNames([]string{})
	if empty == nil || len(empty) != 0 {
		t.Errorf("empty slice should map to empty non-nil map (all disabled), got %v", empty)
	}
	subset := EnabledFromNames([]string{KindExecAfterChmodX, KindConnectAfterDNS})
	if !subset[KindExecAfterChmodX] || !subset[KindConnectAfterDNS] {
		t.Errorf("listed heuristics should be true: %v", subset)
	}
	if subset[KindFileWrittenThenExecuted] {
		t.Errorf("unlisted heuristic should not be set: %v", subset)
	}
}

// TestSetEnabledRuntimeSwap confirms Detector.SetEnabled gates heuristics
// at the next observation. ApplyPolicy calls this when a HookSubscription's
// enrichment.correlations list changes at runtime — without it, operators
// would need to restart the agent to add/remove a heuristic.
func TestSetEnabledRuntimeSwap(t *testing.T) {
	current := time.Unix(100, 0)
	d := New(Config{Window: 30 * time.Second, Clock: func() time.Time { return current }})

	// All-on (default): file_written_then_executed fires on exec of a
	// recently-written path.
	d.RecordFileWrite(1, "/tmp/a", 1, current)
	current = current.Add(time.Second)
	if findKind(d.CheckExec(1, "/tmp/a", 1, current), KindFileWrittenThenExecuted) == nil {
		t.Fatal("default config should emit file_written_then_executed")
	}

	// Disable only the chmod heuristic: fwx should still fire.
	d.SetEnabled(EnabledFromNames([]string{KindFileWrittenThenExecuted}))
	d.RecordFileWrite(2, "/tmp/b", 2, current)
	current = current.Add(time.Second)
	out := d.CheckExec(2, "/tmp/b", 2, current)
	if findKind(out, KindFileWrittenThenExecuted) == nil {
		t.Fatal("enabled heuristic must still fire after SetEnabled")
	}

	// Switch to an all-off policy (empty non-nil map). Nothing should fire.
	d.SetEnabled(EnabledFromNames([]string{}))
	d.RecordFileWrite(3, "/tmp/c", 3, current)
	current = current.Add(time.Second)
	if len(d.CheckExec(3, "/tmp/c", 3, current)) != 0 {
		t.Fatal("empty-list policy must disable every heuristic")
	}

	// Restore default (nil map) and verify.
	d.SetEnabled(nil)
	d.RecordFileWrite(4, "/tmp/d", 4, current)
	current = current.Add(time.Second)
	if findKind(d.CheckExec(4, "/tmp/d", 4, current), KindFileWrittenThenExecuted) == nil {
		t.Fatal("SetEnabled(nil) should restore all-on default")
	}
}
