// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

import (
	"errors"
	"testing"
)

func TestErrStringNilVsMessage(t *testing.T) {
	if got := errString(nil); got != "" {
		t.Errorf("errString(nil) = %q, want empty — a nil lastErr must suppress the exporter_last_error_info series so recovered sinks drop out of /metrics", got)
	}
	if got := errString(errors.New("dial tcp: connection refused")); got != "dial tcp: connection refused" {
		t.Errorf("errString(err) = %q, want verbatim message — the metrics collector applies its own truncation and must see the full text first", got)
	}
}
