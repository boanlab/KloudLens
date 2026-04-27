# tests/e2e — KloudLens end-to-end tests

These tests build the `kloudlens` binary, run it against the live kernel
(or with `--no-ebpf` for the always-runnable smoke tier), then assert
the JSONL intent stream carries the expected shape, kinds, and metadata.

## Tiers

- **Smoke** — runs without root by passing `--no-ebpf`. Verifies CLI
 parsing, pipeline construction, JSONL writer, stats line, and graceful
 `--duration` shutdown. These are always expected to pass; a failure
 here means the `cmd/kloudlens` package or its glue code regressed.

- **eBPF** — runs the real BPF object via `sudo -n`. Requires
 passwordless sudo and a kernel that loads the BPF programs in
 `internal/sensor/bpf/kloudlens_x86_bpfel.o`. When the load fails the
 test fails with the kernel verifier message AND a hint pointing at
 `--skip-bpf-programs` so the operator can isolate the offending
 program quickly.

## Running

```bash
# Whole suite (smoke + eBPF):
go test ./tests/e2e/... -count=1 -v -timeout=300s

# Smoke only:
go test ./tests/e2e/... -count=1 -v -run TestE2E_Smoke

# eBPF only:
go test ./tests/e2e/... -count=1 -v -run TestE2E_BPF -timeout=300s
```

Pass `-v` to see the per-test diagnostics (intent counts, observed
kind distributions, sample paths). Failure messages always include the
captured kloudlens stderr so the cause shows up without rerunning.

## Configuration

| env var | effect |
|-----------------------|----------------------------------------------------------|
| `KLOUDLENS_E2E_BIN` | Use a pre-built kloudlens binary instead of `go build`-ing into `/tmp`. |

## Assertion philosophy

The eBPF tests drive deterministic syscalls (`/usr/bin/which`, file
open/close via `/bin/sh`, TCP connects to a localhost listener) for
the duration of the run window, then assert the agent surfaced *at
least one* intent of the corresponding kind. The runner counts those
triggers in dozens (e.g. ~80 exec triggers, ~40 TCP connects) so a
single observed event is well below the noise floor — zero hits means
the kernel hook, the bridge, or the aggregator silently dropped
everything, which is exactly the kind of regression e2e is meant to
catch.

We do NOT assert that any *specific* trigger landed — during the
agent's first ~1s it opens hundreds of `/sys/kernel/tracing/events/`
files for BPF setup, which can saturate the crit ringbuf and drop
specific short-lived syscalls. Counting "ProcessStart for binary X"
would therefore be flaky in a way that's not the codebase's fault.
Counting "any ProcessStart from 80 exec triggers" stays robust.

## Notes on the BPF object

`defaultBPFSkip` in `runner.go` is the single place to declare BPF
programs the runner should pass to `--skip-bpf-programs`. It is
currently empty; add entries here if a specific kernel rejects a
program so the test bodies don't need to change.
