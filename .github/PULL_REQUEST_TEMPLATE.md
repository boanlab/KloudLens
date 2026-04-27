## Summary

<!-- What does this PR do? One or two sentences. -->

Closes #<!-- issue number -->

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring (no behavior change)
- [ ] Documentation
- [ ] Build / CI

## Changes

<!-- List the key changes. Be specific about modified files or subsystems. -->

-

## Testing

- [ ] `make gofmt golangci-lint gosec test` passes (from the repo root)
- [ ] If `.proto` changed: `make proto` ran cleanly and the regenerated `protobuf/*.pb.go` is committed
- [ ] Live eBPF smoke ran where relevant (`KLOUDLENS_LIVE_SENSOR=1 go test ./internal/sensor/...`)
- [ ] Manual test: <!-- describe what you ran -->

## CLI-side impact

<!-- Does this PR change a gRPC verb, IR field, or other contract the
 klctl CLI depends on? If yes, link the matching kloudlens-cli PR. -->

- [ ] Self-contained (agent only)
- [ ] Needs a kloudlens-cli PR: <!-- link -->

## Notes for Reviewers

<!-- Anything the reviewer should pay attention to: tricky logic, known limitations, follow-up items. -->
