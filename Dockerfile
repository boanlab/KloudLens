# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

### Builder Stage

FROM golang:1.24-alpine3.21 AS builder

RUN apk --no-cache update && apk --no-cache add make gcc musl-dev

# Build context is the KloudLens repo root, which is also the Go module
# root (go.mod sits at the top level).
WORKDIR /src
COPY . .

ARG VERSION=dev
RUN go mod download && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-X main.defaultVersion=${VERSION}" -o /out/kloudlens ./cmd/kloudlens

### Final Stage

FROM alpine:3.21

# crictl is invoked by the enricher's CRI snapshotter to map containerID
# → pod name/namespace/labels. Without it, --enrich=cri silently degrades
# to ContainerID-only enrichment (cri cache stays at size 0 and DNSAnswer
# events have no pod metadata even when cgroup_id resolves).
ARG CRICTL_VERSION=v1.30.0
RUN apk --no-cache update && \
    apk --no-cache add bash ca-certificates curl && \
    curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz" \
      | tar -xz -C /usr/local/bin && \
    apk --no-cache del curl && \
    rm -rf /var/cache/apk/*

COPY --from=builder /out/kloudlens /usr/local/bin/kloudlens

ENTRYPOINT ["/usr/local/bin/kloudlens"]
