# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

IMAGE_NAME = boanlab/kloudlens
TAG ?= latest

.PHONY: build
build: bpf gofmt golangci-lint gosec
	go mod tidy
	CGO_ENABLED=0 go build -ldflags "-X main.defaultVersion=$(TAG)" -o bin/kloudlens ./cmd/kloudlens

# Protobuf code generation lives in its own module under protobuf/.
# Only contributors editing protobuf/event.proto need to run this; the
# committed .pb.go files are the source of truth for ordinary builds.
.PHONY: proto
proto:
	$(MAKE) -C protobuf

.PHONY: proto-clean
proto-clean:
	$(MAKE) -C protobuf clean

.PHONY: bpf
bpf:
	cd bpf; make

.PHONY: gofmt
gofmt:
	cd $(CURDIR); gofmt -w -s -d $(shell find . -type f -name '*.go' -print)

.PHONY: golangci-lint
golangci-lint:
ifeq (, $(shell which golangci-lint))
	@{ \
	set -e ;\
	GOLANGCI_LINT_TEMP_DIR=$$(mktemp -d) ;\
	cd $$GOLANGCI_LINT_TEMP_DIR ;\
	go mod init tmp ;\
	go get github.com/golangci/golangci-lint/v2/cmd/golangci-lint ;\
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint ;\
	rm -rf $$GOLANGCI_LINT_TEMP_DIR ;\
	}
endif
	cd $(CURDIR); golangci-lint run

.PHONY: gosec
gosec:
ifeq (, $(shell which gosec))
	@{ \
	set -e ;\
	GOSEC_TEMP_DIR=$$(mktemp -d) ;\
	cd $$GOSEC_TEMP_DIR ;\
	go mod init tmp ;\
	go get github.com/securego/gosec/v2/cmd/gosec ;\
	go install github.com/securego/gosec/v2/cmd/gosec ;\
	rm -rf $$GOSEC_TEMP_DIR ;\
	}
endif
	cd $(CURDIR); gosec -quiet -exclude-generated ./...

.PHONY: test
test:
	go test ./... -v -count=1

WAL_DIR        ?= /tmp/kloudlens-wal
METRICS_ADDR   ?= :9090
SUBSCRIBE_ADDR ?= :9443
ADMIN_ADDR     ?= :9444

.PHONY: run
run:
	sudo -E bin/kloudlens \
		--enrich=proc \
		--metrics-addr=$(METRICS_ADDR) \
		--subscribe-addr=$(SUBSCRIBE_ADDR) \
		--wal-dir=$(WAL_DIR) \
		--admin-addr=$(ADMIN_ADDR)

.PHONY: clean
clean:
	cd bpf; make clean
	rm -rf bin

.PHONY: build-image
build-image:
	docker build --build-arg VERSION=$(TAG) -t $(IMAGE_NAME):$(TAG) -t $(IMAGE_NAME):latest -f Dockerfile .

.PHONY: push-image
push-image: build-image
	docker push $(IMAGE_NAME):$(TAG)
ifneq ($(TAG),latest)
	docker push $(IMAGE_NAME):latest
endif

.PHONY: clean-image
clean-image:
	docker rmi $(IMAGE_NAME):$(TAG)
ifneq ($(TAG),latest)
	docker rmi $(IMAGE_NAME):latest
endif
