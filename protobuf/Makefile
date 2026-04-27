# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

PROTO   := event.proto
PB_GO   := event.pb.go
GRPC_GO := event_grpc.pb.go

PROTOC         := $(shell which protoc)
PROTOC_GEN_GO  := $(shell which protoc-gen-go)
PROTOC_GEN_GRPC:= $(shell which protoc-gen-go-grpc)

.PHONY: all build clean

all: build

build: $(PB_GO) $(GRPC_GO)

$(PB_GO) $(GRPC_GO): $(PROTO)
ifndef PROTOC
	sudo apt install -y protobuf-compiler
endif
ifndef PROTOC_GEN_GO
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
endif
ifndef PROTOC_GEN_GRPC
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
endif
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO)

clean:
	rm -f $(PB_GO) $(GRPC_GO)
