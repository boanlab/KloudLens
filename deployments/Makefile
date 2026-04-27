# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ DKU
#
# deployments/Makefile — produces the single-file kubectl-applyable
# release manifest from the CRDs + DaemonSet YAML in this directory.
#
# Targets:
#   flat-manifest — concatenates crds/*.yaml + manifests/*.yaml and
#                   rewrites the image tag to $(VERSION). Output:
#                   dist/kloudlens-$(VERSION).yaml.
#   clean         — remove dist/.

VERSION   ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
IMAGE     ?= boanlab/kloudlens
DIST_DIR  := ../dist
CRD_DIR   := crds
MANIFEST_DIR := manifests

.PHONY: flat-manifest clean

flat-manifest:
	@mkdir -p $(DIST_DIR)
	@OUT="$(DIST_DIR)/kloudlens-$(VERSION).yaml"; \
	( for f in $(CRD_DIR)/*.yaml; do cat "$$f"; echo '---'; done; \
	  for f in $(MANIFEST_DIR)/*.yaml; do \
	    sed "s#docker.io/boanlab/kloudlens:[a-zA-Z0-9._-]*#docker.io/$(IMAGE):$(VERSION)#g" "$$f"; \
	    echo '---'; \
	  done ) > "$$OUT"; \
	echo "wrote $$OUT"

clean:
	rm -rf $(DIST_DIR)
