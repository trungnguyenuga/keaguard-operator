# Default local image name for manager builds and runtime rendering.
IMG ?= keaguard-operator:m1-test
# YEAR defines the year value used for substituting the YEAR placeholder in the boilerplate header.
YEAR ?= $(shell date +%Y)

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate the namespaced runtime Role and separate CRD.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./api/...;./internal/controller/..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths="./api/..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test test-unit test-envtest
test: test-unit test-envtest ## Run local unit and API integration suites.

test-unit: toolchain-check ## Run unit tests without a control plane or cluster.
	go test ./api/... ./cmd/... ./internal/controller/... ./test/e2e -run '^TestUnit' -count=1

test-envtest: toolchain-check envtest ## Run envtest with installed, pinned assets only.
	KUBEBUILDER_ASSETS="$$("$(ENVTEST)" use -i $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test ./internal/controller -run '^TestControllers$$' -count=1 -timeout=15m -ginkgo.timeout=14m -ginkgo.focus='$(GINKGO_FOCUS)'

# All Kind operations require the explicit disposable selection; never create/delete implicitly.
.PHONY: kind-image-required kind-create test-kind
# The amended M2 profile needs a serial 70-minute Ginkgo budget inside the
# 75-minute Go process limit. Keep the existing M1 bounds unchanged.
ifeq ($(KEAGUARD_E2E_MILESTONE),m2)
KIND_GO_TIMEOUT := 75m
KIND_GINKGO_TIMEOUT := 70m
else
KIND_GO_TIMEOUT := 25m
KIND_GINKGO_TIMEOUT := 24m
endif

kind-image-required:
	@case "$(origin IMG)" in "command line"|"environment") ;; *) echo 'explicit IMG= required for Kind' >&2; exit 1;; esac
	@test -n "$(strip $(IMG))" || { echo 'explicit IMG= required for Kind' >&2; exit 1; }

kind-create: kind-image-required toolchain-check
	KEAGUARD_KIND_CREATE=1 IMG="$(IMG)" go test ./test/e2e -run '^TestKindCreate$$' -count=1 -timeout=6m -v

test-kind: kind-image-required toolchain-check
	@test "$${KEAGUARD_E2E:-}" = 1 || { echo 'KEAGUARD_E2E=1 is required' >&2; exit 1; }
	IMG="$(IMG)" go test ./test/e2e -run '^TestE2E$$' -count=1 -timeout=$(KIND_GO_TIMEOUT) -ginkgo.timeout=$(KIND_GINKGO_TIMEOUT) -ginkgo.focus='$(GINKGO_FOCUS)' -v

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

# The Dockerfile pins both image digests and the Linux amd64 compiler.
.PHONY: docker-build
docker-build: toolchain-check ## Build the digest-pinned M1 manager image locally.
ifneq ($(strip $(BUILD_IID_FILE)),)
ifneq ($(BUILD_IID_FILE),/tmp/keaguard-m2-acceptance/manager-image.iid)
$(error BUILD_IID_FILE must use the reviewed private M2 path)
endif
	@test -d /tmp/keaguard-m2-acceptance && test ! -L /tmp/keaguard-m2-acceptance
	@test "$$(stat -c %a /tmp/keaguard-m2-acceptance)" = 700
	@test ! -e /tmp/keaguard-m2-acceptance/manager-image.iid && test ! -L /tmp/keaguard-m2-acceptance/manager-image.iid
	bash hack/m2-docker-build-env.sh /tmp/keaguard-m2-acceptance /tmp/keaguard-m2-acceptance/docker-config /tmp/keaguard-m2-acceptance/docker-build-config -- $(CONTAINER_TOOL) build --platform=linux/amd64 --iidfile /tmp/keaguard-m2-acceptance/manager-image.iid -t ${IMG} .
else
	$(CONTAINER_TOOL) build --platform=linux/amd64 -t ${IMG} .
endif

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.22.0

# Verified nested-module tag resolves to controller-runtime commit
# 5d8467b3065818a3b382d8f6941147a801fd1969 (not inferred from root tag).
ENVTEST_VERSION := v0.25.2
ENVTEST_K8S_VERSION := 1.37.0

GOLANGCI_LINT_VERSION ?= v2.13.1
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: toolchain-check $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use -i $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		$(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

.PHONY: toolchain-check
toolchain-check: ## Verify the approved local compiler and platform.
	@test "$${GOTOOLCHAIN:-}" = local || { echo 'GOTOOLCHAIN=local is required' >&2; exit 1; }
	@test "$$(go env GOVERSION GOOS GOARCH GOTOOLCHAIN)" = "$$(printf '%s\n' go1.27.2 linux amd64 local)" || { echo 'Go 1.27.2 Linux amd64 with GOTOOLCHAIN=local is required' >&2; exit 1; }
	@test "$(CONTROLLER_TOOLS_VERSION) $(ENVTEST_VERSION) $(ENVTEST_K8S_VERSION)" = 'v0.22.0 v0.25.2 1.37.0' || { echo 'Pinned generator/envtest selections are required' >&2; exit 1; }
	@test "$$(go list -m -f '{{.Path}} {{.Version}}' sigs.k8s.io/controller-runtime k8s.io/api k8s.io/apimachinery k8s.io/client-go k8s.io/apiserver k8s.io/apiextensions-apiserver)" = "$$(printf '%s\n' 'sigs.k8s.io/controller-runtime v0.25.2' 'k8s.io/api v0.37.0' 'k8s.io/apimachinery v0.37.0' 'k8s.io/client-go v0.37.0' 'k8s.io/apiserver v0.37.0' 'k8s.io/apiextensions-apiserver v0.37.0')" || { echo 'Pinned runtime/Kubernetes modules are required' >&2; exit 1; }
	@printf '%s  %s\n' '629d3f410e09bf49b64ae7079f7f0bda1191efed311f7d37fdbab0ad5b0ec2b7' "$$(command -v $(KUBECTL))" | sha256sum --check --status

.PHONY: render-manifests test-manifests
render-manifests: toolchain-check ## Render runtime and privileged installer separately; no API access.
	mkdir -p dist
	@tmp="$$(mktemp -d)"; trap 'rm -rf -- "$$tmp"' EXIT; \
	  cp -a config "$$tmp/config"; \
	  image='$(IMG)'; digest=''; tag=''; \
	  case "$$image" in *[[:space:]]*|*\"*) echo 'IMG contains unsupported characters' >&2; exit 1;; esac; \
	  if [[ "$$image" == *@* ]]; then digest="$${image#*@}"; image="$${image%%@*}"; fi; \
	  image_component="$${image##*/}"; \
	  if [[ "$$image_component" == *:* ]]; then tag="$${image_component##*:}"; image="$${image%:*}"; fi; \
	  if [[ -z "$$image" || ( -z "$$tag" && -z "$$digest" ) || ( -n "$$digest" && "$$digest" != sha256:* ) ]]; then echo 'IMG must include a tag or sha256 digest' >&2; exit 1; fi; \
	  { printf '\nimages:\n- name: keaguard-operator\n  newName: "%s"\n' "$$image"; \
	    if [[ -n "$$tag" ]]; then printf '  newTag: "%s"\n' "$$tag"; fi; \
	    if [[ -n "$$digest" ]]; then printf '  digest: "%s"\n' "$$digest"; fi; \
	  } >> "$$tmp/config/manager/kustomization.yaml"; \
	  "$(KUBECTL)" kustomize "$$tmp/config/default" > dist/runtime.yaml; \
	  "$(KUBECTL)" kustomize "$$tmp/config/crd" > dist/crd.yaml

test-manifests: render-manifests ## Structurally check both namespace overlays and the CRD installer.
	KUBECTL="$(KUBECTL)" go test ./test/manifests -run '^TestUnit' -count=1

.PHONY: verify-generated
verify-generated: toolchain-check ## Compare reviewed generated files and both renders across two regenerations.
	KUBECTL="$(KUBECTL)" python3 hack/verify-generated.py
