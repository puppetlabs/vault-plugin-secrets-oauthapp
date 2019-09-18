#
# Commands
#

export GIT ?= git
export GO ?= go
export MKDIR_P ?= mkdir -p
export RM ?= rm -f
export SHA256SUM ?= shasum -a 256
export TAR ?= tar
export ZIP_M ?= zip -m

#
# Variables
#

GOFLAGS ?=

CLI_DIST_TARGETS ?= $(addprefix dist-bin-,darwin-amd64 darwin-386 windows-amd64 windows-386 linux-amd64 linux-386 linux-arm64 linux-arm freebsd-amd64 freebsd-386 freebsd-arm netbsd-amd64 netbsd-386 openbsd-amd64 openbsd-386 solaris-amd64)

#
#
#

export CLI_DIST_NAME := vault-plugin-secrets-oauthapp
export CLI_DIST_BRANCH ?= $(shell $(GIT) symbolic-ref --short HEAD)
export CLI_DIST_VERSION ?= $(shell $(GIT) describe --tags --always --dirty)

export ARTIFACTS_DIR := artifacts
export BIN_DIR := bin

#
# Targets
#

.PHONY: all
all: build

$(ARTIFACTS_DIR) $(BIN_DIR):
	$(MKDIR_P) $@

.PHONY: generate
generate:
	$(GO) generate ./...

.PHONY: build
build: generate $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/$(CLI_DIST_NAME) ./cmd/vault-plugin-secrets-oauthapp

.PHONY: test
test: generate
	$(GO) test $(GOFLAGS) ./...

.PHONY: dist
dist: $(CLI_DIST_TARGETS)

.PHONY: clean
clean:
	$(RM) -r $(ARTIFACTS_DIR)/
	$(RM) -r $(BIN_DIR)/

.PHONY: $(CLI_DIST_TARGETS)
$(CLI_DIST_TARGETS): export CGO_ENABLED = 0
$(CLI_DIST_TARGETS): export GOFLAGS += -a
$(CLI_DIST_TARGETS): export GOOS = $(word 1,$(subst -, ,$*))
$(CLI_DIST_TARGETS): export GOARCH = $(subst $(CLI_EXT_$(GOOS)),,$(word 2,$(subst -, ,$*)))
$(CLI_DIST_TARGETS): export LDFLAGS += -extldflags "-static"
$(CLI_DIST_TARGETS): dist-bin-%: $(ARTIFACTS_DIR)
	@scripts/dist
