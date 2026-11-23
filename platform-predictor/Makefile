# The platform predictor, tdx-measure. See BUILD.md.
#
# Every cargo command runs in the digest-pinned Rust image with the source mounted read-only at
# /src and cargo's home and target under /target, so `make build` gives the binary Chutes pins.
RUST_IMAGE := rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
DOCKER ?= docker
OUT ?= target/chutes/tdx-measure
CARGO_BUILD := cargo build --locked --release --manifest-path cli/Cargo.toml --target-dir /target

# $(call in_rust,TARGET_DIR,COMMAND): COMMAND in the pinned image, with TARGET_DIR at /target.
in_rust = $(DOCKER) run --rm --user "$$(id -u):$$(id -g)" --env CARGO_HOME=/target/cargo-home \
	--volume "$(CURDIR):/src:ro" --volume "$(1):/target" --workdir /src $(RUST_IMAGE) $(2)

.PHONY: build repro test fixtures

# The binary at $(OUT) and its sha256 at $(OUT).sha256.
build:
	@mkdir -p target && t=$$(mktemp -d target/.build.XXXXXX) && trap 'rm -rf "$$t"' EXIT && \
	  $(call in_rust,$(CURDIR)/$$t,$(CARGO_BUILD)) && \
	  install -D -m 0755 "$$t/release/tdx-measure" "$(OUT)" && \
	  sha256sum "$(OUT)" | cut -d' ' -f1 | tee "$(OUT).sha256"

# Two builds, each with its own cargo home and target; their binaries must be the same bytes.
repro:
	@mkdir -p target && a=$$(mktemp -d target/.repro-a.XXXXXX) && b=$$(mktemp -d target/.repro-b.XXXXXX) && \
	  trap 'rm -rf "$$a" "$$b"' EXIT && \
	  $(call in_rust,$(CURDIR)/$$a,$(CARGO_BUILD)) && \
	  $(call in_rust,$(CURDIR)/$$b,$(CARGO_BUILD)) && \
	  sa=$$(sha256sum < "$$a/release/tdx-measure" | cut -d' ' -f1) && \
	  sb=$$(sha256sum < "$$b/release/tdx-measure" | cut -d' ' -f1) && \
	  echo "build A: $$sa" && echo "build B: $$sb" && [ "$$sa" = "$$sb" ]

# The firmware the tests read: upstream's OVMF.fd (Ubuntu 25.04) and Chutes' TDVF, sha256-checked.
fixtures:
	tests/fetch_ovmf.sh
	tests/fetch_tdvf.sh

# The library's unit tests and tests/{parse,chutes}.rs. tests/regen.rs is ignored here (BUILD.md).
test: fixtures
	@mkdir -p target && t=$$(mktemp -d target/.test.XXXXXX) && trap 'rm -rf "$$t"' EXIT && \
	  $(call in_rust,$(CURDIR)/$$t,cargo test --locked --release --target-dir /target)
