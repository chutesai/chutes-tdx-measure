# Building and testing the platform predictor

## The pinned build

```sh
make build            # target/chutes/tdx-measure, its sha256 in target/chutes/tdx-measure.sha256
make build OUT=/path  # the binary elsewhere
```

`make build` runs, in `rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0`:

```sh
docker run --rm --user "$(id -u):$(id -g)" --env CARGO_HOME=/target/cargo-home \
  --volume "$PWD:/src:ro" --volume "<empty directory>:/target" --workdir /src <image> \
  cargo build --locked --release --manifest-path cli/Cargo.toml --target-dir /target
```

The binary records the paths it was built from (`/src`, `/target/cargo-home`), so the same source,
`Cargo.lock` files and image give the same bytes only with these mounts; this is the build whose
sha256 Chutes pins. The binary embeds `Dockerfile.qemu-acpi-dump` (`include_str!` in `src/acpi.rs`),
so any change to that file, comments included, gives a new sha256.

## Reproducible build (A = B)

```sh
make repro
```

builds twice, each time with an empty cargo home and target directory, prints both sha256 and fails
unless they are equal. CI runs it on every push.

## The SEV-SNP dump image

```sh
make snp-dump-image   # target/snp-dump-image/{image.tar,digest}, loaded into Docker
```

`--snp-dump` runs one image named by digest. `./build-snp-dump-image.sh [--load] OUT_DIR` builds it
from `Dockerfile.qemu-acpi-dump-snp` reproducibly, so two builders get the same digest:

- **Inputs.** The base image is pinned by digest; the build dependencies come from
  snapshot.ubuntu.com at the snapshot the Dockerfile names, through apt's signed InRelease. The three
  QEMU source package files that `Dockerfile.qemu-acpi-dump-snp.args` names are fetched from
  snapshot.ubuntu.com and checked against their sha256 (the build checks them again), and copied into
  the build context with `pci-bar-stub.c`, with mode 0644 and `SOURCE_DATE_EPOCH` as their time.
- **Time.** `SOURCE_DATE_EPOCH` in the `.args` file is the snapshot time. BuildKit's
  `rewrite-timestamp` sets every file time later than it to it; `RUN` sees it too, so `useradd` and
  Python's byte-code files do not record the build time.
- **Logs and state.** The install step removes the apt and dpkg logs and the ldconfig auxiliary
  cache. QEMU is configured and built in one step, with `PYTHONHASHSEED=0` for meson and QEMU's
  code generators, which then removes configure's and meson's logs, meson's pickled state and
  ninja's logs; the binary runs from the build directory without them.
- **Builder.** BuildKit, pinned by digest, runs daemonless in a privileged container with no cache
  and writes an OCI archive with OCI media types. The manifest digest is the image's identity.

With `--load`, the archive is loaded as `chutes-tdx-measure/qemu-acpi-dump-snp` (this needs Docker's
containerd image store, which keeps a loaded image's manifest digest), and `--snp-dump-image
chutes-tdx-measure/qemu-acpi-dump-snp@sha256:<digest>` runs it.

## Tests

```sh
make test
```

fetches the test firmware and runs `cargo test --locked --release` in the same image:

- `tests/fetch_ovmf.sh`: upstream's `OVMF.fd` (Ubuntu 25.04 `ovmf_2025.02-3ubuntu2`), checked by
  sha256, for the fixtures of `tests/parse.rs`;
- `tests/fetch_tdvf.sh`: Chutes' TDVF `OVMF.inteltdx.fd` (sha256 `01731a86…`), from
  `chutesai/sek8s` at a fixed commit, for `tests/chutes.rs`;
- the library's unit tests;
- `tests/parse.rs`: MRTD and RTMR0 of every fixture under `tests/fixtures/` equal its
  `expected.json`;
- `tests/chutes.rs`: the MRTD of Chutes' TDVF equals the value measured on TDX hardware;
- `tests/forms.rs`: the metadata forms (version 1, legacy and chutesai/tdx-measure) and their rules.

`tests/regen.rs` is `#[ignore]`d there. It runs `--create-acpi-tables` for every fixture and requires
the regenerated `acpi_tables.bin` to equal the committed bytes, which needs Docker on the host, a
network connection for the QEMU source and a few minutes per QEMU build; the `canonical-defaults`
fixture also needs `/dev/kvm`. Run it with a local Rust toolchain:

```sh
tests/fetch_ovmf.sh
(cd cli && cargo build --release)
cargo test --release --test regen -- --ignored --nocapture
```

`tests/fixtures/README.md` describes the fixtures and `tests/regen_fixtures.sh` regenerates them.
