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
- `tests/chutes.rs`: the MRTD of Chutes' TDVF equals the value measured on TDX hardware.

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
