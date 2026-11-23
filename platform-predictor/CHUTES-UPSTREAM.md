# Changes from upstream

- Upstream: `https://github.com/fortanix/tdx-measure`, commit `b48752b5ae2e2576ea6ac1f60922008a27758ac8`
  (a fork of `https://github.com/virtee/tdx-measure`, which derives from dstack-mr in
  `https://github.com/Dstack-TEE/dstack`).
- Licence: Apache-2.0 (`LICENSE`). Attribution: `NOTICE`.

Chutes Global Corp changed this source in 2026 so that it predicts the measurements of the QEMU and
TDVF direct-boot launch that Chutes' bare-metal hosts use. Each modified file says so in its header.
Chutes checks the predictions against quotes and event logs (CCEL) from TDX hardware.

## Files

- Modified: `Cargo.toml`, `Dockerfile.qemu-acpi-dump`, `README.md`, `cli/src/main.rs`,
  `src/acpi.rs`, `src/image.rs`, `src/kernel.rs`, `src/lib.rs`, `src/machine.rs`, `src/tdvf.rs`,
  `src/util.rs`, `tests/fixtures/.gitignore`, `tests/parse.rs`, `tests/regen.rs`.
- Added: `CHUTES-UPSTREAM.md`, `NOTICE`, `BUILD.md`, `Makefile`, `Dockerfile.qemu-acpi-dump-snp`,
  `src/smbios.rs`, `tests/chutes.rs`, `tests/fetch_tdvf.sh`.
- Removed: `CODEOWNERS` and `.github/workflows/ci.yml`. This repository's CI builds and tests the
  tool.
- Unchanged: `LICENSE`, `.gitignore`, `Cargo.lock`, `cli/Cargo.lock`, `cli/Cargo.toml`,
  `cli/src/transcript.rs`, `extract_config_files.py`, `src/num.rs`, `tests/fetch_ovmf.sh`,
  `tests/regen_fixtures.sh`, `tests/fixtures/README.md` and every fixture under `tests/fixtures/`.

## Changes

- **Launch shape.** `boot_config.qemu` takes the complete, ordered QEMU launch: `smp`, `memory`,
  `numa`, `drives` and `smbios` besides upstream's fields. `--create-acpi-tables` dumps the ACPI
  tables and the fw_cfg SMBIOS tables QEMU builds for that shape (`boot_config.smbios_tables`).
- **GPU and NVSwitch surrogates.** `boot_config.qemu.acpi_devices` replaces each VFIO endpoint with
  an unbacked `pci-testdev` in one of two closed forms, so the ACPI dump runs without the hardware.
  The dump image's QEMU gains the `x-rtxpro6000se`, `x-h200` and `x-nvswitch-ls10` BAR layouts.
- **edk2-stable202605.** With `boot_config.firmware_profile` `edk2-stable202605`, RTMR0 follows that
  firmware's event sequence: `etc/extra-pci-roots` when expander root buses exist, the fixed
  direct-boot fw_cfg payloads, the EFI variables and separators, the ACPI blobs, and the SMBIOS
  tables as OVMF completes and filters them (`src/smbios.rs`).
- **Direct-boot command line.** RTMR2 measures the command line as edk2-stable202605 passes it,
  `initrd=initrd ` followed by the kernel command line, then the initrd.
- **MRTD of a firmware alone.** `tdx_measure::measure_mrtd` computes MRTD from a TDVF image.
- **Pinned QEMU source.** `Dockerfile.qemu-acpi-dump` pins the three Launchpad source package files
  (`.dsc`, `.orig.tar.xz`, `.debian.tar.xz`) of every QEMU version its `ppa` and `main` modes
  build by sha256, downloads them with `--download-only`, checks them and only then runs
  `dpkg-source -x`. A version without pins does not build. `ubuntu:25.10` (QEMU
  `1:10.1.0+ds-5ubuntu2.7`) is a supported distribution.
- **Concurrent dumps.** The dump container is named per run, `acpi-tables-generator-` plus the
  basename of the run's private output directory, so concurrent runs never clash on a container
  name.
- **SEV-SNP platform tables.** `--snp-dump DIR --snp-dump-image IMAGE --snp-qemu-version VERSION`
  (`dump_snp_platform_tables`) runs one declared image built from `Dockerfile.qemu-acpi-dump-snp`
  by digest, with `--pull=never --network=none`, and writes the three fw_cfg blobs QEMU serves for
  the metadata's measurement shape: `etc/acpi/tables`, `etc/acpi/rsdp` and `etc/table-loader`.
- **Event logs.** The per-register event logs print at `info` level.
- **Packaging.** `Cargo.toml` names the licence the source ships, `Apache-2.0`, and the authors
  `tdx-measure contributors`.
- **Formatting.** The modified Rust files are formatted with `rustfmt`.
- **Tests.** `tests/chutes.rs` checks the MRTD of Chutes' TDVF (`tests/fetch_tdvf.sh` downloads it);
  `src/acpi.rs` tests the surrogate forms, the declared SEV-SNP image digest and the per-run
  container names.
