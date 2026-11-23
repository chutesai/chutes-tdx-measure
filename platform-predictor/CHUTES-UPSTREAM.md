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
  `Dockerfile.qemu-acpi-dump-snp.args`, `build-snp-dump-image.sh`, `src/smbios.rs`,
  `tests/chutes.rs`, `tests/fetch_tdvf.sh`, `tests/forms.rs`, `tools/fork-equivalence.py`,
  `tools/fork-equivalence-profiles/`, and `pci-bar-stub.c` from
  [chutesai/tdx-measure](https://github.com/chutesai/tdx-measure) (commit
  `494f18deba4c8c85b626b3fb11b612c7721b156b`, Apache-2.0), unchanged.
- Removed: `CODEOWNERS` and `.github/workflows/ci.yml`. This repository's CI builds and tests the
  tool.
- Unchanged: `LICENSE`, `.gitignore`, `Cargo.lock`, `cli/Cargo.lock`, `cli/Cargo.toml`,
  `cli/src/transcript.rs`, `extract_config_files.py`, `src/num.rs`, `tests/fetch_ovmf.sh`,
  `tests/regen_fixtures.sh`, `tests/fixtures/README.md` and every fixture under `tests/fixtures/`.

## Changes

- **Launch shape.** `boot_config.qemu` takes the complete, ordered QEMU launch: `smp`, `memory`,
  `numa`, `drives` and `smbios` besides upstream's fields. `--create-acpi-tables` dumps the ACPI
  tables and the fw_cfg SMBIOS tables QEMU builds for that shape (`boot_config.smbios_tables`).
- **Metadata forms.** `BootConfig`, `QemuShape`, `DirectBoot`, `IndirectBoot` and the document
  itself refuse a field the tool does not know. `"metadata_version": 1` selects the version 1
  form: a direct boot names `firmware_profile` (`edk2-stable202605` or `edk2-stable202502`),
  `qemu.serial` is a list and each `pci-bar-stub` is checked. A document without it is read as
  before; one whose `qemu` carries `processor_id` or a `serial` list, fields only the
  chutesai/tdx-measure fork read, measures what that fork measured (README, "Metadata forms").
  `boot_config.cpus` takes values above 255.
- **Passed-through device stand-ins.** The dump images' QEMU (10.1 and later) builds
  `pci-bar-stub`, a PCI device with a declared BAR layout, vendor, device and class and no backing
  memory. `boot_config.qemu.acpi_devices` replaces each VFIO endpoint with a `pci-bar-stub` at the
  same bus and address, or with one of three named presets (`x-rtxpro6000se`, `x-h200`,
  `x-nvswitch-ls10`, in their earlier `pci-testdev` spelling), each a fixed `pci-bar-stub` layout
  with pci-testdev's identity that dumps the tables the earlier `pci-testdev` modes did. The
  `pci-testdev` patches are gone from both dump images, so the `ubuntu:25.04` image (QEMU 9.2.1,
  whose `pci-testdev` has no `membar-backed`) builds again.
- **SMBIOS Type-4 Processor ID.** `qemu.processor_id` (8 bytes, hex) is written into every Type-4
  structure of the dumped SMBIOS tables before RTMR0 measures them.
- **QEMU version by `.dsc` hash.** `--qemu-dsc-sha256` builds a QEMU source package version that
  `Dockerfile.qemu-acpi-dump` does not pin: its `.dsc` must have that sha256 and the files it lists
  the sha256 its `Checksums-Sha256` field gives.
- **Dump image by ID.** The dump runs the image ID its own `docker build` returned
  (`--iidfile`), not the `acpi-tables-generator` tag another run may have moved.
- **Measuring named tables.** Without `--create-acpi-tables`, the tool measures the
  `acpi_tables` (and `smbios_tables`) the metadata names; it used to try a dump with no
  distribution and fail.
- **One firmware path.** A relative `bios` is resolved against the metadata file's directory for
  the dump as it is for MRTD; the dump used to resolve it against the working directory, so
  `tests/regen.rs` (whose fixtures name `../OVMF.fd`) could not boot its firmware.
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
  `dpkg-source -x`. A version without pins builds only with `--qemu-dsc-sha256` (below). `ubuntu:25.10` (QEMU
  `1:10.1.0+ds-5ubuntu2.7`) is a supported distribution.
- **Concurrent dumps.** The dump container is named per run, `acpi-tables-generator-` plus the
  basename of the run's private output directory, so concurrent runs never clash on a container
  name.
- **SEV-SNP platform tables.** `--snp-dump DIR --snp-dump-image IMAGE --snp-qemu-version VERSION`
  (`dump_snp_platform_tables`) runs one declared image built from `Dockerfile.qemu-acpi-dump-snp`
  (reproducibly, by `build-snp-dump-image.sh`) by digest, with `--pull=never --network=none`, and writes the three fw_cfg blobs QEMU serves for
  the metadata's measurement shape: `etc/acpi/tables`, `etc/acpi/rsdp` and `etc/table-loader`.
- **Event logs.** The per-register event logs print at `info` level.
- **Packaging.** `Cargo.toml` names the licence the source ships, `Apache-2.0`, and the authors
  `tdx-measure contributors`.
- **Formatting.** The modified Rust files are formatted with `rustfmt`.
- **Tests.** `tests/chutes.rs` checks the MRTD of Chutes' TDVF (`tests/fetch_tdvf.sh` downloads it);
  `tests/forms.rs` the metadata forms; `src/acpi.rs` the stand-ins and presets, the `.dsc` hash
  input, the declared SEV-SNP image digest and the per-run container names; `src/smbios.rs` the
  Processor ID write and the fork form's SMBIOS check.
- **Equivalence with chutesai/tdx-measure.** `tools/fork-equivalence.py` runs host profiles through
  that fork and this tool and compares MRTD, RTMR0, RTMR1, RTMR2 and the dumped tables.
