# tdx-measure

`tdx-measure` predicts the Intel TDX measurements of a guest that QEMU boots with a TDVF firmware,
without TDX hardware: MRTD and RTMR0 from the firmware and the QEMU launch shape, RTMR1 and RTMR2
from the kernel, initrd and kernel command line. Chutes' bare-metal TDX hosts launch guests this
way, by QEMU direct kernel boot with Chutes' TDVF, so the tool recomputes the measurements of the
images those hosts run. It also dumps the platform tables QEMU serves an SEV-SNP guest
(`--snp-dump`).

For an image you run on Google Cloud, use `chutes-tdx-measure predict` instead (the
[README](../README.md) at the root of this repository): Google's firmware sets MRTD and RTMR0 there.

## Guarantees

- The dump image's base image and QEMU source package files are pinned by sha256, so the same
  metadata and command line give the same tables whenever they run, and on any host when `cpu` names
  a CPU model.
- `make build` is reproducible: `make repro` builds twice and requires the same sha256. CI runs it.
- `tests/chutes.rs` checks the MRTD of Chutes' TDVF against the value measured on TDX hardware;
  `tests/parse.rs` checks MRTD and RTMR0 of each fixture against its recorded value.

Limits:

- RTMR0 follows one of two firmware event sequences, `edk2-stable202605` or `edk2-stable202502`
  (`firmware_profile`). Other firmware needs its own sequence.
- A prediction made with stand-ins for passed-through devices (`acpi_devices`) is confirmed only by
  the RTMR0 of the target hardware.
- With `--runtime-only` the tool assumes more than 2.75 GB of guest memory.
- RTMR3 is not predicted.

## Build

`make build` and `make repro` need Docker; `make test` also needs `wget`, `dpkg-deb` and `curl` to
fetch the test firmware. Every cargo command runs in a digest-pinned Rust image
(`rust:1.88.0-bookworm`).

```sh
make build   # target/chutes/tdx-measure and target/chutes/tdx-measure.sha256
make test    # unit tests, tests/parse.rs, tests/chutes.rs, tests/forms.rs
make repro   # two independent builds; their sha256 must be equal
```

[BUILD.md](BUILD.md) describes the reproducible build, the SEV-SNP dump image and the slower ACPI
round-trip tests. `cargo install --path cli` installs the command with a local Rust toolchain; that
binary behaves the same but its bytes differ from `make build`'s.

## Usage

```sh
tdx-measure metadata.json --json-file measurements.json \
  --create-acpi-tables ubuntu:26.04
```

reads `metadata.json` (below), builds the pinned QEMU for Ubuntu 26.04 in Docker, dumps the ACPI
and SMBIOS tables for the launch shape, and writes `mrtd`, `rtmr0`, `rtmr1` and `rtmr2`. The options,
in short (`tdx-measure --help` prints the full text):

```
tdx-measure [OPTIONS] <METADATA>

      --direct-boot <DIRECT_BOOT>   Enable direct boot (overrides JSON configuration) [possible values: true, false]
      --json                        Output JSON
      --json-file <JSON_FILE>       Output JSON to file
      --platform-only               Compute MRTD and RTMR0 only
      --runtime-only                Compute RTMR1 and RTMR2 only
      --transcript <TRANSCRIPT>     Write a human-readable transcript of all metadata files
      --create-acpi-tables <DISTRIBUTION> [<QEMU_VERSION>]
                                    Generate the ACPI tables for direct boot (below)
      --qemu-dsc-sha256 <HEX>       The sha256 of the .dsc of a QEMU_VERSION the Dockerfile does not pin
      --patch-kernel                Patch the kernel's boot parameters as QEMU does before measuring RTMR1
                                    (kernels before Ubuntu 26.04; 26.04 and later are measured as-is)
      --qemu-source-url <URL>       Build QEMU from this source tarball (with --qemu-source-sha256)
      --qemu-source-sha256 <HEX>    The tarball's SHA-256
      --exclude-acpi-tables-rtmr0   Exclude the ACPI tables measurement from RTMR0
      --snp-dump <DIR>              Dump the SEV-SNP platform tables into DIR (below)
      --snp-dump-image <IMAGE>      The SEV-SNP dump image, <name>@sha256:<64 hex>
      --snp-qemu-version <VERSION>  The QEMU package version the SEV-SNP host launches with
```

## Metadata

A direct boot:

```json
{
  "metadata_version": 1,
  "boot_config": {
    "cpus": 16,
    "memory": "2G",
    "bios": "OVMF.inteltdx.fd",
    "acpi_tables": "acpi_tables.bin",
    "smbios_tables": "smbios_tables.bin",
    "firmware_profile": "edk2-stable202605"
  },
  "direct": {
    "kernel": "vmlinuz",
    "initrd": "initrd.img",
    "cmdline": "root=/dev/sda1 console=ttyS0"
  }
}
```

Relative paths are resolved against the directory of the metadata file. Every field below is one the
tool reads; a document with any other field is refused.

### Forms

- **Version 1** (`"metadata_version": 1`). A direct boot must name `boot_config.firmware_profile`,
  `qemu.serial` is a list, `qemu.processor_id` is omitted rather than `null`, and every
  `pci-bar-stub` in `devices` or `acpi_devices` is checked before QEMU runs. Use this form for new
  documents.
- **Legacy** (no `metadata_version`). A direct boot whose `firmware_profile` is not
  `edk2-stable202605`, or is absent, measures the `edk2-stable202502` sequence (BootOrder and
  Boot0000 after the ACPI tables); `qemu.serial` is one string.
- **chutesai/tdx-measure** (no `metadata_version`, and `qemu.processor_id`, even `null`, or a
  `qemu.serial` list). These are fields only the
  [chutesai/tdx-measure](https://github.com/chutesai/tdx-measure) fork reads, and such a document
  measures what that fork measures: a direct boot follows `edk2-stable202605` (`firmware_profile`
  may only be absent or `edk2-stable202605`), `etc/extra-pci-roots` counts the `devices` entries
  whose text contains `pxb-pcie`, and the SMBIOS tables go to `smbios-tables` in the directory of
  `acpi_tables` unless `smbios_tables` names a path. The SMBIOS tables must hold no Type 0, 11, 15,
  18, 31, 33 or 128-and-above structure, the types that fork measures differently from the
  firmware; such a document needs version 1.

### `boot_config`

The platform, which determines MRTD and RTMR0.

- `cpus`: the TD's virtual CPUs (up to 2^32 - 1).
- `memory`: the TD's memory, for example `"2G"`.
- `bios`: the TDVF (for example `OVMF.fd`). Canonical's
  [TDX host setup](https://github.com/canonical/tdx/tree/main?tab=readme-ov-file#4-setup-host-os)
  installs one at `/usr/share/ovmf/OVMF.fd`.
- `acpi_tables`: the ACPI tables. `--create-acpi-tables` writes them here; otherwise
  [`extract_config_files.py`](extract_config_files.py) extracts them inside a TD configured like the
  target.
- `rsdp`, `table_loader` *(optional)*: the RSDP and QEMU's table-loader commands. Derived from the
  ACPI tables when absent.
- `smbios_tables` *(optional)*: where `--create-acpi-tables` writes the SMBIOS tables QEMU serves
  over fw_cfg, and where RTMR0 reads them for `edk2-stable202605`.
- `firmware_profile` *(required for a version 1 direct boot)*: the firmware's direct-boot RTMR0
  event sequence.
  - `edk2-stable202605`, Chutes' TDVF: `etc/extra-pci-roots` when expander root buses exist, the
    fixed direct-boot fw_cfg payloads, the EFI variables and separators, the ACPI blobs, and the
    SMBIOS tables as OVMF completes and filters them. Needs `smbios_tables`.
  - `edk2-stable202502`, Ubuntu's OVMF 2025.02: the EFI variables and separators, the ACPI blobs,
    BootOrder and Boot0000.
- `qemu` *(optional)*: the QEMU launch shape `--create-acpi-tables` runs. The command line is
  `-accel -m -smp -cpu -no-reboot -nodefaults -vga none -nographic -bios -machine`, then the lists
  below in this order, and nothing else. Without `qemu`, the tool uses Canonical's
  [direct-boot arguments](https://github.com/canonical/tdx/blob/3.3/guest-tools/direct-boot/boot_direct.sh#L54).
  - `machine` *(required)*: the `-machine` value, for example
    `"q35,kernel_irqchip=split,memory-backend=mem0,smm=off,pic=off"`.
  - `cpu` *(default `"host"`)*: the `-cpu` value. A named model with `phys-bits=N` (for example
    `"Skylake-Server,phys-bits=46"`) makes the dump independent of the host CPU.
  - `accel` *(default `"kvm"`)*: the `-accel` value; `"tcg"` runs without KVM.
  - `smp` *(default `"<cpus>,maxcpus=<cpus>"`)* and `memory` *(default `boot_config.memory`)*: the
    `-smp` and `-m` values.
  - `globals`, `objects`, `numa`, `drives`, `netdevs`, `devices`, `fw_cfg`, `smbios`: lists, each
    value emitted as `-global`, `-object`, `-numa`, `-drive`, `-netdev`, `-device`, `-fw_cfg` and
    `-smbios`.
  - `serial`: a list, each value emitted as `-serial`.
  - `processor_id` *(optional)*: the SMBIOS Type-4 Processor ID, 16 hex digits (CPUID leaf 1 EAX
    then EDX, little-endian), written into every Type-4 structure of the dumped SMBIOS tables before
    RTMR0 measures them. Under KVM the dumping host's CPUID would otherwise reach that field. A
    launch that sets it with `-smbios type=4,processor-id=N` needs no `processor_id`: the same value
    in `smbios` gives the same bytes (`processor-id=1` is `0100000000000000`).
  - `acpi_devices` *(optional)*: a device list for the dump, aligned one for one with `devices`.
    Every non-VFIO entry must be identical; every `vfio-pci` endpoint is replaced by a stand-in with
    the same `bus` and `addr`.

**The order of `devices` is part of the measurement.** QEMU gives each `-device` the lowest free PCI
slot in command-line order, so `devices` must list them in the order of the launch you reproduce. A
`slot=N` on a `pcie-root-port` is a hint and moves when an earlier device holds that slot. The order
within the other lists does not change the ACPI tables.

**Stand-ins for passed-through devices.** The dump image's QEMU (10.1 and later: `ubuntu:25.10`,
`ubuntu:26.04`) has `pci-bar-stub` (`pci-bar-stub.c`), a PCI device with a declared BAR layout and no
backing memory:
`pci-bar-stub,bus=<bus>,addr=<addr>,bars=<layout>[,vendor=0xVVVV][,device=0xDDDD][,class=0xCCCC]`.
`bars` lists `<index>:<size>:<kind>` entries separated by `;`: an index from 0 to 5 (a 64-bit BAR also
takes the next one), a power-of-two size with an optional `K`, `M` or `G` suffix, and a kind, `m32`,
`m64`, `p32` or `p64` (`p`: prefetchable). `vendor`, `device` and `class` default to 1b36:0010,
class 0880. For example, an H200 is
`bars=0:16M:p64;2:256G:p64;4:32M:p64,vendor=0x10de,device=0x2335,class=0x0302`. Three presets in
`pci-testdev` spelling stand for fixed layouts with pci-testdev's identity (1b36:0005, class 00ff):

| Preset | Layout |
|---|---|
| `pci-testdev,membar=<MiB>M,membar-backed=off,x-rtxpro6000se=on,bus=<bus>,addr=<addr>` | `bars=0:64M:p64;2:<MiB>M:p64;4:32M:p64` (RTX PRO 6000 SE) |
| `pci-testdev,membar=<MiB>M,membar-backed=off,x-h200=on,bus=<bus>,addr=<addr>` | `bars=0:16M:p64;2:<MiB>M:p64;4:32M:p64` (H200) |
| `pci-testdev,membar-backed=off,x-nvswitch-ls10=on,bus=<bus>,addr=<addr>` | `bars=0:32M:m64` (LS10 NVSwitch) |

### `direct`

The direct-boot inputs, which determine RTMR1 and RTMR2. Canonical's
[direct-boot instructions](https://github.com/canonical/tdx/tree/main/guest-tools/direct-boot#prerequisites)
show how to obtain them.

- `kernel`: the kernel image the firmware loads.
- `initrd`: the initial RAM disk.
- `cmdline`: the kernel command line, as passed to QEMU with `-append`.

Direct boot needs no `boot_order` or `path_boot_xxxx`: the tool computes its one BootOrder and one
Boot#### variable.

### `indirect`

An indirect boot (OVMF, shim, GRUB, then the kernel, as Canonical's `tdvirsh` runs it) replaces
`direct` with `indirect` and adds two `boot_config` fields:

```json
{
  "boot_config": {
    "cpus": 32,
    "memory": "10G",
    "bios": "OVMF.fd",
    "acpi_tables": "acpi_tables.bin",
    "rsdp": "rsdp.bin",
    "table_loader": "table_loader.bin",
    "boot_order": "BootOrder.bin",
    "path_boot_xxxx": "boot-options/"
  },
  "indirect": {
    "qcow2": "tdx-guest-ubuntu-25.04-generic.qcow2",
    "cmdline": "console=ttyS0 root=/dev/vda1",
    "mok_list": "MokList.bin",
    "mok_list_trusted": "MokListTrusted.bin",
    "mok_list_x": "MokListX.bin",
    "sbat_level": "SbatLevel.bin"
  }
}
```

- `boot_order`: the UEFI BootOrder variable.
- `path_boot_xxxx`: a directory of `Boot0000.bin`, `Boot0001.bin`, ..., one per Boot#### variable.
- `qcow2`: the guest disk with shim, GRUB and a kernel (Canonical's
  [instructions](https://github.com/canonical/tdx/tree/main?tab=readme-ov-file#5-create-td-image)
  create one).
- `cmdline`: the kernel command line, as `/proc/cmdline` shows it inside the TD.
- `mok_list`, `mok_list_trusted`, `mok_list_x`: the Machine Owner Key lists (enrolled, trusted,
  denied).
- `sbat_level`: the SBAT revocation level.

`extract_config_files.py`, run inside a TD configured like the target, extracts every file except
`qcow2`. `--create-acpi-tables` is refused for an indirect boot.

## ACPI and SMBIOS tables

With `--create-acpi-tables` the tool builds a Docker image whose patched QEMU writes `etc/acpi/tables`
(and, with `smbios_tables`, the fw_cfg SMBIOS tables) and exits at the firmware's first ACPI read,
then runs it with the metadata's launch shape. This needs Docker, and KVM when `accel` is `"kvm"`. Each base image
is pinned by digest, and so is the QEMU version:

| Distribution   | QEMU source                         | Pinned QEMU version               |
|----------------|-------------------------------------|-----------------------------------|
| `ubuntu:24.04` | `kobuk-team/tdx-release` PPA        | `2:8.2.2+ds-0ubuntu1.4+tdx1.1`    |
| `ubuntu:25.04` | `kobuk-team/tdx-release` PPA        | `1:9.2.1+ds-1ubuntu4+tdx2.0~ppa2` |
| `ubuntu:25.10` | distribution main archive           | `1:10.1.0+ds-5ubuntu2.7`          |
| `ubuntu:26.04` | distribution main archive           | `1:10.2.1+ds-1ubuntu4`            |

A second value selects another version, for example a stable release update:

```
--create-acpi-tables ubuntu:26.04 1:10.2.1+ds-1ubuntu3.2
```

A version string names a Launchpad publication, not its bytes, so `Dockerfile.qemu-acpi-dump` pins
the three source package files (`.dsc`, `.orig.tar.xz`, `.debian.tar.xz`) of every version it builds
by sha256 and checks them before it unpacks anything. Any other version builds when
`--qemu-dsc-sha256` gives the sha256 of its `.dsc`; the files the `.dsc` lists must then have the
sha256 its `Checksums-Sha256` field gives:

```
--create-acpi-tables ubuntu:26.04 1:10.2.1+ds-1ubuntu3.1 \
  --qemu-dsc-sha256 8499c312190488c1126fe61a9e340928eb78da0eff68e7b168ee30627d4a0ad7
```

A version with neither does not build. `--qemu-source-url` and `--qemu-source-sha256` build QEMU from
an upstream source tarball instead (`.tar.xz`, `.gz` or `.bz2`, unpacking to a top-level `qemu*/`
directory), refused unless its SHA-256 matches:

```
--create-acpi-tables ubuntu:24.04 \
  --qemu-source-url https://download.qemu.org/qemu-9.2.1.tar.xz \
  --qemu-source-sha256 <sha256 of the tarball>
```

Without `--create-acpi-tables` the tool measures the tables the metadata names: `acpi_tables`, and
`smbios_tables` for `edk2-stable202605`.

## SEV-SNP platform tables

```
tdx-measure metadata.json --snp-dump DIR \
  --snp-dump-image chutes-tdx-measure/qemu-acpi-dump-snp@sha256:<digest> \
  --snp-qemu-version 1:10.2.1+ds-1ubuntu3.2
```

writes the three fw_cfg blobs QEMU builds for the metadata's launch shape (`boot_config`, with the
firmware as `bios`, under TCG) into `DIR`: the ACPI tables (`acpi-tables.bin`), the RSDP
(`rsdp.bin`) and the table-loader commands (`table-loader.bin`). It computes no measurement. It runs
only an image named by digest, with `docker run --rm --pull=never --network=none`, after checking
that the image's `org.chutes.qemu-package-version` label equals `--snp-qemu-version`. It never builds
or pulls an image, and refuses `--create-acpi-tables` and the `--qemu-source-*` flags.
`./build-snp-dump-image.sh --load OUT_DIR` (or `make snp-dump-image`) builds that image reproducibly
from `Dockerfile.qemu-acpi-dump-snp` and loads it as `chutes-tdx-measure/qemu-acpi-dump-snp`
([BUILD.md](BUILD.md)).

## Transcript

`--transcript FILE` writes a human-readable transcript of the binary configuration files. It
disassembles the ACPI tables with `iasl`, which must be installed.

## Compatibility with chutesai/tdx-measure

The tool reads the documents written for the chutesai/tdx-measure fork unchanged and gives the same
MRTD, RTMR0, RTMR1 and RTMR2 with the same arguments, except that it builds only a QEMU version it
pins or one named with `--qemu-dsc-sha256`. The fork's `ubuntu:26.04` default is
`1:10.2.1+ds-1ubuntu3.1`:

```
tdx-measure metadata.json --platform-only --json-file out.json \
  --create-acpi-tables ubuntu:26.04 1:10.2.1+ds-1ubuntu3.1 \
  --qemu-dsc-sha256 8499c312190488c1126fe61a9e340928eb78da0eff68e7b168ee30627d4a0ad7
tdx-measure --runtime-only runtime.json      # RTMR1 and RTMR2, without --patch-kernel
```

The JSON output has `mrtd`, `rtmr0`, `rtmr1` and `rtmr2`; the fork's also has `rtmr0_log`. The same
document in version 1 form adds `"metadata_version": 1`, `"firmware_profile": "edk2-stable202605"`
and `smbios_tables`, and drops a `null` `processor_id`.

`tools/fork-equivalence.py` runs host profiles through both binaries and reports MRTD, RTMR0 (in the
fork form and in version 1), RTMR1, RTMR2 and the dumped ACPI and SMBIOS tables as match or
MISMATCH; it exits 0 only when every value matches. It renders each profile with chutes-cvm, Chutes'
guest launch library, which must be importable; its docstring describes the inputs.
`tools/fork-equivalence-profiles/` holds 15 host profiles: 8x RTX PRO 6000 (guest NUMA, flat,
interleaved and partly without NUMA affinity), 8x H200 with four NVSwitches on either node, 4x H200,
8x B300, 8x B200 (176 and 272 vCPUs), 1x H100 PCIe, and AMD hosts of four of them.

## What the registers cover

- `MRTD`: the TDVF.
- `RTMR0`: the firmware configuration: the TD HOB (mostly the memory the TD can reach), the
  configuration firmware volume, the Secure Boot variables, the ACPI tables, the boot variables and,
  for indirect boot, the [SbatLevel](https://github.com/rhboot/shim/blob/main/SbatLevel_Variable.txt)
  variable.
- `RTMR1`: the kernel for direct boot; for indirect boot, the GPT, shim and GRUB.
- `RTMR2`: the kernel command line and the initrd; for indirect boot, also the
  [MOK variables](https://github.com/rhboot/shim/blob/main/MokVars.txt).

## Layout

| Path | Contents |
|---|---|
| `src/` | The library: firmware (`tdvf.rs`), ACPI dump and tables (`acpi.rs`), SMBIOS (`smbios.rs`), kernel and boot chain |
| `cli/` | The `tdx-measure` command |
| `Dockerfile.qemu-acpi-dump` | The TDX dump image (embedded in the binary) |
| `Dockerfile.qemu-acpi-dump-snp`, `build-snp-dump-image.sh` | The SEV-SNP dump image and its reproducible build |
| `pci-bar-stub.c` | The stand-in PCI device both dump images add to QEMU |
| `tests/` | Tests and fixtures |
| `tools/` | `fork-equivalence.py` and its host profiles |

## Licence

Apache-2.0 (`LICENSE`). This directory is derived from
[fortanix/tdx-measure](https://github.com/fortanix/tdx-measure), a fork of
[virtee/tdx-measure](https://github.com/virtee/tdx-measure), which derives from dstack-mr in
[Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack). `NOTICE` gives the attribution and
`CHUTES-UPSTREAM.md` lists the changes.
