# tdx-measure, the platform predictor

`tdx-measure` predicts the Intel TDX measurements of a guest that QEMU boots with a TDVF firmware,
without TDX hardware: MRTD and RTMR0 from the firmware and the QEMU launch shape, RTMR1 and RTMR2
from the kernel, initrd and kernel command line. Chutes' bare-metal TDX hosts launch every guest
this way, by QEMU direct kernel boot with Chutes' TDVF, so this tool recomputes the measurements of
Chutes' site images and of any image those hosts launch. It also dumps the platform tables QEMU
serves to an SEV-SNP guest of a given launch shape (`--snp-dump`).

For a VM image you build and run on Google Cloud, use `chutes-tdx-measure predict` instead (the
README at the root of this repository): Google's firmware sets MRTD and RTMR0 there.

Licence: Apache-2.0 (`LICENSE`). This directory is derived from
[fortanix/tdx-measure](https://github.com/fortanix/tdx-measure), a fork of
[virtee/tdx-measure](https://github.com/virtee/tdx-measure), which derives from dstack-mr in
[Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack). `NOTICE` gives the attribution and
`CHUTES-UPSTREAM.md` lists Chutes' changes.

## Build and test

`make build` and `make repro` need Docker; `make test` also needs `wget`, `dpkg-deb` and `curl` to
fetch the test firmware. Every cargo command runs in the digest-pinned Rust image
(`rust:1.88.0-bookworm`), so `make build` gives the binary whose sha256 Chutes pins.

```sh
make build   # target/chutes/tdx-measure and target/chutes/tdx-measure.sha256
make test    # the library's unit tests, tests/parse.rs, tests/chutes.rs and tests/forms.rs
make repro   # two independent builds; their sha256 must be equal
```

`BUILD.md` describes the reproducible build and the slower ACPI round-trip tests.

## Usage

```
tdx-measure [OPTIONS] <METADATA>
```

`<METADATA>` is the path of a metadata JSON file (formats below).

```
      --direct-boot <DIRECT_BOOT>   Enable direct boot (overrides JSON configuration) [possible values: true, false]
      --json                        Output JSON
      --json-file <JSON_FILE>       Output JSON to file
      --platform-only               Compute MRTD and RTMR0 only
      --runtime-only                Compute RTMR1 and RTMR2 only
      --transcript <TRANSCRIPT>     Generate a human-readable transcript of all metadata files and write
                                    it to the specified file
      --create-acpi-tables <DISTRIBUTION> [<QEMU_VERSION>]
                                    Generate ACPI tables for direct boot. <DISTRIBUTION> is one of
                                    ubuntu:24.04, ubuntu:25.04, ubuntu:25.10, ubuntu:26.04. <QEMU_VERSION>
                                    overrides the pinned QEMU source package version for that
                                    distribution; a version builds when Dockerfile.qemu-acpi-dump
                                    pins its source package files by sha256, or with
                                    --qemu-dsc-sha256 (below)
      --qemu-dsc-sha256 <HEX>       The sha256 of the .dsc file of <QEMU_VERSION>, a version
                                    Dockerfile.qemu-acpi-dump does not pin; the files the .dsc lists
                                    must have the sha256 its Checksums-Sha256 field gives
      --patch-kernel                Apply QEMU-style kernel boot-params patching before measuring RTMR1.
                                    Without it the kernel is measured as-is (Ubuntu 26.04 and later,
                                    whose kernels are loaded through the EFI stub); pass it for older
                                    guests (Ubuntu 24.04, 25.04)
      --qemu-source-url <URL>       Build QEMU from the source tarball at <URL> (hash-verified against
                                    --qemu-source-sha256) instead of the distribution's PPA/main
                                    package. Only used with --create-acpi-tables; both flags must be
                                    given together
      --qemu-source-sha256 <HEX>    Expected SHA-256 (hex) of the --qemu-source-url tarball
      --exclude-acpi-tables-rtmr0   Exclude the ACPI tables measurement from RTMR0
      --snp-dump <DIR>              Dump the SEV-SNP platform tables of the metadata's measurement
                                    shape (boot_config.qemu, under TCG, with boot_config.bios as the
                                    checking firmware) into DIR with the declared SEV-SNP dump image;
                                    no measurement is computed. Requires --snp-dump-image and
                                    --snp-qemu-version; never builds or pulls an image
      --snp-dump-image <IMAGE>      The declared SEV-SNP dump image, <name>@sha256:<64 hex>
      --snp-qemu-version <VERSION>  The QEMU package version the SEV-SNP host launches with; the
                                    image's org.chutes.qemu-package-version label must equal it
  -h, --help                        Print help
  -V, --version                     Print version
```

With `--runtime-only` the tool assumes a VM memory size above 2.75 GB.

### Direct boot

#### Metadata

```
{
  "boot_config": {
    "cpus": 16,
    "memory": "2G",
    "bios": "[path to OVMF.fd]",
    "acpi_tables": "[path to acpi_tables.bin]",
    "rsdp": "[path to rsdp.bin]",
    "table_loader": "[path to table_loader.bin]"
  },
  "direct": {
    "kernel": "[path to vmlinuz]",
    "initrd": "[path to initrd]",
    "cmdline": "root=/dev/sda1 console=ttyS0"
  }
}
```

Relative paths are resolved against the directory of the metadata file.

#### Metadata forms

Every field below is one the tool reads; a document with any other field is refused, in every form.
A document is in one of three forms:

- **Version 1**, with `"metadata_version": 1` at the top level. A direct boot must name
  `boot_config.firmware_profile`, `qemu.serial` is a list, a `qemu.processor_id` is 16 hex digits
  (omit it rather than set it `null`), and every `pci-bar-stub` in `devices` or `acpi_devices` is
  checked before QEMU runs. New documents should use this form.
- **Legacy**, without `metadata_version`: the form this tool read before versions, with the same
  meaning. A direct boot whose `firmware_profile` is not `edk2-stable202605` (absent included)
  measures the `edk2-stable202502` sequence, BootOrder and Boot0000 after the ACPI tables, and
  `qemu.serial` is one string.
- **chutesai/tdx-measure**, without `metadata_version` and with `qemu.processor_id` (a `null` value
  counts) or a `qemu.serial` list, fields only the
  [chutesai/tdx-measure](https://github.com/chutesai/tdx-measure) fork read. Such a document
  measures what that fork measured: a direct boot follows the `edk2-stable202605` sequence whatever
  `firmware_profile` says (it may only be absent or `edk2-stable202605`), `etc/extra-pci-roots`
  counts the `devices` entries whose text contains `pxb-pcie`, and the SMBIOS tables go to
  `smbios-tables` in the directory of `acpi_tables` unless `smbios_tables` names a path. The SMBIOS
  tables must hold no Type 0, 11, 15, 18, 31, 33 or 128-and-above structure, the types that fork
  measured differently from the firmware; such a document needs version 1.
  `tools/fork-equivalence.py` (below) compares the two tools on any set of host profiles.

The legacy forms have no field the tool accepts and ignores: each field they can carry is listed
below and read.

#### Metadata fields

- `metadata_version` *(optional)*: `1` for the version 1 form.
- `boot_config`: the platform configuration, which determines MRTD and RTMR0.
  - `cpus`: the number of virtual CPUs of the TD (up to 2^32 - 1).
  - `memory`: the TD's memory (for example `"2G"`).
  - `bios`: the virtual firmware (TDVF, for example `OVMF.fd`) that boots the TD. Canonical's TDX
    host setup ([instructions](https://github.com/canonical/tdx/tree/main?tab=readme-ov-file#4-setup-host-os))
    installs one at `/usr/share/ovmf/OVMF.fd`.
  - `acpi_tables`: the ACPI tables, which describe the hardware the TD discovers. With
    `--create-acpi-tables` the tool generates them and writes them to this path. Alternatively,
    [`extract_config_files.py`](extract_config_files.py) extracts them inside a TD configured
    identically to the target.
  - `rsdp`: the Root System Description Pointer, the ACPI structure that gives the address of the
    RSDT/XSDT. The tool derives it from the ACPI tables when the field is absent;
    `extract_config_files.py` extracts it from a TD.
  - `table_loader`: QEMU's ACPI table loader, the commands that load and patch the ACPI tables. The
    tool derives it from the ACPI tables when the field is absent; `extract_config_files.py` extracts
    it from a TD.
  - `smbios_tables` *(optional)*: where `--create-acpi-tables` writes the SMBIOS tables QEMU serves
    over fw_cfg, and where RTMR0 reads them with `firmware_profile` `edk2-stable202605`.
  - `firmware_profile` *(required for a version 1 direct boot)*: the firmware's direct-boot RTMR0
    event sequence. `edk2-stable202605`, the one Chutes' TDVF follows: `etc/extra-pci-roots` when
    expander root buses exist, the fixed direct-boot fw_cfg payloads, the EFI variables and
    separators, the ACPI blobs, and the SMBIOS tables as OVMF completes and filters them; it needs
    `smbios_tables`. `edk2-stable202502`, the one Ubuntu's OVMF 2025.02 follows: the EFI variables
    and separators, the ACPI blobs, BootOrder and Boot0000.
  - `qemu` *(optional)*: the QEMU launch shape that `--create-acpi-tables` runs. When present, the
    QEMU command line is `-accel -m -smp -cpu -no-reboot -nodefaults -vga none -nographic -bios
    -machine` followed by the lists below, in this order; nothing else is added. When absent, the
    tool uses Canonical's direct-boot arguments. Fields:
    - `machine` *(required)*: passed verbatim to `-machine`, for example
      `"q35,kernel_irqchip=split,memory-backend=mem0,smm=off,pic=off"`.
    - `cpu` *(default `"host"`)*: passed verbatim to `-cpu`. A named model with an explicit
      `phys-bits=N` (for example `"Skylake-Server,phys-bits=46"`) makes the run independent of the
      host CPU.
    - `accel` *(default `"kvm"`)*: passed verbatim to `-accel`. `"tcg"` runs without KVM.
    - `smp` *(default `"<cpus>,maxcpus=<cpus>"`)* and `memory` *(default `boot_config.memory`)*:
      the values of `-smp` and `-m`.
    - `globals`, `objects`, `numa`, `drives`, `netdevs`, `devices`, `fw_cfg`, `smbios`: lists of
      strings, each emitted as `-global`, `-object`, `-numa`, `-drive`, `-netdev`, `-device`,
      `-fw_cfg` and `-smbios` respectively.
    - `serial`: a list, each value emitted as `-serial` (a legacy document may give one string).
    - `processor_id` *(optional)*: the SMBIOS Type-4 Processor ID, 8 bytes as 16 hex digits (CPUID
      leaf 1 EAX then EDX, little-endian), written into every Type-4 structure of the dumped SMBIOS
      tables before RTMR0 measures them. Under KVM the dumping host's CPUID reaches that field
      unless the launch sets it; `processor_id` gives the launch host's value instead. A launch
      that fixes it with `-smbios type=4,processor-id=N` needs no `processor_id`: the same
      `-smbios` value in `smbios` gives the same bytes (`processor-id=1` is
      `0100000000000000`).

    **The order of `devices` is part of the measurement.** QEMU assigns PCI slots to `-device`
    arguments in command-line order, each taking the lowest free slot, so `devices` must list them
    in the order of the launch you are reproducing. A `slot=N` on a `pcie-root-port` is a hint only
    and moves when an earlier device already holds that slot. The order within the other lists does
    not change the ACPI tables.
    - `acpi_devices` *(optional)*: a hardware-free device list for the ACPI dump, aligned one for
      one with `devices`. Every non-VFIO entry stays byte-identical. Every `vfio-pci` endpoint is
      replaced by a stand-in with the same `bus` and `addr` (below). Such a prediction is
      provisional: the RTMR0 of the target hardware confirms it.

    **Stand-ins for passed-through devices.** The dump image's QEMU has `pci-bar-stub`
    (`pci-bar-stub.c`, from chutesai/tdx-measure), a PCI device with a declared BAR layout and no
    backing memory, so the dump runs without the device:
    `pci-bar-stub,bus=<bus>,addr=<addr>,bars=<layout>[,vendor=0xVVVV][,device=0xDDDD][,class=0xCCCC]`.
    `bars` lists `<index>:<size>:<kind>` entries separated by `;`: an index from 0 to 5 (a 64-bit BAR
    also takes the next one), a power-of-two size in bytes with an optional `K`, `M` or `G` suffix,
    and a kind, `m32`, `m64`, `p32` or `p64` (`m`: non-prefetchable, `p`: prefetchable). `vendor`,
    `device` and `class` default to 1b36:0010, class 0880. A host's captured BARs give the layout,
    for example an H200: `bars=0:16M:p64;2:256G:p64;4:32M:p64,vendor=0x10de,device=0x2335,class=0x0302`.
    `pci-bar-stub` is built into QEMU 10.1 and later (`ubuntu:25.10`, `ubuntu:26.04`). In
    `acpi_devices` three named presets stand for fixed layouts, with pci-testdev's identity
    (1b36:0005, class 00ff); their dumped tables are the bytes the earlier pci-testdev modes gave:

    | Preset | Stands for |
    |---|---|
    | `pci-testdev,membar=<MiB>M,membar-backed=off,x-rtxpro6000se=on,bus=<bus>,addr=<addr>` | `bars=0:64M:p64;2:<MiB>M:p64;4:32M:p64` (RTX PRO 6000 SE) |
    | `pci-testdev,membar=<MiB>M,membar-backed=off,x-h200=on,bus=<bus>,addr=<addr>` | `bars=0:16M:p64;2:<MiB>M:p64;4:32M:p64` (H200) |
    | `pci-testdev,membar-backed=off,x-nvswitch-ls10=on,bus=<bus>,addr=<addr>` | `bars=0:32M:m64` (LS10 NVSwitch) |

- `direct`: the direct-boot configuration, which determines RTMR1 and RTMR2.
  - `kernel`: the kernel image (for example `vmlinuz`) that the firmware loads and runs. Canonical's
    [direct-boot instructions](https://github.com/canonical/tdx/tree/main/guest-tools/direct-boot#prerequisites)
    show how to obtain one.
  - `initrd`: the initial RAM disk (for example `initrd.img`), from the same instructions.
  - `cmdline`: the kernel command line, as passed to QEMU with `-append`.

Direct boot needs no `boot_order` or `path_boot_xxxx`: there is one standard BootOrder variable and
one Boot#### variable, which the tool computes.

#### Generating ACPI tables

With `--create-acpi-tables` the tool builds a small Docker image whose patched QEMU writes
`etc/acpi/tables` (and, with `smbios_tables`, the fw_cfg SMBIOS tables) and exits before the TD
starts, then runs it with the metadata's launch shape. This needs Docker, and KVM on the host when
`accel` is `"kvm"`. The base image of each distribution is pinned by digest, and so is the QEMU
version:

| Distribution   | QEMU source                         | Pinned QEMU version               |
|----------------|-------------------------------------|-----------------------------------|
| `ubuntu:24.04` | `kobuk-team/tdx-release` PPA        | `2:8.2.2+ds-0ubuntu1.4+tdx1.1`    |
| `ubuntu:25.04` | `kobuk-team/tdx-release` PPA        | `1:9.2.1+ds-1ubuntu4+tdx2.0~ppa2` |
| `ubuntu:25.10` | distribution main archive           | `1:10.1.0+ds-5ubuntu2.7`          |
| `ubuntu:26.04` | distribution main archive           | `1:10.2.1+ds-1ubuntu4`            |

The same metadata and command line give the same ACPI bytes whenever they run. A second value
overrides the version, for example to check a stable release update:

```
--create-acpi-tables ubuntu:26.04                              # the pinned version
--create-acpi-tables ubuntu:26.04 1:10.2.1+ds-1ubuntu3.2       # an explicit version
```

A version string names a Launchpad publication, not its bytes, so `Dockerfile.qemu-acpi-dump` pins
the three source package files (`.dsc`, `.orig.tar.xz`, `.debian.tar.xz`) of every version it builds
by sha256: it downloads them without unpacking, checks them, and only then runs `dpkg-source -x`.
Any other version builds when `--qemu-dsc-sha256` gives the sha256 of its `.dsc`: the `.dsc` must
have it, and every file the `.dsc` lists must have the sha256 the `.dsc`'s `Checksums-Sha256` field
gives, before anything is unpacked. That lets the version come with its hash from wherever the
launch host's QEMU is recorded:

```
--create-acpi-tables ubuntu:26.04 1:10.2.1+ds-1ubuntu3.1 \
  --qemu-dsc-sha256 8499c312190488c1126fe61a9e340928eb78da0eff68e7b168ee30627d4a0ad7
```

A version with neither, including `""`, does not build.

Without `--create-acpi-tables` the tool measures the tables the metadata names: `acpi_tables`, and
for `edk2-stable202605` `smbios_tables`.

#### Building QEMU from a source tarball

Instead of a distribution package, the container can build QEMU from an upstream source tarball
checked against a SHA-256, with any supported base distribution. Both flags are required:

```
--create-acpi-tables ubuntu:24.04 \
  --qemu-source-url https://download.qemu.org/qemu-9.2.1.tar.xz \
  --qemu-source-sha256 <sha256 of the tarball>
```

The container downloads the tarball, refuses it unless `sha256sum -c` passes, and builds from it. It
may be `.tar.xz`, `.gz` or `.bz2` and must unpack to a top-level `qemu*/` directory.

#### SEV-SNP platform-table dump

`--snp-dump <DIR> --snp-dump-image <IMAGE> --snp-qemu-version <VERSION>` writes into `DIR` the ACPI
table blob (`acpi-tables.bin`), the RSDP (`rsdp.bin`) and the `etc/table-loader` script
(`table-loader.bin`) that QEMU builds for one SEV-SNP measurement shape: the metadata's
`boot_config`, with the checking firmware as its `bios`. It computes no measurement. It runs only an
image named by digest (`<name>@sha256:<64 hex>`), built from `Dockerfile.qemu-acpi-dump-snp`
with the three source package files of the host's QEMU package, each checked by sha256:
`./build-snp-dump-image.sh --load OUT_DIR` (or `make snp-dump-image`) builds it reproducibly
(BUILD.md) and loads it as `chutes-tdx-measure/qemu-acpi-dump-snp`. It
runs that image under TCG with `docker run --rm --pull=never --network=none`, after checking that
the image's QEMU version label equals `--snp-qemu-version`. It never builds or pulls an image, and
it refuses `--create-acpi-tables` and the `--qemu-source-*` flags. Chutes' image build runs it for
each SEV-SNP launch shape and folds each dump into the transcript the checking firmware recomputes
at boot.

### Indirect boot

#### Metadata

```
{
  "boot_config": {
    "cpus": 32,
    "memory": "10G",
    "bios": "[path to OVMF.fd]",
    "acpi_tables": "[path to acpi_tables.bin]",
    "rsdp": "[path to rsdp.bin]",
    "table_loader": "[path to table_loader.bin]",
    "boot_order": "[path to BootOrder.bin]",
    "path_boot_xxxx": "[path to directory containing Bootxxxx.bin files]"
  },
  "indirect": {
    "qcow2": "[path to tdx-guest-ubuntu-25.04-generic.qcow2]",
    "cmdline": "console=ttyS0 root=/dev/vda1",
    "mok_list": "[path to MokList.bin]",
    "mok_list_trusted": "[path to MokListTrusted.bin]",
    "mok_list_x": "[path to MokListX.bin]",
    "sbat_level": "[path to SbatLevel.bin]"
  }
}
```

#### Metadata fields

[`extract_config_files.py`](extract_config_files.py), run inside a TD configured identically to the
target, extracts every file below except `qcow2`.

- `boot_config`: as for direct boot, plus:
  - `boot_order`: the UEFI BootOrder variable, the order in which the firmware tries boot options.
  - `path_boot_xxxx`: a directory of `Boot0000.bin`, `Boot0001.bin`, ... files, one per Boot####
    variable, each a boot option's device path and description.
  - With indirect boot, `--create-acpi-tables` is refused: `acpi_tables` comes from the TD.
- `indirect`: the boot chain, which determines RTMR1 and RTMR2.
  - `qcow2`: the guest disk image in QCOW2 format, with the boot loader chain (shim and GRUB) and a
    kernel. Canonical's [instructions](https://github.com/canonical/tdx/tree/main?tab=readme-ov-file#5-create-td-image)
    create one.
  - `cmdline`: the kernel command line, as `cat /proc/cmdline` shows it inside the TD.
  - `mok_list`: the Machine Owner Key list for Secure Boot, the user-enrolled keys added to the
    vendor's.
  - `mok_list_trusted`: the trusted MOK list.
  - `mok_list_x`: the MOK deny list, keys revoked explicitly.
  - `sbat_level`: the SBAT (Secure Boot Advanced Targeting) revocation list, which revokes boot loader
    versions without revoking their signing keys.

### Transcript

`--transcript FILE` writes a human-readable transcript of the binary configuration files. It
disassembles the ACPI tables with `iasl`, which must be installed.

## Moving from chutesai/tdx-measure

This tool reads the documents chutes-cvm renders for the chutesai/tdx-measure fork unchanged (the
fork form above) and gives the same MRTD, RTMR0, RTMR1 and RTMR2, run with the same arguments,
except that it builds only a QEMU version it pins or one named with `--qemu-dsc-sha256`. The fork's
`ubuntu:26.04` default is `1:10.2.1+ds-1ubuntu3.1`:

```
tdx-measure metadata.json --platform-only --json-file out.json \
  --create-acpi-tables ubuntu:26.04 1:10.2.1+ds-1ubuntu3.1 \
  --qemu-dsc-sha256 8499c312190488c1126fe61a9e340928eb78da0eff68e7b168ee30627d4a0ad7
tdx-measure --runtime-only runtime.json      # RTMR1 and RTMR2, without --patch-kernel
```

Its JSON output has `mrtd`, `rtmr0`, `rtmr1` and `rtmr2`; the fork's also had `rtmr0_log`.
The version 1 form of the same document adds `"metadata_version": 1`,
`"firmware_profile": "edk2-stable202605"` and `smbios_tables`, and drops a `null` `processor_id`.

`tools/fork-equivalence.py` runs host profiles through both binaries and reports MRTD, RTMR0 (as
the fork form and as version 1), RTMR1, RTMR2 and the dumped ACPI and SMBIOS tables of each as
match or MISMATCH. It renders each profile with chutes-cvm, as `measurements generate` does, so
chutes-cvm must be importable (`--chutes-cvm` names its source directory otherwise):

```
python3 tools/fork-equivalence.py PROFILES_DIR \
  --fork /path/to/fork/tdx-measure --ours /path/to/this/tdx-measure \
  --firmware-dir /path/to/firmware \
  --image /path/to/release.qcow2 \
  --report report.json
```

Each file in `PROFILES_DIR` is a host profile as the API stores it, one record of
`GET /servers/tdx/host_profiles` (`{"fingerprint", "measured", "profile"}`), a list of records, or a
ready metadata document. `--firmware-dir` holds `OVMF.inteltdx.fd` and `OVMF.amdsev.fd`, as
chutes-cvm's `--bios-dir`; `--image` names a release image whose staged `.vmlinuz`, `.initrd` and
`.cmdline` give RTMR1 and RTMR2 (or `--kernel`, `--initrd` and `--cmdline`). The fork runs as
chutes-cvm runs it; this tool gets `--qemu-version` and `--qemu-dsc-sha256`, by default the fork's
pin above. The fork builds its dump image with `docker build --progress plain`, which needs Docker's
buildx plugin. The runs are sequential; the tool exits 0 only when every value matches.

`tools/fork-equivalence-profiles/` holds 15 host profiles in the API's form, rendered with
chutes-cvm from its test fixtures and captured BAR layouts: 8x RTX PRO 6000 (guest NUMA, flat,
interleaved and partly without NUMA affinity), 8x H200 with four NVSwitches on either node, 4x H200,
8x B300, 8x B200 (176 and 272 vCPUs), 1x H100 PCIe, and AMD hosts of four of them.

## Building outside Docker

`cargo build --release` builds the library and `cargo install --path cli` installs the command with a
local Rust toolchain ([rustup](https://www.rust-lang.org/tools/install)). That binary works the same
but is not the pinned one: `make build` gives the pinned bytes.

## Boot methods

Canonical's TDX repository offers two:

1. **Direct boot**: OVMF (the TDVF) boots the kernel directly; QEMU receives the kernel, the initrd and
   the kernel command line.
2. **Indirect boot**: `tdvirsh` runs the TD, and the boot chain is OVMF, shim, GRUB and then the
   kernel and initrd.

## What the measurements cover

A TDX attestation report carries four measurement registers.

- `MRTD`: the TD's virtual firmware (the TDVF).
- `RTMR[0]`: the firmware configuration and platform: the TD HOB (mostly the memory the TD can
  reach), the TDX configuration values, the Secure Boot variables, the ACPI tables, the boot
  variables (BootOrder and others) and, for indirect boot, the
  [SbatLevel](https://github.com/rhboot/shim/blob/main/SbatLevel_Variable.txt) variable.
- `RTMR[1]`: the kernel for direct boot; for indirect boot, the boot chain: the GPT, shim and GRUB.
- `RTMR[2]`: the kernel command line and the initrd for direct boot; for indirect boot, also the
  [MOK variables](https://github.com/rhboot/shim/blob/main/MokVars.txt).
