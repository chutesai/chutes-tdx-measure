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
make test    # the library's unit tests, tests/parse.rs and tests/chutes.rs
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
                                    distribution; a version builds only when Dockerfile.qemu-acpi-dump
                                    pins its source package files by sha256 (below)
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

#### Metadata fields

- `boot_config`: the platform configuration, which determines MRTD and RTMR0.
  - `cpus`: the number of virtual CPUs of the TD.
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
  - `firmware_profile` *(optional)*: `edk2-stable202605` selects that firmware's RTMR0 event
    sequence, the one Chutes' TDVF follows: `etc/extra-pci-roots` when expander root buses exist,
    the fixed direct-boot fw_cfg payloads, the EFI variables and separators, the ACPI blobs, and the
    SMBIOS tables as OVMF completes and filters them. It needs `smbios_tables`.
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
    - `serial`: passed verbatim to `-serial`.

    **The order of `devices` is part of the measurement.** QEMU assigns PCI slots to `-device`
    arguments in command-line order, each taking the lowest free slot, so `devices` must list them
    in the order of the launch you are reproducing. A `slot=N` on a `pcie-root-port` is a hint only
    and moves when an earlier device already holds that slot. The order within the other lists does
    not change the ACPI tables.
    - `acpi_devices` *(optional)*: a hardware-free device list for the ACPI dump, aligned one for
      one with `devices`. Every non-VFIO entry stays byte-identical. Every `vfio-pci` endpoint is
      replaced by an unbacked `pci-testdev` with the same `bus` and `addr`, in one of two forms: the
      GPU form `pci-testdev,membar=<MiB>M,membar-backed=off,<mode>=on,bus=<bus>,addr=<addr>` with a
      positive `membar` and exactly one GPU mode (`x-rtxpro6000se`: BAR0 64 MiB and BAR4 32 MiB;
      `x-h200`: BAR0 16 MiB and BAR4 32 MiB; both 64-bit prefetchable, no I/O BAR), or the NVSwitch
      form `pci-testdev,membar-backed=off,x-nvswitch-ls10=on,bus=<bus>,addr=<addr>` (one 32 MiB
      64-bit non-prefetchable BAR0, no `membar`). Such a prediction is provisional: the RTMR0 of the
      target hardware confirms it.

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
by sha256: it downloads them without unpacking, checks them, and only then runs `dpkg-source -x`. A
version without pins, including `""`, does not build: add its three rows to the Dockerfile and
rebuild the tool, or use a source tarball.

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
