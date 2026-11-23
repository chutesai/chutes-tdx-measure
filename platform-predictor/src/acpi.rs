/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025-2026 Intel Corporation
 * Modified by Chutes Global Corp, 2026; the changes are listed in CHUTES-UPSTREAM.md.
 * SPDX-License-Identifier: Apache-2.0
 */
//! This module provides functionality to load ACPI tables for QEMU from files.

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::read_file_data;
use crate::{BootConfig, ImageConfig, Machine, QemuShape};

const DOCKERFILE_QEMU_ACPI_DUMP: &str = include_str!("../Dockerfile.qemu-acpi-dump");
const CONTAINER_NAME: &str = "acpi-tables-generator";
const IMAGE_NAME: &str = "acpi-tables-generator";
const OVMF_IN_CONTAINER: &str = "/usr/share/ovmf/OVMF.fd";

const LDR_LENGTH: usize = 4096;
const FIXED_STRING_LEN: usize = 56;

// The SEV-SNP platform-table dump: the patched QEMU of `Dockerfile.qemu-acpi-dump-snp` writes
// these three fw_cfg blobs into /output.
const SNP_DUMP_TABLES: &str = "acpi-tables.bin";
const SNP_DUMP_RSDP: &str = "rsdp.bin";
const SNP_DUMP_LOADER: &str = "table-loader.bin";
const SNP_DUMP_QEMU_LABEL: &str = "org.chutes.qemu-package-version";

pub struct Tables {
    pub tables: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub loader: Vec<u8>,
}

/// The three fw_cfg blobs of one SEV-SNP platform-table dump, exactly as QEMU serves them:
/// `etc/acpi/tables`, `etc/acpi/rsdp` and `etc/table-loader`.
pub struct SnpPlatformDump {
    pub tables: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub loader: Vec<u8>,
}

impl Machine<'_> {
    pub fn build_tables(&self) -> Result<Tables> {
        let tables = if self.direct_boot && self.create_acpi_table {
            generate_acpi_tables(
                self.metadata_path,
                self.distribution,
                self.qemu_version,
                self.qemu_source_url,
                self.qemu_source_sha256,
            )?
        } else {
            read_file_data(self.acpi_tables)?
        };
        self.process_acpi_tables(tables)
    }

    fn process_acpi_tables(&self, tables: Vec<u8>) -> Result<Tables> {
        let rsdp: Vec<u8> = if !self.rsdp.is_empty() {
            read_file_data(self.rsdp)?
        } else {
            let (rsdt_offset, _rsdt_csum, _rsdt_len) = find_acpi_table(&tables, "RSDT")?;

            // Generate RSDP
            let mut rsdp = Vec::with_capacity(20);
            rsdp.extend_from_slice(b"RSD PTR "); // Signature
            rsdp.push(0x00); // Checksum placeholder
            rsdp.extend_from_slice(b"BOCHS "); // OEM ID
            rsdp.push(0x00); // Revision
            rsdp.extend_from_slice(&rsdt_offset.to_le_bytes()); // RSDT Address
            rsdp
        };

        let loader: Vec<u8> = if !self.table_loader.is_empty() {
            read_file_data(self.table_loader)?
        } else {
            derive_table_loader(&tables)?
        };

        Ok(Tables {
            tables,
            rsdp,
            loader,
        })
    }

    pub fn build_tables_with_boot_config(&self, boot_config: &BootConfig) -> Result<Tables> {
        let mut acpi_tables_path = self.acpi_tables;
        if acpi_tables_path.is_empty() {
            acpi_tables_path = &boot_config.acpi_tables; // override if Machine::acpi_tables is empty.
        }
        let maybe_acpi_tables_target = if acpi_tables_path.is_empty() {
            None
        } else {
            let acpi_tables_target = Path::new("").join(acpi_tables_path);
            let acpi_tables_dir = acpi_tables_target.parent().with_context(|| {
                format!(
                    "acpi_tables has no parent dir: {}",
                    acpi_tables_target.display()
                )
            })?;
            fs_err::create_dir_all(acpi_tables_dir)?;
            Some(acpi_tables_target)
        };
        let maybe_smbios_tables_target = boot_config
            .smbios_tables
            .as_ref()
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let generate_tables = || {
            let tables = generate_acpi_tables_with_qemu_args(
                boot_config,
                self.distribution,
                self.qemu_version,
                self.qemu_source_url,
                self.qemu_source_sha256,
                maybe_acpi_tables_target.as_ref(),
                maybe_smbios_tables_target.as_ref(),
            )?;
            self.process_acpi_tables(tables)
        };
        if self.create_acpi_table {
            if self.direct_boot {
                generate_tables()
            } else {
                Err(anyhow!(
                    "ACPI table cannot be generated for `indirect_boot`"
                ))
            }
        } else {
            generate_tables()
        }
    }
}

/// Walks the concatenated ACPI tables blob exposed by QEMU via `etc/acpi/tables`
/// and returns one entry per System Description Table found in it, in file order.
/// Each tuple is `(signature, offset, csum_offset, length)` where `csum_offset`
/// is the byte offset of the table's `Checksum` field (header offset 9).
fn list_acpi_tables(tables: &[u8]) -> Result<Vec<([u8; 4], u32, u32, u32)>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= tables.len() {
        let sig: [u8; 4] = tables[off..off + 4].try_into().unwrap();
        if !sig.iter().all(|b| (32..127).contains(b)) {
            break;
        }
        let len = u32::from_le_bytes(tables[off + 4..off + 8].try_into().unwrap()) as usize;
        if len < 8 || off + len > tables.len() {
            bail!("ACPI table at offset {off:#x} has invalid length {len}");
        }
        out.push((sig, off as u32, (off + 9) as u32, len as u32));
        off += len;
    }
    Ok(out)
}

/// Build the QEMU table-loader blob (`etc/table-loader`) from a concatenated ACPI
/// tables image. The command order mirrors what QEMU's `acpi_build` emits today:
///   Allocate rsdp + Allocate tables
///   AddChecksum DSDT
///   AddPtr FACP→FACS, FACP→DSDT (4-byte), FACP→DSDT (8-byte X_DSDT)
///   AddChecksum FACP
///   AddChecksum {APIC, HPET, MCFG, WAET, ...} in file order
///   AddPtr RSDT→entry_i for each 4-byte entry (one per non-DSDT table)
///   AddChecksum RSDT
///   AddPtr RSDP→RSDT, AddChecksum RSDP
fn derive_table_loader(tables: &[u8]) -> Result<Vec<u8>> {
    const TABLES_FILE: &str = "etc/acpi/tables";
    const RSDP_FILE: &str = "etc/acpi/rsdp";

    let list = list_acpi_tables(tables)?;

    let find = |sig: &str| -> Result<(u32, u32, u32)> {
        list.iter()
            .find(|(s, ..)| s.as_slice() == sig.as_bytes())
            .map(|&(_, off, csum, len)| (off, csum, len))
            .ok_or_else(|| anyhow!("Required ACPI table missing: {sig}"))
    };
    let (dsdt_offset, dsdt_csum, dsdt_len) = find("DSDT")?;
    let (facp_offset, facp_csum, facp_len) = find("FACP")?;
    let (rsdt_offset, rsdt_csum, rsdt_len) = find("RSDT")?;

    let mut loader = TableLoader::new();
    loader.append(LoaderCmd::Allocate {
        file: RSDP_FILE,
        alignment: 16,
        zone: 2,
    });
    loader.append(LoaderCmd::Allocate {
        file: TABLES_FILE,
        alignment: 64,
        zone: 1,
    });
    loader.append(LoaderCmd::AddChecksum {
        file: TABLES_FILE,
        result_offset: dsdt_csum,
        start: dsdt_offset,
        length: dsdt_len,
    });
    for ptr_offset in [36u32, 40] {
        loader.append(LoaderCmd::AddPtr {
            pointer_file: TABLES_FILE,
            pointee_file: TABLES_FILE,
            pointer_offset: facp_offset + ptr_offset,
            pointer_size: 4,
        });
    }
    loader.append(LoaderCmd::AddPtr {
        pointer_file: TABLES_FILE,
        pointee_file: TABLES_FILE,
        pointer_offset: facp_offset + 140,
        pointer_size: 8,
    });
    loader.append(LoaderCmd::AddChecksum {
        file: TABLES_FILE,
        result_offset: facp_csum,
        start: facp_offset,
        length: facp_len,
    });
    // Non-DSDT/FACP/RSDT secondary tables in their file order, e.g. APIC, HPET,
    // MCFG, WAET. FACS lives in the same blob but has no Checksum slot and is
    // wired to FACP via the FIRMWARE_CTRL pointer above, so skip it here.
    for (sig, off, csum, len) in &list {
        if matches!(sig.as_slice(), b"FACS" | b"DSDT" | b"FACP" | b"RSDT") {
            continue;
        }
        loader.append(LoaderCmd::AddChecksum {
            file: TABLES_FILE,
            result_offset: *csum,
            start: *off,
            length: *len,
        });
    }
    // RSDT lists every non-DSDT table; emit one 4-byte AddPtr per entry slot.
    const RSDT_HEADER_LEN: u32 = 36;
    if rsdt_len < RSDT_HEADER_LEN || (rsdt_len - RSDT_HEADER_LEN) % 4 != 0 {
        bail!("Malformed RSDT length: {rsdt_len}");
    }
    let rsdt_entries = (rsdt_len - RSDT_HEADER_LEN) / 4;
    for i in 0..rsdt_entries {
        loader.append(LoaderCmd::AddPtr {
            pointer_file: TABLES_FILE,
            pointee_file: TABLES_FILE,
            pointer_offset: rsdt_offset + RSDT_HEADER_LEN + i * 4,
            pointer_size: 4,
        });
    }
    loader.append(LoaderCmd::AddChecksum {
        file: TABLES_FILE,
        result_offset: rsdt_csum,
        start: rsdt_offset,
        length: rsdt_len,
    });
    loader.append(LoaderCmd::AddPtr {
        pointer_file: RSDP_FILE,
        pointee_file: TABLES_FILE,
        pointer_offset: 16,
        pointer_size: 4,
    });
    loader.append(LoaderCmd::AddChecksum {
        file: RSDP_FILE,
        result_offset: 8,
        start: 0,
        length: 20,
    });

    if loader.buffer.len() < LDR_LENGTH {
        loader.buffer.resize(LDR_LENGTH, 0);
    }
    Ok(loader.buffer)
}

/// An enum to represent the different QEMU loader commands in a type-safe way.
#[derive(Debug)]
enum LoaderCmd<'a> {
    Allocate {
        file: &'a str,
        alignment: u32,
        zone: u8,
    },
    AddPtr {
        pointer_file: &'a str,
        pointee_file: &'a str,
        pointer_offset: u32,
        pointer_size: u8,
    },
    AddChecksum {
        file: &'a str,
        result_offset: u32,
        start: u32,
        length: u32,
    },
}

/// Builder for QEMU-specific loader commands that instruct firmware how to load and patch ACPI tables.
struct TableLoader {
    /// Buffer containing serialized QEMU loader commands
    buffer: Vec<u8>,
}

impl TableLoader {
    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(LDR_LENGTH),
        }
    }

    /// Appends a fixed-length, null-padded string to the data buffer.
    fn append_fixed_string(data: &mut Vec<u8>, s: &str) {
        let mut s_bytes = s.as_bytes().to_vec();
        s_bytes.resize(FIXED_STRING_LEN, 0);
        data.extend_from_slice(&s_bytes);
    }

    fn append(&mut self, cmd: LoaderCmd) {
        match cmd {
            LoaderCmd::Allocate {
                file,
                alignment,
                zone,
            } => {
                self.buffer.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
                Self::append_fixed_string(&mut self.buffer, file);
                self.buffer.extend_from_slice(&alignment.to_le_bytes());
                self.buffer.push(zone);
                self.buffer.resize(self.buffer.len() + 63, 0); // Padding
            }
            LoaderCmd::AddPtr {
                pointer_file,
                pointee_file,
                pointer_offset,
                pointer_size,
            } => {
                self.buffer.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
                Self::append_fixed_string(&mut self.buffer, pointer_file);
                Self::append_fixed_string(&mut self.buffer, pointee_file);
                self.buffer.extend_from_slice(&pointer_offset.to_le_bytes());
                self.buffer.push(pointer_size);
                self.buffer.resize(self.buffer.len() + 7, 0); // Padding
            }
            LoaderCmd::AddChecksum {
                file,
                result_offset,
                start,
                length,
            } => {
                self.buffer.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
                Self::append_fixed_string(&mut self.buffer, file);
                self.buffer.extend_from_slice(&result_offset.to_le_bytes());
                self.buffer.extend_from_slice(&start.to_le_bytes());
                self.buffer.extend_from_slice(&length.to_le_bytes());
                self.buffer.resize(self.buffer.len() + 56, 0); // Padding
            }
        }
    }
}

/// Searches for an ACPI table with the given signature and returns its offset,
/// checksum offset, and length.
fn find_acpi_table(tables: &[u8], signature: &str) -> Result<(u32, u32, u32)> {
    if signature.len() != 4 {
        bail!("Signature must be 4 characters long, but got '{signature}'");
    }

    let sig_bytes = signature.as_bytes();

    let mut offset = 0;
    while offset < tables.len() {
        // Ensure there's enough space for a table header
        if offset + 8 > tables.len() {
            bail!("Table not found: {signature}");
        }

        let tbl_sig = &tables[offset..offset + 4];
        let tbl_len_bytes: [u8; 4] = tables[offset + 4..offset + 8].try_into().unwrap();
        let tbl_len = u32::from_le_bytes(tbl_len_bytes) as usize;

        if tbl_sig == sig_bytes {
            // Found the table
            return Ok((offset as u32, (offset + 9) as u32, tbl_len as u32));
        }

        if tbl_len == 0 {
            // Invalid table length, stop searching
            bail!("Found table with zero length at offset {offset}");
        }
        // Move to the next table
        offset += tbl_len;
    }

    bail!("Table not found: {signature}");
}

/// Describes how to fetch the QEMU source for a given distribution.
struct QemuPkg<'a> {
    /// `ppa` -> `pull-ppa-source --ppa ppa:kobuk-team/tdx-release qemu $VERSION`
    /// `main` -> `pull-lp-source qemu $VERSION`
    /// `url`  -> download a source tarball from `url` and verify it against `sha256`
    source: &'static str,
    /// Version handed to the source fetcher. For `main`/`ppa` the Dockerfile builds
    /// only a version whose source package files it pins by sha256 (never an empty one).
    version: &'a str,
    /// Immutable OCI digest of the base image (`sha256:...`).
    image_digest: &'static str,
    /// For `source == "url"`: the QEMU source-tarball URL and its expected
    /// SHA-256 (hex). Ignored for `ppa`/`main`.
    url: Option<&'a str>,
    sha256: Option<&'a str>,
}

fn qemu_pkg_for<'a>(distribution: &str, version_override: Option<&'a str>) -> Result<QemuPkg<'a>> {
    // Pinned defaults for reproducibility; override via `--qemu-version`.
    let (source, default_version, image_digest): (&'static str, &'static str, &'static str) =
        match distribution {
            "ubuntu:24.04" => (
                "ppa",
                "2:8.2.2+ds-0ubuntu1.4+tdx1.1",
                "sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54",
            ),
            "ubuntu:25.04" => (
                "ppa",
                "1:9.2.1+ds-1ubuntu4+tdx2.0~ppa2",
                "sha256:27771fb7b40a58237c98e8d3e6b9ecdd9289cec69a857fccfb85ff36294dac20",
            ),
            "ubuntu:25.10" => (
                "main",
                "1:10.1.0+ds-5ubuntu2.7",
                "sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092",
            ),
            "ubuntu:26.04" => (
                "main",
                "1:10.2.1+ds-1ubuntu4",
                "sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64",
            ),
            other => bail!(
                "Unsupported distribution: {other}. Supported: ubuntu:24.04, \
             ubuntu:25.04, ubuntu:25.10, ubuntu:26.04"
            ),
        };
    Ok(QemuPkg {
        source,
        version: version_override.unwrap_or(default_version),
        image_digest,
        url: None,
        sha256: None,
    })
}

/// Builds the QEMU command line that the patched in-container QEMU will run to
/// dump `etc/acpi/tables`. When `qemu` is `Some(_)`, the command is taken
/// verbatim from the block plus the seven measurement-related core flags;
/// nothing else is added implicitly. When `qemu` is `None`, the script falls
/// back to the Canonical direct-boot defaults so Intel's reference scenario
/// keeps working unchanged.
fn qemu_device_field<'a>(device: &'a str, key: &str) -> Option<&'a str> {
    device.split(',').skip(1).find_map(|field| {
        let (name, value) = field.split_once('=')?;
        (name == key).then_some(value)
    })
}

// The closed ACPI-surrogate forms: the GPU form
// `pci-testdev,membar=<MiB>M,membar-backed=off,<gpu mode>=on,bus=<bus>,addr=<addr>` with
// exactly one GPU mode, and the NVSwitch form
// `pci-testdev,membar-backed=off,x-nvswitch-ls10=on,bus=<bus>,addr=<addr>` without a membar.
// The modes are the patched QEMU's (`Dockerfile.qemu-acpi-dump`).
const ACPI_SURROGATE_GPU_MODES: [&str; 2] = ["x-rtxpro6000se", "x-h200"];
const ACPI_SURROGATE_NVSWITCH_MODE: &str = "x-nvswitch-ls10";
const ACPI_SURROGATE_GPU_FIELDS: usize = 6;
const ACPI_SURROGATE_NVSWITCH_FIELDS: usize = 5;

/// The sorted property names of one `-device` value, or `None` when a property is not
/// `name=value` or repeats.
fn qemu_device_keys(device: &str) -> Option<Vec<&str>> {
    let mut keys: Vec<&str> = Vec::new();
    for field in device.split(',').skip(1) {
        let (name, _) = field.split_once('=')?;
        if keys.contains(&name) {
            return None;
        }
        keys.push(name);
    }
    keys.sort_unstable();
    Some(keys)
}

/// Whether `surrogate` is an unbacked `pci-testdev` with exactly `field_count` fields and
/// exactly the property names `keys`.
fn is_exact_surrogate_form(surrogate: &str, field_count: usize, keys: &[&str]) -> bool {
    let mut expected: Vec<&str> = keys.to_vec();
    expected.sort_unstable();
    let actual = qemu_device_keys(surrogate);
    surrogate.split(',').count() == field_count
        && surrogate.split(',').next() == Some("pci-testdev")
        && qemu_device_field(surrogate, "membar-backed") == Some("off")
        && actual.as_deref() == Some(expected.as_slice())
}

fn acpi_devices(qemu: &QemuShape) -> Result<&[String]> {
    let Some(acpi_devices) = qemu.acpi_devices.as_deref() else {
        return Ok(&qemu.devices);
    };
    if acpi_devices.len() != qemu.devices.len() {
        bail!("qemu.acpi_devices must align one-for-one with qemu.devices");
    }
    let mut replacements = 0usize;
    for (live, surrogate) in qemu.devices.iter().zip(acpi_devices) {
        if !live.starts_with("vfio-pci,") {
            if surrogate != live {
                bail!("qemu.acpi_devices may not alter a non-VFIO device");
            }
            continue;
        }
        replacements += 1;
        let gpu_mode = ACPI_SURROGATE_GPU_MODES
            .iter()
            .copied()
            .find(|mode| qemu_device_field(surrogate, mode) == Some("on"));
        let gpu_form = match gpu_mode {
            Some(mode) => is_exact_surrogate_form(
                surrogate,
                ACPI_SURROGATE_GPU_FIELDS,
                &["membar", "membar-backed", mode, "bus", "addr"],
            ),
            None => false,
        };
        let nvswitch_form = qemu_device_field(surrogate, ACPI_SURROGATE_NVSWITCH_MODE)
            == Some("on")
            && is_exact_surrogate_form(
                surrogate,
                ACPI_SURROGATE_NVSWITCH_FIELDS,
                &["membar-backed", ACPI_SURROGATE_NVSWITCH_MODE, "bus", "addr"],
            );
        if !gpu_form && !nvswitch_form {
            bail!(
                "each VFIO ACPI surrogate must be one unbacked pci-testdev endpoint in one of two \
                 forms: the GPU form (membar=<MiB>M, membar-backed=off, exactly one of \
                 x-rtxpro6000se=on or x-h200=on, bus, addr) or the NVSwitch form \
                 (membar-backed=off, x-nvswitch-ls10=on, bus, addr; no membar)"
            );
        }
        if gpu_form {
            let membar_mib = qemu_device_field(surrogate, "membar")
                .and_then(|value| value.strip_suffix('M'))
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| anyhow!("VFIO ACPI surrogate membar must be positive MiB"))?;
            let _ = membar_mib;
        }
        for field in ["bus", "addr"] {
            if qemu_device_field(live, field).is_none()
                || qemu_device_field(live, field) != qemu_device_field(surrogate, field)
            {
                bail!("VFIO ACPI surrogate must preserve the exact {field}");
            }
        }
        if qemu_device_field(surrogate, "host").is_some()
            || qemu_device_field(surrogate, "iommufd").is_some()
        {
            bail!("VFIO ACPI surrogate must not carry host or iommufd authority");
        }
    }
    if replacements == 0 {
        bail!("qemu.acpi_devices requires at least one VFIO replacement");
    }
    Ok(acpi_devices)
}

fn build_qemu_args(qemu: Option<&QemuShape>, cpus: u8, memory: &str) -> Result<Vec<OsString>> {
    let mut args: Vec<OsString> = Vec::new();
    let push = |args: &mut Vec<OsString>, k: &str, v: &str| {
        args.push(k.into());
        args.push(v.into());
    };

    match qemu {
        Some(q) => {
            let smp = q
                .smp
                .clone()
                .unwrap_or_else(|| format!("{cpus},maxcpus={cpus}"));
            let qemu_memory = q.memory.as_deref().unwrap_or(memory);
            push(&mut args, "-accel", &q.accel);
            push(&mut args, "-m", qemu_memory);
            push(&mut args, "-smp", &smp);
            push(&mut args, "-cpu", &q.cpu);
            args.push("-no-reboot".into());
            args.push("-nodefaults".into());
            push(&mut args, "-vga", "none");
            args.push("-nographic".into());
            push(&mut args, "-bios", OVMF_IN_CONTAINER);
            push(&mut args, "-machine", &q.machine);
            for v in &q.globals {
                push(&mut args, "-global", v);
            }
            for v in &q.objects {
                push(&mut args, "-object", v);
            }
            for v in &q.numa {
                push(&mut args, "-numa", v);
            }
            for v in &q.drives {
                push(&mut args, "-drive", v);
            }
            for v in &q.netdevs {
                push(&mut args, "-netdev", v);
            }
            for v in acpi_devices(q)? {
                push(&mut args, "-device", v);
            }
            for v in &q.fw_cfg {
                push(&mut args, "-fw_cfg", v);
            }
            for v in &q.smbios {
                push(&mut args, "-smbios", v);
            }
            if let Some(serial) = &q.serial {
                push(&mut args, "-serial", serial);
            }
        }
        None => {
            // Canonical direct-boot defaults: minimal args from
            // https://github.com/canonical/tdx/blob/3.3/guest-tools/direct-boot/boot_direct.sh#L54
            push(&mut args, "-accel", "kvm");
            push(&mut args, "-m", memory);
            push(&mut args, "-smp", &cpus.to_string());
            push(&mut args, "-cpu", "host");
            push(
                &mut args,
                "-machine",
                "q35,kernel-irqchip=split,hpet=off,smm=off,pic=off",
            );
            push(&mut args, "-bios", OVMF_IN_CONTAINER);
            args.push("-nographic".into());
            args.push("-nodefaults".into());
            push(&mut args, "-serial", "stdio");
        }
    }
    Ok(args)
}

fn prepare_output_drives(qemu: Option<&QemuShape>, output_dir: &Path) -> Result<()> {
    let Some(qemu) = qemu else {
        return Ok(());
    };
    for drive in &qemu.drives {
        let Some(path) = drive
            .split(',')
            .find_map(|field| field.strip_prefix("file=/output/"))
        else {
            continue;
        };
        if path.is_empty() || path.contains('/') || path.contains("..") {
            bail!("invalid /output dummy drive path in qemu shape: {path:?}");
        }
        let drive_path = output_dir.join(path);
        let file = std::fs::File::create(&drive_path)
            .with_context(|| format!("Failed to create dummy drive {}", drive_path.display()))?;
        file.set_len(1024 * 1024)?;
        fs_err::set_permissions(&drive_path, std::fs::Permissions::from_mode(0o666))?;
    }
    Ok(())
}

/// Resolves a metadata-relative path against `metadata_path`'s parent.
fn resolve_metadata_path(metadata_path: &Path, path: &str) -> PathBuf {
    metadata_path.parent().unwrap_or(Path::new(".")).join(path)
}

/// Returns the host's `kvm` group id, if the group exists. Used to grant the
/// container access to `/dev/kvm` and `/dev/vhost-vsock`.
fn kvm_group_id() -> Option<String> {
    let out = Command::new("getent")
        .args(["group", "kvm"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout)
        .ok()?
        .lines()
        .next()
        .and_then(|line| line.split(':').nth(2).map(str::to_owned))
}

fn build_docker_image(
    dockerfile_dir: &Path,
    distribution: &str,
    pkg: &QemuPkg,
    acpi_tables_name: &str,
) -> Result<()> {
    info!("Building Docker image: {IMAGE_NAME}");
    match pkg.source {
        "ppa" => info!(
            "QEMU source: ppa:kobuk-team/tdx-release (Intel TDX-patched QEMU {}) on {distribution}",
            pkg.version
        ),
        "main" => info!(
            "QEMU source: {distribution} main archive ({})",
            if pkg.version.is_empty() {
                "latest"
            } else {
                pkg.version
            }
        ),
        "url" => info!(
            "QEMU source: tarball {} (sha256 {}) on {distribution}",
            pkg.url.expect("Missing QEMU url for source type `url`"),
            pkg.sha256
                .expect("Missing QEMU sha256 hash for source type `url`"),
        ),
        other => info!(
            "QEMU source: {other} ({})",
            if pkg.version.is_empty() {
                "?"
            } else {
                pkg.version
            }
        ),
    }

    let pinned_image = format!("{distribution}@{}", pkg.image_digest);
    let mut cmd = Command::new("docker");
    cmd.arg("build")
        .args(["--tag", IMAGE_NAME])
        .arg("--build-arg")
        .arg(format!("DISTRIBUTION={pinned_image}"))
        .arg("--build-arg")
        .arg(format!("QEMU_SOURCE={}", pkg.source))
        .arg("--build-arg")
        .arg(format!("QEMU_VERSION={}", pkg.version))
        .arg("--build-arg")
        .arg(format!("ACPI_TABLES_NAME={acpi_tables_name}"));
    if pkg.source == "url" {
        cmd.arg("--build-arg").arg(format!(
            "QEMU_URL={}",
            pkg.url.expect("Missing QEMU url for source type `url`")
        ));
        cmd.arg("--build-arg").arg(format!(
            "QEMU_SHA256={}",
            pkg.sha256
                .expect("Missing QEMU sha256 hash for source type `url`")
        ));
    }
    let status = cmd
        .arg("--file")
        .arg(dockerfile_dir.join("Dockerfile.qemu-acpi-dump"))
        .arg(dockerfile_dir)
        .status()
        .context("Failed to invoke `docker build`")?;
    if !status.success() {
        bail!("docker build failed (exit {status})");
    }
    Ok(())
}

/// The dump container's name for one run: the fixed prefix plus the basename of the run's private
/// output directory. That directory exists for the container's whole life and no two existing
/// directories share a path, so concurrent runs never collide on a fixed name.
fn dump_container_name(output_dir: &Path) -> Result<String> {
    let run = output_dir
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("ACPI output dir has no UTF-8 name: {}", output_dir.display()))?;
    Ok(format!("{CONTAINER_NAME}-{run}"))
}

fn run_docker_container(
    bios: &Path,
    output_dir: &Path,
    qemu_args: &[OsString],
    need_kvm: bool,
    need_vhost_vsock: bool,
) -> Result<()> {
    info!("Running QEMU container to generate ACPI tables...");
    // The Dockerfile skips `subdir('pc-bios')` in QEMU's meson build (the option
    // ROMs aren't needed to dump ACPI tables and adding them ~doubles image size).
    // As a result QEMU prints "rom: file kvmvapic.bin … No such file or directory"
    // (and similar for `linuxboot_dma.bin` if a PCI NIC is in play). Harmless —
    // the ACPI dump runs before any ROM would be loaded.
    warn!(
        "NOTE: harmless ROM-file errors (kvmvapic.bin, linuxboot_dma.bin, ...) from QEMU are expected; \
         pc-bios is skipped in the patched build."
    );

    let container_name = dump_container_name(output_dir)?;
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--name", container_name.as_str()]);

    // The `kvm` group also owns `/dev/vhost-vsock` on Linux, so add it whenever
    // either device matters.
    if let Some(gid) = kvm_group_id() {
        cmd.arg("--group-add").arg(gid);
    }
    if need_kvm {
        if !Path::new("/dev/kvm").exists() {
            bail!(
                "accelerator requires /dev/kvm but the host has none \
                 (use `accel: \"tcg\"` in the qemu block to skip KVM)"
            );
        }
        cmd.args(["--device", "/dev/kvm:/dev/kvm"]);
    }
    if need_vhost_vsock && Path::new("/dev/vhost-vsock").exists() {
        cmd.args(["--device", "/dev/vhost-vsock:/dev/vhost-vsock"]);
    }
    cmd.arg("-v")
        .arg(format!("{}:{OVMF_IN_CONTAINER}:ro", bios.display()));
    cmd.arg("-v")
        .arg(format!("{}:/output", output_dir.display()));
    cmd.arg(IMAGE_NAME);
    cmd.args(qemu_args);

    let status = cmd.status().context("Failed to invoke `docker run`")?;
    if !status.success() {
        bail!("QEMU execution failed (exit {status})");
    }
    Ok(())
}

/// Generates ACPI tables for direct boot by building and running a
/// patched-QEMU Docker container. The patched QEMU writes the
/// `etc/acpi/tables` blob it would have exposed via fw_cfg to
/// `boot_config.acpi_tables` and exits before TD entry.
pub fn generate_acpi_tables(
    metadata_path: &Path,
    distribution: &str,
    qemu_version: Option<&str>,
    qemu_source_url: Option<&str>,
    qemu_source_sha256: Option<&str>,
) -> Result<Vec<u8>> {
    let raw_metadata = fs_err::read_to_string(metadata_path)
        .context("Failed to read metadata.json for ACPI generation")?;
    let image_config: ImageConfig = serde_json::from_str(&raw_metadata)
        .context("Failed to parse metadata.json for ACPI generation")?;
    let mut boot_config = image_config
        .boot_config
        .clone()
        .context("boot_config is required to generate ACPI tables")?;
    let bios = resolve_metadata_path(metadata_path, &boot_config.bios)
        .canonicalize()
        .with_context(|| format!("BIOS file not found: {}", boot_config.bios))?;
    let acpi_tables_target = resolve_metadata_path(metadata_path, &boot_config.acpi_tables);
    let smbios_tables_target = boot_config
        .smbios_tables
        .as_ref()
        .filter(|path| !path.is_empty())
        .map(|path| resolve_metadata_path(metadata_path, path));

    boot_config.bios = bios.display().to_string();

    let acpi_tables_dir = acpi_tables_target.parent().with_context(|| {
        format!(
            "acpi_tables has no parent dir: {}",
            acpi_tables_target.display()
        )
    })?;
    fs_err::create_dir_all(acpi_tables_dir)?;
    generate_acpi_tables_with_qemu_args(
        &boot_config,
        distribution,
        qemu_version,
        qemu_source_url,
        qemu_source_sha256,
        Some(&acpi_tables_target),
        smbios_tables_target.as_ref(),
    )
}

/// Generates ACPI tables for direct boot by building and running a
/// patched-QEMU Docker container. The patched QEMU writes the
/// `etc/acpi/tables` blob it would have exposed via fw_cfg to
/// `boot_config.acpi_tables` and exits before TD entry.
pub fn generate_acpi_tables_with_qemu_args(
    boot_config: &BootConfig,
    distribution: &str,
    maybe_qemu_version: Option<&str>,
    maybe_qemu_source_url: Option<&str>,
    maybe_qemu_source_sha256: Option<&str>,
    maybe_acpi_tables_target: Option<&PathBuf>,
    maybe_smbios_tables_target: Option<&PathBuf>,
) -> Result<Vec<u8>> {
    let mut pkg = qemu_pkg_for(distribution, maybe_qemu_version)?;
    // When a source URL + SHA-256 are supplied, build QEMU from that tarball
    // (hash-verified) instead of the distribution's PPA/main package. Both must
    // be provided together.
    match (maybe_qemu_source_url, maybe_qemu_source_sha256) {
        (Some(url), Some(sha256)) => {
            pkg.source = "url";
            pkg.url = Some(url);
            pkg.sha256 = Some(sha256);
        }
        (Some(_), None) | (None, Some(_)) => {
            bail!("--qemu-source-url and --qemu-source-sha256 must be provided together")
        }
        (None, None) => {}
    }

    let bios = Path::new(&boot_config.bios);
    // Bind-mounted output dir must be writable by the container's non-root `qemu-user`.

    let output_dir = tempfile::tempdir().context("Failed to create ACPI output dir")?;
    fs_err::set_permissions(output_dir.path(), std::fs::Permissions::from_mode(0o777))?;
    const DEFAULT_ACPI_TABLES_NAME: &str = "acpi-tables.bin";
    let acpi_tables_name = DEFAULT_ACPI_TABLES_NAME;
    let generated_acpi_tables = output_dir.path().join(acpi_tables_name);
    let generated_smbios_tables = output_dir.path().join("smbios-tables.bin");

    info!(
        "ACPI gen config: cpus={}, memory={}, bios={}, target={}",
        boot_config.cpus,
        boot_config.memory,
        bios.display(),
        generated_acpi_tables.display(),
    );
    if let Some(q) = &boot_config.qemu {
        info!(
            "Using boot_config.qemu shape: machine='{}' cpu='{}' accel='{}'",
            q.machine, q.cpu, q.accel
        );
    }

    // Stage the Dockerfile into a temp build context so `docker build` finds it.
    let build_ctx = tempfile::tempdir().context("Failed to create docker build context")?;
    fs_err::write(
        build_ctx.path().join("Dockerfile.qemu-acpi-dump"),
        DOCKERFILE_QEMU_ACPI_DUMP,
    )?;
    build_docker_image(build_ctx.path(), distribution, &pkg, acpi_tables_name)?;

    let qemu_args = build_qemu_args(
        boot_config.qemu.as_ref(),
        boot_config.cpus,
        &boot_config.memory,
    )?;
    let need_kvm = boot_config
        .qemu
        .as_ref()
        .map(|q| q.accel == "kvm")
        .unwrap_or(true);
    let need_vhost_vsock = boot_config.qemu.is_some();
    prepare_output_drives(boot_config.qemu.as_ref(), output_dir.path())?;

    run_docker_container(
        &bios,
        output_dir.path(),
        &qemu_args,
        need_kvm,
        need_vhost_vsock,
    )?;

    // Move the generated_acpi_tables ACPI tables into place; `fs::copy` would inherit the
    // container's restrictive 0600 from the source, so widen to 0644 after.
    if !generated_acpi_tables.exists() {
        bail!(
            "ACPI tables not found in container output: {}",
            generated_acpi_tables.display()
        );
    }
    if let Some(acpi_tables_target) = maybe_acpi_tables_target {
        fs_err::copy(&generated_acpi_tables, &acpi_tables_target)?;
        fs_err::set_permissions(&acpi_tables_target, std::fs::Permissions::from_mode(0o644))?;
        info!("ACPI tables written to: {}", acpi_tables_target.display());
    } else {
        debug!("ACPI tables were not copied from the temporary file target");
    }
    if let Some(smbios_tables_target) = maybe_smbios_tables_target {
        if !generated_smbios_tables.exists() {
            bail!(
                "SMBIOS tables not found in container output: {}",
                generated_smbios_tables.display()
            );
        }
        if let Some(parent) = smbios_tables_target.parent() {
            fs_err::create_dir_all(parent)?;
        }
        fs_err::copy(&generated_smbios_tables, smbios_tables_target)?;
        fs_err::set_permissions(smbios_tables_target, std::fs::Permissions::from_mode(0o644))?;
        info!(
            "SMBIOS tables written to: {}",
            smbios_tables_target.display()
        );
    }

    let tables = fs_err::read(&generated_acpi_tables)?;

    Ok(tables)
}

/// Whether `image` names one image by digest: `<name>@sha256:<64 lowercase hex>`.
fn is_declared_image(image: &str) -> bool {
    match image.rsplit_once("@sha256:") {
        Some((name, hex)) => {
            !name.is_empty()
                && hex.len() == 64
                && hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        }
        None => false,
    }
}

/// The SEV-SNP platform-table dump of one measurement shape.
///
/// Runs one declared SEV-SNP dump image (`Dockerfile.qemu-acpi-dump-snp`, built once from the
/// local source of the SEV-SNP host's QEMU package) by digest with `--pull=never` and
/// `--network=none`; this mode never builds an image and never pulls one. The image's
/// `org.chutes.qemu-package-version` label must equal `qemu_package_version`, the QEMU package
/// version the SEV-SNP host launches with, which the caller always passes explicitly (there is no
/// distribution default here). The measurement shape (`boot_config.qemu`) runs under TCG with
/// the checking firmware as `-bios`; the patched QEMU writes the three fw_cfg blobs it serves at
/// the firmware's first ACPI read and exits.
pub fn dump_snp_platform_tables(
    boot_config: &BootConfig,
    image: &str,
    qemu_package_version: &str,
    output_dir: &Path,
) -> Result<SnpPlatformDump> {
    if !is_declared_image(image) {
        bail!(
            "the SEV-SNP dump image must be one declared digest (<name>@sha256:<64 hex>), \
             got {image:?}"
        );
    }
    if qemu_package_version.trim().is_empty() {
        bail!("the SEV-SNP dump needs the launch contract's QEMU package version");
    }
    let qemu = boot_config
        .qemu
        .as_ref()
        .context("the SEV-SNP dump needs boot_config.qemu (the measurement shape)")?;
    if qemu.accel != "tcg" {
        bail!(
            "the SEV-SNP dump runs the measurement shape under TCG, got accel {:?}",
            qemu.accel
        );
    }
    let label_format = format!("{{{{ index .Config.Labels \"{SNP_DUMP_QEMU_LABEL}\" }}}}");
    let inspected = Command::new("docker")
        .args(["image", "inspect", "--format"])
        .arg(&label_format)
        .arg(image)
        .output()
        .context("Failed to invoke `docker image inspect`")?;
    if !inspected.status.success() {
        bail!(
            "the declared SEV-SNP dump image {image} is not present (it is never built or \
             pulled here)"
        );
    }
    let labelled = String::from_utf8_lossy(&inspected.stdout).trim().to_string();
    if labelled != qemu_package_version {
        bail!(
            "the SEV-SNP dump image carries QEMU {labelled:?}, the launch contract names \
             {qemu_package_version:?}"
        );
    }
    let bios = Path::new(&boot_config.bios)
        .canonicalize()
        .with_context(|| format!("BIOS file not found: {}", boot_config.bios))?;
    fs_err::create_dir_all(output_dir)?;
    // The container's non-root qemu-user writes the blobs.
    fs_err::set_permissions(output_dir, std::fs::Permissions::from_mode(0o777))?;
    prepare_output_drives(Some(qemu), output_dir)?;
    let qemu_args = build_qemu_args(Some(qemu), boot_config.cpus, &boot_config.memory)?;

    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--pull=never", "--network=none"]);
    cmd.arg("-v")
        .arg(format!("{}:{OVMF_IN_CONTAINER}:ro", bios.display()));
    cmd.arg("-v")
        .arg(format!("{}:/output", output_dir.display()));
    cmd.arg(image);
    cmd.args(&qemu_args);
    let status = cmd.status().context("Failed to invoke `docker run`")?;
    if !status.success() {
        bail!("the SEV-SNP platform-table dump failed (exit {status})");
    }
    let read = |name: &str| -> Result<Vec<u8>> {
        let path = output_dir.join(name);
        fs_err::read(&path)
            .with_context(|| format!("the SEV-SNP dump wrote no {}", path.display()))
    };
    Ok(SnpPlatformDump {
        tables: read(SNP_DUMP_TABLES)?,
        rsdp: read(SNP_DUMP_RSDP)?,
        loader: read(SNP_DUMP_LOADER)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each run's dump container has its own valid Docker name, the fixed prefix plus its output
    /// directory's basename, so two concurrent runs never share one.
    #[test]
    fn dump_container_names_are_per_run_and_valid_docker_names() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let a = dump_container_name(first.path()).unwrap();
        let b = dump_container_name(second.path()).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, CONTAINER_NAME);
        for (name, dir) in [(&a, &first), (&b, &second)] {
            let run = dir.path().file_name().unwrap().to_str().unwrap();
            assert_eq!(*name, format!("acpi-tables-generator-{run}"));
            // Docker's container-name grammar: [a-zA-Z0-9][a-zA-Z0-9_.-]+
            let mut chars = name.chars();
            assert!(chars.next().unwrap().is_ascii_alphanumeric(), "{name}");
            assert!(
                chars.all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)),
                "{name}"
            );
        }
        assert!(dump_container_name(Path::new("/")).is_err());
    }

    /// Builds an 8-byte ACPI table header with the given signature and length.
    /// Body bytes (if any) are caller-appended.
    fn header(sig: &[u8; 4], len: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(sig);
        h.extend_from_slice(&len.to_le_bytes());
        h
    }

    /// Concatenates a list of (sig, padded_body_len) into a blob shaped like
    /// `etc/acpi/tables`. Each entry becomes `<8-byte header><(len-8) zeros>`.
    fn build_blob(tables: &[(&[u8; 4], u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(sig, len) in tables {
            out.extend(header(sig, len));
            out.resize(out.len() + (len as usize - 8), 0);
        }
        out
    }

    #[test]
    fn find_acpi_table_returns_offsets_and_csum_for_each_table() {
        // Minimal Canonical-defaults table set, no HPET; 4-entry RSDT (len=36+16).
        let blob = build_blob(&[
            (b"FACS", 64),
            (b"DSDT", 200),
            (b"FACP", 244),
            (b"APIC", 144),
            (b"MCFG", 60),
            (b"WAET", 40),
            (b"RSDT", 52),
        ]);

        // Spot-check three tables. csum is the offset of the table's
        // 9th byte (header layout: 4-byte sig, 4-byte length, 1-byte revision,
        // 1-byte checksum -> checksum lives at offset+9).
        let (off, csum, len) = find_acpi_table(&blob, "DSDT").unwrap();
        assert_eq!(off, 64);
        assert_eq!(csum, 73);
        assert_eq!(len, 200);

        let (off, _, len) = find_acpi_table(&blob, "FACP").unwrap();
        assert_eq!(off, 264);
        assert_eq!(len, 244);

        let (off, _, _) = find_acpi_table(&blob, "RSDT").unwrap();
        assert_eq!(off, 64 + 200 + 244 + 144 + 60 + 40); // = 752
    }

    #[test]
    fn list_acpi_tables_walks_blob_and_stops_at_padding() {
        let blob = build_blob(&[(b"FACS", 64), (b"DSDT", 100), (b"FACP", 244), (b"RSDT", 40)]);
        let list = list_acpi_tables(&blob).unwrap();
        let sigs: Vec<&[u8]> = list.iter().map(|(s, ..)| s.as_slice()).collect();
        assert_eq!(sigs, [b"FACS".as_slice(), b"DSDT", b"FACP", b"RSDT"]);

        // Padding region (zeros) after the last table must terminate the walk,
        // not be treated as a malformed table.
        let mut blob_padded = blob.clone();
        blob_padded.resize(blob.len() + 4096, 0);
        let list2 = list_acpi_tables(&blob_padded).unwrap();
        assert_eq!(list2.len(), 4);
    }

    /// Decodes one 128-byte QEMU loader command, returning a tuple shaped like
    /// (cmd_type, file_or_ptr_file, optional_pointee_file, payload_u32s).
    /// Used to assert the byte layout of `derive_table_loader` without re-
    /// implementing the encoder.
    fn decode_loader_cmd(cmd: &[u8]) -> (u32, String, Option<String>, Vec<u32>) {
        assert_eq!(cmd.len(), 128);
        let kind = u32::from_le_bytes(cmd[0..4].try_into().unwrap());
        let read_str = |off: usize| -> String {
            let s = &cmd[off..off + FIXED_STRING_LEN];
            let end = s.iter().position(|b| *b == 0).unwrap_or(s.len());
            std::str::from_utf8(&s[..end]).unwrap().to_string()
        };
        match kind {
            // Allocate: file + alignment + zone
            1 => {
                let file = read_str(4);
                let align = u32::from_le_bytes(cmd[60..64].try_into().unwrap());
                let zone = cmd[64] as u32;
                (1, file, None, vec![align, zone])
            }
            // AddPtr: pointer_file + pointee_file + offset + size
            2 => {
                let ptr_file = read_str(4);
                let ptee_file = read_str(60);
                let ptr_off = u32::from_le_bytes(cmd[116..120].try_into().unwrap());
                let ptr_size = cmd[120] as u32;
                (2, ptr_file, Some(ptee_file), vec![ptr_off, ptr_size])
            }
            // AddChecksum: file + result_offset + start + length
            3 => {
                let file = read_str(4);
                let result = u32::from_le_bytes(cmd[60..64].try_into().unwrap());
                let start = u32::from_le_bytes(cmd[64..68].try_into().unwrap());
                let length = u32::from_le_bytes(cmd[68..72].try_into().unwrap());
                (3, file, None, vec![result, start, length])
            }
            other => panic!("unknown loader cmd type {other}"),
        }
    }

    fn split_cmds(loader: &[u8]) -> Vec<&[u8]> {
        assert!(loader.len() >= LDR_LENGTH);
        loader
            .chunks_exact(128)
            .take_while(|chunk| u32::from_le_bytes(chunk[0..4].try_into().unwrap()) != 0)
            .collect()
    }

    #[test]
    fn derive_table_loader_emits_canonical_no_hpet_layout() {
        let blob = build_blob(&[
            (b"FACS", 64),
            (b"DSDT", 100),
            (b"FACP", 244),
            (b"APIC", 144),
            (b"MCFG", 60),
            (b"WAET", 40),
            (b"RSDT", 52), // header (36) + 4 × 4-byte entries
        ]);
        let loader = derive_table_loader(&blob).unwrap();
        let cmds: Vec<_> = split_cmds(&loader)
            .into_iter()
            .map(decode_loader_cmd)
            .collect();

        // Expected command sequence per the docstring on derive_table_loader.
        // Allocate rsdp + Allocate tables + AddChecksum DSDT + 3×AddPtr FACP + AddChecksum FACP
        // + AddChecksum APIC + AddChecksum MCFG + AddChecksum WAET + 4×AddPtr RSDT
        // + AddChecksum RSDT + AddPtr RSDP + AddChecksum RSDP = 17 commands.
        assert_eq!(cmds.len(), 17);
        assert_eq!(cmds[0].0, 1); // Allocate
        assert_eq!(cmds[0].1, "etc/acpi/rsdp");
        assert_eq!(cmds[1].0, 1);
        assert_eq!(cmds[1].1, "etc/acpi/tables");
        assert_eq!(cmds[2].0, 3); // AddChecksum DSDT
        assert_eq!(cmds[2].3, vec![64 + 9, 64, 100]);

        // 3 AddPtr at facp+36, facp+40, facp+140 (offsets relative to the
        // FACP base in the concatenated blob)
        let facp_off = 64 + 100;
        for (i, &expected_off) in [36u32, 40, 140].iter().enumerate() {
            let cmd = &cmds[3 + i];
            assert_eq!(cmd.0, 2);
            assert_eq!(cmd.3[0], facp_off + expected_off);
        }
        // 4 RSDT pointers (no HPET) at rsdt+36/+40/+44/+48
        let rsdt_off = 64 + 100 + 244 + 144 + 60 + 40;
        for (i, expected_off) in (36u32..36 + 4 * 4).step_by(4).enumerate() {
            let cmd = &cmds[10 + i];
            assert_eq!(cmd.0, 2);
            assert_eq!(cmd.3[0], rsdt_off + expected_off);
        }
        // RSDT checksum, then the final RSDP wiring + checksum.
        assert_eq!(cmds[14].0, 3); // AddChecksum RSDT
        assert_eq!(cmds[14].1, "etc/acpi/tables");
        assert_eq!(cmds[15].0, 2); // AddPtr rsdp+16 -> tables
        assert_eq!(cmds[15].1, "etc/acpi/rsdp");
        assert_eq!(cmds[15].3, vec![16, 4]);
        assert_eq!(cmds[16].0, 3); // AddChecksum rsdp
        assert_eq!(cmds[16].1, "etc/acpi/rsdp");
        assert_eq!(cmds[16].3, vec![8, 0, 20]);

        // Buffer must be padded to LDR_LENGTH (4096).
        assert_eq!(loader.len(), LDR_LENGTH);
    }

    #[test]
    fn derive_table_loader_with_hpet_adds_an_extra_addchecksum_and_rsdt_ptr() {
        // Same shape with HPET in the mix. RSDT now has 5 entries (FACP, APIC,
        // HPET, MCFG, WAET) so length = 36 + 5*4 = 56. Regression case for the
        // pre-rewrite code that hardcoded 4 RSDT entries.
        let blob = build_blob(&[
            (b"FACS", 64),
            (b"DSDT", 100),
            (b"FACP", 244),
            (b"APIC", 144),
            (b"HPET", 56),
            (b"MCFG", 60),
            (b"WAET", 40),
            (b"RSDT", 56),
        ]);
        let loader = derive_table_loader(&blob).unwrap();
        let cmds: Vec<_> = split_cmds(&loader)
            .into_iter()
            .map(decode_loader_cmd)
            .collect();

        // 17 + 2 commands now: one extra AddChecksum HPET + one extra AddPtr RSDT entry.
        assert_eq!(cmds.len(), 19);
        // Count AddChecksums in `etc/acpi/tables` (i.e. tables blob, not rsdp).
        let checksum_tables: Vec<_> = cmds
            .iter()
            .filter(|c| c.0 == 3 && c.1 == "etc/acpi/tables")
            .collect();
        // DSDT + FACP + APIC + HPET + MCFG + WAET + RSDT = 7
        assert_eq!(checksum_tables.len(), 7);
        // Count RSDT-entry AddPtrs (5 vs the 4 the old code emitted).
        let rsdt_off = 64 + 100 + 244 + 144 + 56 + 60 + 40;
        let rsdt_ptrs: Vec<_> = cmds
            .iter()
            .filter(|c| {
                c.0 == 2
                    && c.1 == "etc/acpi/tables"
                    && c.3[0] >= rsdt_off + 36
                    && c.3[0] < rsdt_off + 36 + 5 * 4
            })
            .collect();
        assert_eq!(rsdt_ptrs.len(), 5);
    }

    #[test]
    fn snp_dump_takes_only_a_declared_image_digest() {
        let digest = "a".repeat(64);
        assert!(is_declared_image(&format!("chutes/qemu-acpi-dump-snp@sha256:{digest}")));
        assert!(!is_declared_image("chutes/qemu-acpi-dump-snp:latest"));
        assert!(!is_declared_image(&format!("@sha256:{digest}")));
        assert!(!is_declared_image(&format!("dump@sha256:{}", "A".repeat(64))));
        assert!(!is_declared_image(&format!("dump@sha256:{}", "a".repeat(63))));
    }

    #[test]
    fn qemu_pkg_for_known_distros_returns_pinned_defaults() {
        let p = qemu_pkg_for("ubuntu:25.04", None).unwrap();
        assert_eq!(p.source, "ppa");
        assert_eq!(p.version, "1:9.2.1+ds-1ubuntu4+tdx2.0~ppa2");
        assert!(p.image_digest.starts_with("sha256:"));
        assert_eq!(p.image_digest.len(), "sha256:".len() + 64);

        let p = qemu_pkg_for("ubuntu:25.10", None).unwrap();
        assert_eq!(p.source, "main");
        assert_eq!(p.version, "1:10.1.0+ds-5ubuntu2.7");
        assert!(p.image_digest.starts_with("sha256:"));

        let p = qemu_pkg_for("ubuntu:26.04", None).unwrap();
        assert_eq!(p.source, "main");
        assert_eq!(p.version, "1:10.2.1+ds-1ubuntu4");
        assert!(p.image_digest.starts_with("sha256:"));
        assert_eq!(p.image_digest.len(), "sha256:".len() + 64);
    }

    #[test]
    fn qemu_pkg_for_supports_24_04_via_ppa() {
        let p = qemu_pkg_for("ubuntu:24.04", None).unwrap();
        assert_eq!(p.source, "ppa");
        // 24.04 base image is pinned by digest for reproducibility.
        assert!(p.image_digest.starts_with("sha256:"));
        assert_eq!(p.image_digest.len(), "sha256:".len() + 64);
        assert!(p.url.is_none() && p.sha256.is_none());
    }

    #[test]
    fn qemu_pkg_for_honors_version_override() {
        let p = qemu_pkg_for("ubuntu:26.04", Some("1:10.3.0-1ubuntu1")).unwrap();
        assert_eq!(p.source, "main");
        assert_eq!(p.version, "1:10.3.0-1ubuntu1");

        // Even an empty override (caller asked for "latest") wins over the pin.
        let p = qemu_pkg_for("ubuntu:26.04", Some("")).unwrap();
        assert_eq!(p.version, "");
    }

    #[test]
    fn qemu_pkg_for_rejects_unknown_distro() {
        assert!(qemu_pkg_for("debian:12", None).is_err());
        assert!(qemu_pkg_for("", None).is_err());
    }

    #[test]
    fn build_qemu_args_canonical_fallback_matches_dstack_reference() {
        // Canonical direct-boot args from the upstream `dstack`-derived flow.
        // Pinned because the Canonical-defaults scenario depends on this exact order.
        let args = build_qemu_args(None, 4, "2048M").unwrap();
        let expected: Vec<&str> = vec![
            "-accel",
            "kvm",
            "-m",
            "2048M",
            "-smp",
            "4",
            "-cpu",
            "host",
            "-machine",
            "q35,kernel-irqchip=split,hpet=off,smm=off,pic=off",
            "-bios",
            OVMF_IN_CONTAINER,
            "-nographic",
            "-nodefaults",
            "-serial",
            "stdio",
        ];
        let got: Vec<&str> = args.iter().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn build_qemu_args_qemu_block_passes_fields_verbatim_and_in_documented_order() {
        let shape = QemuShape {
            machine: "q35,kernel_irqchip=split,smm=off,pic=off".into(),
            memory: None,
            smp: Some("8,sockets=1,cores=8,threads=1".into()),
            cpu: "Skylake-Server,phys-bits=46".into(),
            accel: "tcg".into(),
            globals: vec!["q35-pcihost.pci-hole64-size=4096G".into()],
            objects: vec!["memory-backend-ram,id=mem0,size=16384M".into()],
            numa: vec![],
            drives: vec!["file=/dev/null,if=none,id=disk0,format=raw".into()],
            netdevs: vec!["hubport,id=net0,hubid=0".into()],
            devices: vec![
                "e1000,netdev=net0,bus=pcie.0,addr=0x2,romfile=".into(),
                "virtio-rng-pci".into(),
            ],
            acpi_devices: None,
            fw_cfg: vec!["name=opt/ovmf/X-PciMmio64Mb,string=262144".into()],
            smbios: vec!["type=4,processor-id=1".into()],
            serial: None,
        };
        let args = build_qemu_args(Some(&shape), 8, "16384M")
            .unwrap()
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect::<Vec<_>>();

        // Core seven flags first (in a documented order), then -machine, then
        // user-supplied lists in -global / -object / -netdev / -device / -fw_cfg order.
        assert_eq!(
            args,
            vec![
                "-accel",
                "tcg",
                "-m",
                "16384M",
                "-smp",
                "8,sockets=1,cores=8,threads=1",
                "-cpu",
                "Skylake-Server,phys-bits=46",
                "-no-reboot",
                "-nodefaults",
                "-vga",
                "none",
                "-nographic",
                "-bios",
                OVMF_IN_CONTAINER,
                "-machine",
                "q35,kernel_irqchip=split,smm=off,pic=off",
                "-global",
                "q35-pcihost.pci-hole64-size=4096G",
                "-object",
                "memory-backend-ram,id=mem0,size=16384M",
                "-drive",
                "file=/dev/null,if=none,id=disk0,format=raw",
                "-netdev",
                "hubport,id=net0,hubid=0",
                "-device",
                "e1000,netdev=net0,bus=pcie.0,addr=0x2,romfile=",
                "-device",
                "virtio-rng-pci",
                "-fw_cfg",
                "name=opt/ovmf/X-PciMmio64Mb,string=262144",
                "-smbios",
                "type=4,processor-id=1",
            ]
        );
    }

    #[test]
    fn build_qemu_args_uses_only_aligned_unbacked_vfio_acpi_surrogates() {
        let live_root = "pcie-root-port,port=16,chassis=1,id=rp1,bus=pcie.0,addr=0x8";
        let live_vfio = "vfio-pci,host=0000:01:00.0,bus=rp1,addr=0x0,iommufd=iommufd0";
        let surrogate =
            "pci-testdev,membar=131072M,membar-backed=off,x-rtxpro6000se=on,bus=rp1,addr=0x0";
        let shape = QemuShape {
            machine: "pc-q35-10.1".into(),
            memory: None,
            smp: None,
            cpu: "max,phys-bits=46".into(),
            accel: "tcg".into(),
            globals: vec![],
            objects: vec!["iommufd,id=iommufd0".into()],
            numa: vec![],
            drives: vec![],
            netdevs: vec![],
            devices: vec![live_root.into(), live_vfio.into()],
            acpi_devices: Some(vec![live_root.into(), surrogate.into()]),
            fw_cfg: vec![],
            smbios: vec![],
            serial: None,
        };
        let args = build_qemu_args(Some(&shape), 14, "114688M")
            .unwrap()
            .into_iter()
            .map(|value| value.into_string().unwrap())
            .collect::<Vec<_>>();
        assert!(args.contains(&surrogate.to_string()));
        assert!(!args.contains(&live_vfio.to_string()));

        let mut bad = shape.clone();
        bad.acpi_devices = Some(vec![
            live_root.into(),
            "pci-testdev,membar=131072M,membar-backed=off,x-rtxpro6000se=on,bus=rp2,addr=0x0"
                .into(),
        ]);
        assert!(build_qemu_args(Some(&bad), 14, "114688M").is_err());
    }

    #[test]
    fn acpi_surrogates_are_exactly_the_gpu_and_nvswitch_forms() {
        let live_root = "pcie-root-port,port=24,chassis=9,id=rp9,bus=pxb_nvsw,addr=0x1";
        let live_vfio = "vfio-pci,host=0000:09:00.0,bus=rp9,addr=0x0,iommufd=iommufd0";
        let shape_with = |surrogate: &str| QemuShape {
            machine: "pc-q35-10.2".into(),
            memory: None,
            smp: None,
            cpu: "max,phys-bits=46".into(),
            accel: "tcg".into(),
            globals: vec![],
            objects: vec!["iommufd,id=iommufd0".into()],
            numa: vec![],
            drives: vec![],
            netdevs: vec![],
            devices: vec![live_root.into(), live_vfio.into()],
            acpi_devices: Some(vec![live_root.into(), surrogate.into()]),
            fw_cfg: vec![],
            smbios: vec![],
            serial: None,
        };
        for accepted in [
            "pci-testdev,membar=262144M,membar-backed=off,x-rtxpro6000se=on,bus=rp9,addr=0x0",
            "pci-testdev,membar=262144M,membar-backed=off,x-h200=on,bus=rp9,addr=0x0",
            "pci-testdev,membar-backed=off,x-nvswitch-ls10=on,bus=rp9,addr=0x0",
        ] {
            assert!(acpi_devices(&shape_with(accepted)).is_ok(), "{accepted}");
        }
        for refused in [
            // no mode, two GPU modes, an unknown mode, a mode switched off
            "pci-testdev,membar=262144M,membar-backed=off,bus=rp9,addr=0x0",
            "pci-testdev,membar=262144M,x-h200=on,x-rtxpro6000se=on,bus=rp9,addr=0x0",
            "pci-testdev,membar=262144M,membar-backed=off,x-b200=on,bus=rp9,addr=0x0",
            "pci-testdev,membar=262144M,membar-backed=off,x-h200=off,bus=rp9,addr=0x0",
            // a switch with a membar or a GPU mode; a GPU without its membar or a zero one
            "pci-testdev,membar=32M,membar-backed=off,x-nvswitch-ls10=on,bus=rp9,addr=0x0",
            "pci-testdev,membar-backed=off,x-nvswitch-ls10=on,x-h200=on,bus=rp9,addr=0x0",
            "pci-testdev,membar-backed=off,x-h200=on,bus=rp9,addr=0x0",
            "pci-testdev,membar=0M,membar-backed=off,x-h200=on,bus=rp9,addr=0x0",
            // backed, a repeated property, moved, or carrying host authority
            "pci-testdev,membar-backed=on,x-nvswitch-ls10=on,bus=rp9,addr=0x0",
            "pci-testdev,membar-backed=off,x-nvswitch-ls10=on,bus=rp9,bus=rp9",
            "pci-testdev,membar-backed=off,x-nvswitch-ls10=on,bus=rp10,addr=0x0",
            "pci-testdev,membar-backed=off,x-nvswitch-ls10=on,host=0000:09:00.0,addr=0x0",
            "vfio-pci,membar-backed=off,x-nvswitch-ls10=on,bus=rp9,addr=0x0",
        ] {
            assert!(acpi_devices(&shape_with(refused)).is_err(), "{refused}");
        }
    }
}
