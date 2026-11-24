/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025 Intel Corporation
 * Modified by Chutes Global Corp, 2026; the changes are listed in CHUTES-UPSTREAM.md.
 * SPDX-License-Identifier: Apache-2.0
 */
use anyhow::{anyhow, bail, Context, Result};
use bon::Builder;
use serde::{Deserialize, Deserializer, Serialize};
use serde_human_bytes as hex_bytes;
use std::path::Path;

pub use acpi::{dump_snp_platform_tables, SnpPlatformDump};
pub use machine::Machine;

use util::{measure_log, measure_sha384};

mod acpi;
mod image;
mod kernel;
mod machine;
mod num;
mod smbios;
mod tdvf;
mod util;

/// Compute MRTD from the exact TDVF metadata/page-add transcript without TDX hardware.
pub fn measure_mrtd(firmware: impl AsRef<std::path::Path>) -> Result<Vec<u8>> {
    let data = fs_err::read(firmware)?;
    tdvf::Tdvf::parse(&data)?.mrtd()
}

/// Contains all the measurement values for TDX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxMeasurements {
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mrtd: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr0: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr1: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr2: Vec<u8>,
}

/// The `firmware_profile` whose RTMR0 event sequence includes the fw_cfg items, the EFI variables
/// and the SMBIOS tables edk2-stable202605 measures.
pub const FIRMWARE_EDK2_STABLE202605: &str = "edk2-stable202605";
/// The `firmware_profile` whose direct-boot RTMR0 event sequence ends in the BootOrder and Boot0000
/// variables, as Ubuntu's OVMF 2025.02 (edk2-stable202502) measures it.
pub const FIRMWARE_EDK2_STABLE202502: &str = "edk2-stable202502";

/// The input form of a metadata document. `ImageConfig::load` decides it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MetadataForm {
    /// `metadata_version: 1`: every field is known, direct boot names its `firmware_profile`,
    /// `qemu.serial` is a list and every `pci-bar-stub` device is checked before QEMU runs.
    V1,
    /// No `metadata_version`: a direct boot without `firmware_profile` `edk2-stable202605` measures
    /// the BootOrder/Boot0000 sequence.
    #[default]
    Legacy,
    /// No `metadata_version`, written for the chutesai/tdx-measure fork: `qemu` carries
    /// `processor_id` or a `serial` list, which only that fork reads. As in that fork, a direct boot
    /// measures the edk2-stable202605 sequence whether or not `firmware_profile` says so, with the
    /// fork's two rules: `etc/extra-pci-roots` counts the devices whose text contains `pxb-pcie`,
    /// and the SMBIOS tables go to `smbios-tables` beside `acpi_tables` unless `smbios_tables`
    /// names a path. Its indirect boot measures the boot variables, as every legacy document's.
    LegacyFork,
}

/// `qemu.serial`: one `-serial` value (the legacy form's string) or a list of them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SerialPorts {
    One(String),
    List(Vec<String>),
}

/// Common boot configuration (platform-specific)
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[serde(deny_unknown_fields)]
pub struct BootConfig {
    pub cpus: u32,
    pub memory: String,
    pub bios: String,
    pub acpi_tables: String,
    #[serde(default)]
    pub smbios_tables: Option<String>,
    #[serde(default)]
    pub firmware_profile: Option<String>,
    pub rsdp: Option<String>,
    pub table_loader: Option<String>,
    pub boot_order: Option<String>,
    pub path_boot_xxxx: Option<String>,
    pub qemu: Option<QemuShape>,
}

/// QEMU command-line pass-through consumed by the ACPI dumper.
/// Device-ordering matters. See README for the field-by-field schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QemuShape {
    pub machine: String,
    #[serde(default)]
    pub memory: Option<String>,
    #[serde(default)]
    pub smp: Option<String>,
    #[serde(default = "default_cpu")]
    pub cpu: String,
    #[serde(default = "default_accel")]
    pub accel: String,
    #[serde(default)]
    pub globals: Vec<String>,
    #[serde(default)]
    pub objects: Vec<String>,
    #[serde(default)]
    pub numa: Vec<String>,
    #[serde(default)]
    pub drives: Vec<String>,
    #[serde(default)]
    pub netdevs: Vec<String>,
    #[serde(default)]
    pub devices: Vec<String>,
    /// Optional hardware-free device list used only by the ACPI dumper. It must preserve every
    /// non-VFIO entry and replace each live VFIO endpoint with a stand-in at the same bus and
    /// address: a `pci-bar-stub` or one of the three named presets.
    #[serde(default)]
    pub acpi_devices: Option<Vec<String>>,
    #[serde(default)]
    pub fw_cfg: Vec<String>,
    #[serde(default)]
    pub smbios: Vec<String>,
    /// `-serial` values: a list, or (legacy form) one string. Absent: no `-serial` flag.
    #[serde(default)]
    pub serial: Option<SerialPorts>,
    /// The SMBIOS Type-4 Processor ID, 8 bytes as 16 hex digits, written into every Type-4
    /// structure of the dumped SMBIOS tables before they are measured. `Some(None)` is a present
    /// `null`, which only the fork form accepts (no patch).
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub processor_id: Option<Option<String>>,
}

impl QemuShape {
    /// The `-serial` values, in order.
    pub fn serial_ports(&self) -> Vec<&str> {
        match &self.serial {
            None => Vec::new(),
            Some(SerialPorts::One(port)) => vec![port.as_str()],
            Some(SerialPorts::List(ports)) => ports.iter().map(String::as_str).collect(),
        }
    }

    /// The Type-4 Processor ID to write, decoded, when one is given.
    pub fn processor_id_bytes(&self) -> Result<Option<[u8; 8]>> {
        match &self.processor_id {
            Some(Some(hex_id)) => {
                let bytes = hex::decode(hex_id).context("qemu.processor_id must be hex")?;
                let id: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("qemu.processor_id must decode to 8 bytes"))?;
                Ok(Some(id))
            }
            _ => Ok(None),
        }
    }
}

/// A present field, `null` included, deserializes to `Some`; an absent one stays `None`.
fn deserialize_present<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

fn default_cpu() -> String {
    "host".to_string()
}
fn default_accel() -> String {
    "kvm".to_string()
}

/// Direct boot specific information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectBoot {
    pub kernel: String,
    pub initrd: String,
    pub cmdline: String,
}

/// Indirect boot specific information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndirectBoot {
    pub qcow2: String,
    pub cmdline: String,
    pub mok_list: String,
    pub mok_list_trusted: String,
    pub mok_list_x: String,
    pub sbat_level: String,
}

/// Complete image configuration
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[serde(deny_unknown_fields)]
pub struct ImageConfig {
    /// `1` for the versioned form; absent for the legacy forms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_config: Option<BootConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct: Option<DirectBoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indirect: Option<IndirectBoot>,
    /// The form `ImageConfig::load` read; a document deserialized directly is `Legacy`.
    #[serde(skip)]
    #[builder(default)]
    pub form: MetadataForm,
}

impl ImageConfig {
    /// Reads a metadata document and decides its form (`MetadataForm`). A document with
    /// `metadata_version` must be version 1 and meet that form's rules; a document without one is
    /// the legacy form, or the fork form when its `qemu` carries `processor_id` or a `serial` list.
    /// Every field must be one this tool knows, in every form.
    pub fn from_json_str(text: &str) -> Result<Self> {
        let mut config: ImageConfig =
            serde_json::from_str(text).context("Failed to parse image metadata")?;
        config.form = match config.metadata_version {
            Some(1) => MetadataForm::V1,
            Some(other) => bail!("metadata_version {other} is not one this tool reads (1)"),
            None if config.has_fork_fields() => MetadataForm::LegacyFork,
            None => MetadataForm::Legacy,
        };
        config.check_form()?;
        Ok(config)
    }

    /// `from_json_str` on the file at `path`, with a relative `bios` resolved against the directory
    /// of `path`. A fork-form document's SMBIOS tables go where that fork put them,
    /// `smbios-tables` in the directory of `acpi_tables`, unless `smbios_tables` names a path.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs_err::read_to_string(path).context("Failed to read image metadata")?;
        let mut config = Self::from_json_str(&text)?;
        let base = path.parent().unwrap_or(Path::new("."));
        let fork_form = config.form == MetadataForm::LegacyFork;
        if let Some(boot_config) = config.boot_config.as_mut() {
            // The firmware the dump boots is the one MRTD measures: both resolve a relative
            // `bios` against the metadata file's directory.
            boot_config.bios = base.join(&boot_config.bios).display().to_string();
            if fork_form && boot_config.smbios_tables.is_none() {
                let acpi_tables = base.join(&boot_config.acpi_tables);
                let dir = acpi_tables.parent().unwrap_or(Path::new("."));
                boot_config.smbios_tables = Some(dir.join("smbios-tables").display().to_string());
            }
        }
        Ok(config)
    }

    /// Whether the document uses a field only the chutesai/tdx-measure fork reads.
    fn has_fork_fields(&self) -> bool {
        self.boot_config
            .as_ref()
            .and_then(|config| config.qemu.as_ref())
            .is_some_and(|qemu| {
                qemu.processor_id.is_some() || matches!(qemu.serial, Some(SerialPorts::List(_)))
            })
    }

    /// The rules of the document's form.
    fn check_form(&self) -> Result<()> {
        let boot_config = self.boot_config.as_ref();
        let qemu = boot_config.and_then(|config| config.qemu.as_ref());
        if let Some(qemu) = qemu {
            qemu.processor_id_bytes()?;
        }
        match self.form {
            MetadataForm::Legacy => Ok(()),
            MetadataForm::LegacyFork => {
                let profile = boot_config.and_then(|config| config.firmware_profile.as_deref());
                if profile.is_some_and(|profile| {
                    profile != FIRMWARE_EDK2_STABLE202605 || self.indirect.is_some()
                }) {
                    bail!(
                        "a document with qemu.processor_id or a qemu.serial list (the \
                         chutesai/tdx-measure form) measures a direct boot with the \
                         {FIRMWARE_EDK2_STABLE202605} sequence and an indirect boot with the \
                         boot variables; firmware_profile {profile:?} contradicts it"
                    );
                }
                Ok(())
            }
            MetadataForm::V1 => {
                if let Some(config) = boot_config {
                    match config.firmware_profile.as_deref() {
                        Some(FIRMWARE_EDK2_STABLE202605) => {
                            if config.smbios_tables.as_deref().is_none_or(str::is_empty) {
                                bail!(
                                    "firmware_profile {FIRMWARE_EDK2_STABLE202605} needs \
                                     boot_config.smbios_tables (RTMR0 measures the SMBIOS tables)"
                                );
                            }
                        }
                        Some(FIRMWARE_EDK2_STABLE202502) => {}
                        Some(other) => bail!(
                            "firmware_profile {other:?} is not one this tool knows \
                             ({FIRMWARE_EDK2_STABLE202605}, {FIRMWARE_EDK2_STABLE202502})"
                        ),
                        None if self.direct.is_some() => bail!(
                            "metadata_version 1: a direct boot must name \
                             boot_config.firmware_profile ({FIRMWARE_EDK2_STABLE202605} or \
                             {FIRMWARE_EDK2_STABLE202502}); its RTMR0 event sequence depends on it"
                        ),
                        None => {}
                    }
                }
                if let Some(qemu) = qemu {
                    if matches!(qemu.serial, Some(SerialPorts::One(_))) {
                        bail!("metadata_version 1 takes qemu.serial as a list of -serial values");
                    }
                    if qemu.processor_id == Some(None) {
                        bail!("metadata_version 1: omit qemu.processor_id rather than set it null");
                    }
                    for device in qemu.devices.iter().chain(qemu.acpi_devices.iter().flatten()) {
                        if acpi::is_bar_stub(device) {
                            acpi::check_bar_stub(device)?;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Validate that exactly one boot mode is specified
    pub fn validate(&self) -> Result<(), String> {
        match (&self.direct, &self.indirect) {
            (Some(_), None) => Ok(()),
            (None, Some(_)) => Ok(()),
            (Some(_), Some(_)) => Err("Cannot specify both direct and indirect boot".to_string()),
            (None, None) => Ok(()),
        }
    }

    /// Check if this is direct boot mode
    pub fn is_direct_boot(&self) -> bool {
        self.direct.is_some()
    }

    /// Get direct boot info
    pub fn direct_boot(&self) -> Option<&DirectBoot> {
        self.direct.as_ref()
    }

    /// Get indirect boot info
    pub fn indirect_boot(&self) -> Option<&IndirectBoot> {
        self.indirect.as_ref()
    }

    /// Get command line regardless of boot mode
    pub fn cmdline(&self) -> &str {
        match (&self.direct, &self.indirect) {
            (Some(direct), None) => &direct.cmdline,
            (None, Some(indirect)) => &indirect.cmdline,
            _ => "", // Should not happen after validation
        }
    }

    /// Get CPU count from boot config
    pub fn cpu_count(&self) -> Result<u32> {
        let boot_config = self
            .boot_config
            .as_ref()
            .ok_or_else(|| anyhow!("Boot config is required"))?;

        Ok(boot_config.cpus)
    }

    /// Get memory size from boot config
    pub fn memory_size(&self) -> Result<u64> {
        let boot_config = self
            .boot_config
            .as_ref()
            .ok_or_else(|| anyhow!("Boot config is required"))?;

        parse_memory_size(&boot_config.memory)
    }
}

/// Parse a memory size value that can be decimal or hexadecimal (with 0x prefix)
pub fn parse_memory_size(s: &str) -> Result<u64> {
    let s = s.trim();

    if s.is_empty() {
        return Err(anyhow!("Empty memory size"));
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        let hex_str = &s[2..];
        return u64::from_str_radix(hex_str, 16)
            .map_err(|e| anyhow!("Invalid hexadecimal value: {}", e));
    }

    if s.chars().all(|c| c.is_ascii_digit()) {
        return Ok(s.parse::<u64>()?);
    }
    let len = s.len();
    let (num_part, suffix) = match s.chars().last().unwrap() {
        'k' | 'K' => (&s[0..len - 1], 1024u64),
        'm' | 'M' => (&s[0..len - 1], 1024u64 * 1024),
        'g' | 'G' => (&s[0..len - 1], 1024u64 * 1024 * 1024),
        't' | 'T' => (&s[0..len - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => return Err(anyhow!("Unknown memory size suffix")),
    };

    let num = num_part.parse::<u64>()?;
    Ok(num * suffix)
}
