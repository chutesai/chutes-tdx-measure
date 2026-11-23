/*
 * Copyright (c) 2026 Chutes Global Corp
 * SPDX-License-Identifier: Apache-2.0
 */
//! The metadata forms: `metadata_version` 1, the legacy form and the chutesai/tdx-measure form.

use serde_json::{json, Value};
use tdx_measure::{ImageConfig, MetadataForm, SerialPorts};

/// A document as chutes-cvm renders one for `--platform-only --create-acpi-tables`.
fn cvm_document() -> Value {
    json!({
        "boot_config": {
            "cpus": 124,
            "memory": "1128G",
            "bios": "/opt/ovmf/OVMF.inteltdx.fd",
            "acpi_tables": "/out/acpi.bin",
            "qemu": {
                "machine": "q35,kernel_irqchip=split,smm=off,pic=off",
                "cpu": "host,-avx10,vendor=GenuineIntel",
                "accel": "kvm",
                "smp": "124,sockets=2,cores=62,threads=1",
                "objects": ["memory-backend-ram,id=mem-node0,size=577536M,reserve=off"],
                "numa": ["node,nodeid=0,memdev=mem-node0", "cpu,node-id=0,socket-id=0"],
                "smbios": ["type=3,manufacturer=Chutes,version=1.0,serial=0"],
                "serial": ["null"],
                "devices": [
                    "pxb-pcie,bus_nr=128,id=pxb_numa0,numa_node=0,bus=pcie.0,addr=0x18",
                    "pcie-root-port,port=16,chassis=1,id=rp1,bus=pxb_numa0,addr=0x1",
                    "pci-bar-stub,bus=rp1,bars=0:16M:p64;2:256G:p64;4:32M:p64,vendor=0x10de,device=0x2335,class=0x0302"
                ],
                "fw_cfg": [],
                "processor_id": "f2060c00fffba91f"
            }
        },
        "direct": {"kernel": "/dev/null", "initrd": "/dev/null", "cmdline": ""}
    })
}

/// A document as Chutes' launch tooling renders one.
fn chutes_document() -> Value {
    json!({
        "boot_config": {
            "cpus": 8,
            "memory": "65536M",
            "bios": "/fw/OVMF.inteltdx.fd",
            "acpi_tables": "/w/acpi_tables.bin",
            "smbios_tables": "/w/smbios_tables.bin",
            "firmware_profile": "edk2-stable202605",
            "qemu": {
                "machine": "pc-q35-10.2,hpet=off",
                "memory": "65536M",
                "smp": "8",
                "cpu": "max,phys-bits=46",
                "accel": "tcg",
                "globals": [],
                "objects": [],
                "numa": [],
                "drives": [],
                "netdevs": ["hubport,id=n0,hubid=0"],
                "devices": ["virtio-rng-pci"],
                "fw_cfg": [],
                "smbios": ["type=4,processor-id=1"],
                "serial": "null"
            }
        },
        "direct": {"kernel": "/k", "initrd": "/i", "cmdline": "ro"}
    })
}

fn v1_document() -> Value {
    let mut doc = chutes_document();
    doc["metadata_version"] = json!(1);
    doc["boot_config"]["qemu"]["serial"] = json!(["null"]);
    doc
}

fn parse(doc: &Value) -> anyhow::Result<ImageConfig> {
    ImageConfig::from_json_str(&doc.to_string())
}

#[test]
fn each_form_is_recognized() {
    assert_eq!(parse(&cvm_document()).unwrap().form, MetadataForm::LegacyFork);
    assert_eq!(parse(&chutes_document()).unwrap().form, MetadataForm::Legacy);
    assert_eq!(parse(&v1_document()).unwrap().form, MetadataForm::V1);

    // A present null processor_id marks the fork form too; so does a serial list alone.
    let mut doc = cvm_document();
    doc["boot_config"]["qemu"]["processor_id"] = Value::Null;
    assert_eq!(parse(&doc).unwrap().form, MetadataForm::LegacyFork);
    let mut doc = cvm_document();
    doc["boot_config"]["qemu"].as_object_mut().unwrap().remove("processor_id");
    assert_eq!(parse(&doc).unwrap().form, MetadataForm::LegacyFork);
    doc["boot_config"]["qemu"]["serial"] = json!("null");
    assert_eq!(parse(&doc).unwrap().form, MetadataForm::Legacy);

    // The runtime-only document and the upstream fixtures are legacy documents.
    let runtime = json!({"direct": {"kernel": "/k", "initrd": "/i", "cmdline": ""}});
    assert_eq!(parse(&runtime).unwrap().form, MetadataForm::Legacy);
    for fixture in ["canonical-defaults", "q35-with-hpet", "runtime-capture"] {
        let path = format!("{}/tests/fixtures/{fixture}/metadata.json", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(ImageConfig::from_json_str(&text).unwrap().form, MetadataForm::Legacy, "{path}");
    }
}

#[test]
fn the_fork_form_keeps_its_fields() {
    let config = parse(&cvm_document()).unwrap();
    let qemu = config.boot_config.unwrap().qemu.unwrap();
    assert_eq!(qemu.serial, Some(SerialPorts::List(vec!["null".into()])));
    assert_eq!(qemu.serial_ports(), vec!["null"]);
    assert_eq!(qemu.processor_id_bytes().unwrap(), Some([0xf2, 0x06, 0x0c, 0x00, 0xff, 0xfb, 0xa9, 0x1f]));
}

#[test]
fn more_than_255_vcpus_parse() {
    let mut doc = cvm_document();
    doc["boot_config"]["cpus"] = json!(272);
    assert_eq!(parse(&doc).unwrap().cpu_count().unwrap(), 272);
}

#[test]
fn an_unknown_field_is_an_error_in_every_form() {
    for (doc, at) in [
        (cvm_document(), "/boot_config/qemu"),
        (chutes_document(), "/boot_config/qemu"),
        (v1_document(), "/boot_config/qemu"),
        (chutes_document(), "/boot_config"),
        (v1_document(), "/direct"),
        (cvm_document(), ""),
    ] {
        let mut doc = doc;
        let target = if at.is_empty() { &mut doc } else { doc.pointer_mut(at).unwrap() };
        target["gpu_device_offset"] = json!(9);
        let err = parse(&doc).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field `gpu_device_offset`"), "{at}: {err:#}");
    }
}

#[test]
fn version_1_rules() {
    let refusals: [(&str, fn(&mut Value)); 8] = [
        ("direct boot without firmware_profile", |doc| {
            doc["boot_config"].as_object_mut().unwrap().remove("firmware_profile");
        }),
        ("an unknown firmware_profile", |doc| doc["boot_config"]["firmware_profile"] = json!("edk2-stable202511")),
        ("edk2-stable202605 without smbios_tables", |doc| {
            doc["boot_config"].as_object_mut().unwrap().remove("smbios_tables");
        }),
        ("serial as one string", |doc| doc["boot_config"]["qemu"]["serial"] = json!("null")),
        ("a null processor_id", |doc| doc["boot_config"]["qemu"]["processor_id"] = Value::Null),
        ("a short processor_id", |doc| doc["boot_config"]["qemu"]["processor_id"] = json!("01000000")),
        ("a malformed pci-bar-stub", |doc| {
            doc["boot_config"]["qemu"]["devices"] = json!(["pci-bar-stub,bus=rp1,bars=0:24M:m32"]);
        }),
        ("an unknown metadata_version", |doc| doc["metadata_version"] = json!(2)),
    ];
    for (what, edit) in refusals {
        let mut doc = v1_document();
        edit(&mut doc);
        assert!(parse(&doc).is_err(), "metadata_version 1 accepted {what}");
    }

    let mut doc = v1_document();
    doc["boot_config"]["firmware_profile"] = json!("edk2-stable202502");
    doc["boot_config"]["qemu"]["processor_id"] = json!("0100000000000000");
    doc["boot_config"]["qemu"]["devices"] = json!([
        "pcie-root-port,port=16,chassis=1,id=rp1,bus=pcie.0,addr=0x8",
        "pci-bar-stub,bus=rp1,bars=0:64M:p64;2:128G:p64;4:32M:p64,vendor=0x10de,device=0x2bb5,class=0x0302"
    ]);
    parse(&doc).unwrap();

    // A platform-only document with no direct boot needs no firmware_profile.
    let mut doc = v1_document();
    doc["boot_config"].as_object_mut().unwrap().remove("firmware_profile");
    doc.as_object_mut().unwrap().remove("direct");
    parse(&doc).unwrap();
}

#[test]
fn the_legacy_form_keeps_its_rules() {
    // Direct boot without firmware_profile stays accepted (the BootOrder/Boot0000 sequence).
    let mut doc = chutes_document();
    doc["boot_config"].as_object_mut().unwrap().remove("firmware_profile");
    parse(&doc).unwrap();
    // Any other firmware_profile string keeps selecting that sequence.
    doc["boot_config"]["firmware_profile"] = json!("legacy");
    parse(&doc).unwrap();
}

#[test]
fn the_fork_form_measures_the_edk2_stable202605_sequence() {
    let mut doc = cvm_document();
    doc["boot_config"]["firmware_profile"] = json!("edk2-stable202605");
    parse(&doc).unwrap();
    doc["boot_config"]["firmware_profile"] = json!("edk2-stable202502");
    assert!(parse(&doc).is_err());

    let mut doc = cvm_document();
    doc["boot_config"]["qemu"]["processor_id"] = json!("zz060c00fffba91f");
    assert!(parse(&doc).is_err());
}

#[test]
fn load_puts_the_fork_forms_smbios_tables_where_that_fork_did() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = cvm_document();
    doc["boot_config"]["acpi_tables"] = json!("out/acpi.bin");
    doc["boot_config"]["bios"] = json!("fw/OVMF.inteltdx.fd");
    let path = dir.path().join("metadata.json");
    std::fs::write(&path, doc.to_string()).unwrap();
    let boot_config = ImageConfig::load(&path).unwrap().boot_config.unwrap();
    assert_eq!(
        boot_config.smbios_tables.as_deref(),
        Some(dir.path().join("out/smbios-tables").to_str().unwrap())
    );
    assert_eq!(boot_config.bios, dir.path().join("fw/OVMF.inteltdx.fd").to_str().unwrap());
    assert_eq!(boot_config.firmware_profile, None);

    // A legacy document's absolute paths stay as written; a relative bios is resolved too.
    let path = dir.path().join("chutes.json");
    std::fs::write(&path, chutes_document().to_string()).unwrap();
    let boot_config = ImageConfig::load(&path).unwrap().boot_config.unwrap();
    assert_eq!(boot_config.smbios_tables.as_deref(), Some("/w/smbios_tables.bin"));
    assert_eq!(boot_config.bios, "/fw/OVMF.inteltdx.fd");
    let mut doc = chutes_document();
    doc["boot_config"]["bios"] = json!("../OVMF.fd");
    std::fs::write(&path, doc.to_string()).unwrap();
    let boot_config = ImageConfig::load(&path).unwrap().boot_config.unwrap();
    assert_eq!(boot_config.bios, dir.path().join("../OVMF.fd").to_str().unwrap());
}
