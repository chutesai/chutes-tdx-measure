/*
 * Copyright (c) 2026 Chutes Global Corp
 * SPDX-License-Identifier: Apache-2.0
 */
//! The MRTD of Chutes' TDVF, `OVMF.inteltdx.fd`, the firmware Chutes' bare-metal TDX hosts boot
//! guests with. `tests/fetch_tdvf.sh` downloads it to `tests/fixtures/OVMF.inteltdx.fd` and checks
//! its sha256; `TDVF=<path>` names another copy of the same file.

use sha2::{Digest, Sha256};
use std::path::PathBuf;

const TDVF_SHA256: &str = "01731a86fa3665caccaa4a1906cdd9276b0a53fc5921dbcc70970219ac942169";

fn tdvf() -> PathBuf {
    match std::env::var_os("TDVF") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/OVMF.inteltdx.fd"),
    }
}

#[test]
fn chutes_tdvf_reproduces_live_mrtd() {
    let firmware = tdvf();
    let bytes = std::fs::read(&firmware).unwrap_or_else(|err| {
        panic!("{}: {err} (run tests/fetch_tdvf.sh)", firmware.display())
    });
    assert_eq!(hex::encode(Sha256::digest(&bytes)), TDVF_SHA256, "{}", firmware.display());
    let mrtd = tdx_measure::measure_mrtd(&firmware).expect("measure Chutes' TDVF");

    assert_eq!(
        hex::encode_upper(mrtd),
        "261CE538B435E2D0E85FC97E254BC99154C507B7A8E13D59B69F8532384F1D0BFAADFDDF3FCCC6E0A411203840BBEE8D"
    );
}
