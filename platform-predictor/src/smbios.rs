/*
 * Copyright (c) 2026 Chutes Global Corp
 * SPDX-License-Identifier: Apache-2.0
 */
use anyhow::{bail, Result};

const OVMF_DEFAULT_TYPE0: &[u8] = b"\x00\x1a\x00\x00\x01\x02\x00\xe8\
    \x03\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\xff\xff\x00\x00\
    EDK II\x00unknown\x0002/02/2022\x00\x00";
const OVMF_END_OF_TABLE: &[u8] = b"\x7f\x04\xff\xfe\x00\x00";

#[derive(Clone, Copy)]
struct Filter {
    offset: usize,
    size: usize,
    string: bool,
}

const TYPE1: &[Filter] = &[
    Filter {
        offset: 7,
        size: 1,
        string: true,
    },
    Filter {
        offset: 8,
        size: 16,
        string: false,
    },
    Filter {
        offset: 24,
        size: 1,
        string: false,
    },
];
const TYPE2: &[Filter] = &[
    Filter {
        offset: 7,
        size: 1,
        string: true,
    },
    Filter {
        offset: 10,
        size: 1,
        string: true,
    },
];
const TYPE3: &[Filter] = &[
    Filter {
        offset: 7,
        size: 1,
        string: true,
    },
    Filter {
        offset: 8,
        size: 1,
        string: true,
    },
];
const TYPE4: &[Filter] = &[
    Filter {
        offset: 32,
        size: 1,
        string: true,
    },
    Filter {
        offset: 33,
        size: 1,
        string: true,
    },
    Filter {
        offset: 34,
        size: 1,
        string: true,
    },
    Filter {
        offset: 35,
        size: 1,
        string: false,
    },
    Filter {
        offset: 36,
        size: 1,
        string: false,
    },
    Filter {
        offset: 37,
        size: 1,
        string: false,
    },
    Filter {
        offset: 42,
        size: 2,
        string: false,
    },
    Filter {
        offset: 44,
        size: 2,
        string: false,
    },
    Filter {
        offset: 46,
        size: 2,
        string: false,
    },
    Filter {
        offset: 17,
        size: 1,
        string: false,
    },
    Filter {
        offset: 22,
        size: 2,
        string: false,
    },
];
const TYPE17: &[Filter] = &[
    Filter {
        offset: 24,
        size: 1,
        string: true,
    },
    Filter {
        offset: 25,
        size: 1,
        string: true,
    },
    Filter {
        offset: 26,
        size: 1,
        string: true,
    },
];

fn entry_end(data: &[u8], start: usize, formatted_len: usize) -> Result<usize> {
    let mut cursor = start + formatted_len;
    if cursor > data.len() {
        bail!("SMBIOS formatted structure exceeds table length");
    }
    while cursor + 1 < data.len() {
        if data[cursor] == 0 && data[cursor + 1] == 0 {
            return Ok(cursor + 2);
        }
        cursor += 1;
    }
    bail!("SMBIOS structure has no double-NUL terminator")
}

fn string_range(
    entry: &[u8],
    formatted_len: usize,
    string_id: u8,
) -> Result<Option<(usize, usize)>> {
    if string_id == 0 {
        return Ok(None);
    }
    let mut cursor = formatted_len;
    let mut current = 1u8;
    while cursor < entry.len() {
        if entry[cursor] == 0 {
            if cursor + 1 < entry.len() && entry[cursor + 1] == 0 {
                break;
            }
            current = current.saturating_add(1);
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < entry.len() && entry[cursor] != 0 {
            cursor += 1;
        }
        if current == string_id {
            return Ok(Some((start, cursor)));
        }
    }
    bail!("SMBIOS string index {string_id} is out of range")
}

fn filters_for(table_type: u8) -> Option<&'static [Filter]> {
    match table_type {
        1 => Some(TYPE1),
        2 => Some(TYPE2),
        3 => Some(TYPE3),
        4 => Some(TYPE4),
        11 | 15 | 18 | 31 | 33 => Some(&[]),
        17 => Some(TYPE17),
        _ => None,
    }
}

/// Apply edk2-stable202605 SmbiosMeasurementDxe's filtering policy byte-for-byte.
pub(crate) fn filter_for_measurement(data: &[u8]) -> Result<Vec<u8>> {
    let mut filtered = data.to_vec();
    let mut start = 0usize;
    while start < filtered.len() {
        if start + 4 > filtered.len() {
            bail!("truncated SMBIOS structure header");
        }
        let table_type = filtered[start];
        let formatted_len = filtered[start + 1] as usize;
        if formatted_len < 4 {
            bail!("invalid SMBIOS formatted structure length");
        }
        let end = entry_end(&filtered, start, formatted_len)?;
        let entry = &mut filtered[start..end];
        if table_type >= 128 {
            entry[4..].fill(0);
        } else if let Some(filters) = filters_for(table_type) {
            if filters.is_empty() {
                entry[4..].fill(0);
            } else {
                for filter in filters {
                    if formatted_len < filter.offset + filter.size {
                        continue;
                    }
                    if filter.string {
                        let string_id = entry[filter.offset];
                        if let Some((string_start, string_end)) =
                            string_range(entry, formatted_len, string_id)?
                        {
                            entry[string_start..string_end].fill(b' ');
                        }
                    }
                    entry[filter.offset..filter.offset + filter.size].fill(0);
                }
            }
        }
        start = end;
    }
    Ok(filtered)
}

/// Reproduce the table block exported by edk2-stable202605's SmbiosDxe.
///
/// QEMU's fw_cfg payload omits Type 0. OVMF imports every structure before
/// QEMU's Type 127 marker, appends its deterministic default Type 0, then
/// emits a new Type 127 marker with the reserved 0xFEFF handle.
pub(crate) fn ovmf_filter_for_measurement(data: &[u8]) -> Result<Vec<u8>> {
    let mut tables = Vec::with_capacity(data.len() + OVMF_DEFAULT_TYPE0.len());
    let mut start = 0usize;
    let mut found_end = false;
    let mut found_type0 = false;
    while start < data.len() {
        if start + 4 > data.len() {
            bail!("truncated SMBIOS structure header");
        }
        let table_type = data[start];
        let formatted_len = data[start + 1] as usize;
        if formatted_len < 4 {
            bail!("invalid SMBIOS formatted structure length");
        }
        let end = entry_end(data, start, formatted_len)?;
        if table_type == 127 {
            if end != data.len() {
                bail!("SMBIOS data follows the Type 127 end marker");
            }
            found_end = true;
            break;
        }
        found_type0 |= table_type == 0;
        tables.extend_from_slice(&data[start..end]);
        start = end;
    }
    if !found_end {
        bail!("SMBIOS table has no Type 127 end marker");
    }
    if !found_type0 {
        tables.extend_from_slice(OVMF_DEFAULT_TYPE0);
    }
    tables.extend_from_slice(OVMF_END_OF_TABLE);
    filter_for_measurement(&tables)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use sha2::{Digest, Sha384};

    #[test]
    fn filters_type1_uuid_wakeup_and_serial_string() {
        let mut entry = vec![1, 27, 0, 0, 1, 2, 3, 4];
        entry.extend_from_slice(&[0xAA; 16]);
        entry.push(6);
        entry.extend_from_slice(&[0, 0]);
        entry.extend_from_slice(b"maker\0product\0version\0serial\0\0");

        let filtered = filter_for_measurement(&entry).unwrap();

        assert_eq!(&filtered[8..24], &[0; 16]);
        assert_eq!(filtered[24], 0);
        assert_eq!(filtered[7], 0);
        assert!(filtered.windows(6).any(|window| window == b"      "));
    }

    #[test]
    fn reproduces_live_edk2_stable202605_smbios_digest() {
        let qemu_tables = hex!(
            "011b0001010203000000000000000000000000000000000006000051454d5500"
            "5374616e646172642050432028513335202b20494348392c2032303039290070"
            "632d7133352d31302e3100000316000301010200000303030200000000000000"
            "000051454d550070632d7133352d31302e310000042a00040103fe0201000000"
            "0000000003000000d007d0074101ffffffffffff000000020202020001004350"
            "5520300043687574657300496e74656c2d5444582d5669727475616c2d435055"
            "00001017001001030600008000feff0100000000000000000000001128001100"
            "10feffffffffff00200900010007020000000200000000000000000000000000"
            "00000044494d4d20300051454d550000131f001300000000ffff1f0000100100"
            "0000000000000000000000000000000000131f011300004000ffff9f00001001"
            "000000000000000000000000000000000000200b00200000000000000000007f"
            "04007f0000"
        );

        let filtered = ovmf_filter_for_measurement(&qemu_tables).unwrap();

        assert_eq!(
            Sha384::digest(&filtered).as_slice(),
            &hex!(
                "9bd524d0aa99b7ff99c47286feca42be8af72f8e32b52293be03845ba09a5ee4"
                "2f1e8feae9315717b0e705ab6f61a16e"
            )
        );
    }
}
