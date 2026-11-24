"""
- ``chutes.cvm-platform-data.v1``: per machine type, the RTMR0 template and the captures
  (``{uefi_sha384, mrtd, cfv_sha384, rtmr0}``) of the platform; ``predict`` takes MRTD and RTMR0
  from it (exact: the newest capture; firmware-following: the template);
- ``chutes.cvm-platform.v1``: the platform entry of Chutes' signed catalog: project numbers,
  regions, machine types and firmware floor; ``verify-quote --platform`` pins the platform row and
  the floor to it.
"""

from __future__ import annotations

import json
import re

_HEX96 = re.compile(r"[0-9a-f]{96}")
_GCE_ID = re.compile(r"[1-9][0-9]{0,19}")
_REGION = re.compile(r"[a-z]+(-[a-z]+)+[0-9]+")
_MACHINE = re.compile(r"[a-z][a-z0-9-]{0,62}")


def _closed(value, keys, name):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{name} is exactly {sorted(keys)}")
    return value


def _hex96(value, name):
    if not isinstance(value, str) or _HEX96.fullmatch(value) is None:
        raise ValueError(f"{name} is 96 lower-case hex")
    return value


def check_template(t, name="rtmr0_template"):
    _closed(t, {"before_cfv", "after_cfv"}, name)
    _hex96(t["before_cfv"], name + ".before_cfv")
    if not isinstance(t["after_cfv"], list) or not 1 <= len(t["after_cfv"]) <= 32:
        raise ValueError(name + ".after_cfv has 1..32 entries")
    for item in t["after_cfv"]:
        _hex96(item, name + ".after_cfv[]")
    return t


def parse_platform_data(raw: bytes) -> dict:
    doc = json.loads(raw)
    _closed(doc, {"schema", "captured_at", "source", "settings", "machine_types"}, "platform data")
    if doc["schema"] != "chutes.cvm-platform-data.v1":
        raise ValueError("schema is chutes.cvm-platform-data.v1")
    _closed(doc["settings"], {"secure_boot", "vtpm", "integrity_monitoring", "disks"}, "settings")
    if not isinstance(doc["machine_types"], dict) or not doc["machine_types"]:
        raise ValueError("machine_types names at least one machine type")
    for machine, entry in doc["machine_types"].items():
        if _MACHINE.fullmatch(machine) is None:
            raise ValueError(f"machine type {machine!r}")
        _closed(entry, {"rtmr0_template", "captures"}, machine)
        check_template(entry["rtmr0_template"], machine + ".rtmr0_template")
        if not isinstance(entry["captures"], list):
            raise ValueError(machine + ".captures is a list")
        for capture in entry["captures"]:
            _closed(capture, {"uefi_sha384", "mrtd", "cfv_sha384", "rtmr0"}, machine + ".captures[]")
            for key in capture:
                _hex96(capture[key], f"{machine}.captures[].{key}")
    return doc


def parse_platform(raw: bytes) -> dict:
    doc = json.loads(raw)
    _closed(doc, {"schema", "provider", "tee_type", "project_numbers", "regions", "machine_types", "firmware_floor"}, "platform")
    if doc["schema"] != "chutes.cvm-platform.v1" or doc["provider"] != "gcp" or doc["tee_type"] != "tdx":
        raise ValueError("a chutes.cvm-platform.v1 document for gcp tdx")
    for key, pattern, bound in (("project_numbers", _GCE_ID, 4), ("regions", _REGION, 16), ("machine_types", _MACHINE, 8)):
        items = doc[key]
        if (not isinstance(items, list) or not 1 <= len(items) <= bound or len(set(items)) != len(items)
                or not all(isinstance(i, str) and pattern.fullmatch(i) for i in items)):
            raise ValueError(f"{key}: 1..{bound} distinct values")
    return doc
