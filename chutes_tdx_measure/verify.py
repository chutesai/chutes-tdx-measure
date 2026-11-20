from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

from chutes_tdx_measure import collateral, document, firmware
from chutes_tdx_measure.match import match
from chutes_tdx_measure.vendor.chutes_attest import gcp_tdx_provenance, quote as quote_parser, tdx_policy, tdx_verify

ATTEST_TAG = b"chutes-tdx-endpoint-attest-v1"
INCOMPLETE = "endpoint_check_incomplete"
_ZONE = re.compile(r"[a-z]+(-[a-z]+)+[0-9]+-[a-z]")
_GCE_ID = re.compile(r"[1-9][0-9]{0,19}")
_MEASUREMENT_CODES = {
    "measurements_unsigned": "endpoint_vm_measurements_unsigned",
    "firmware_refused": "endpoint_vm_firmware_refused",
    "measurements_unmatched": "endpoint_vm_measurements_unmatched",
}


def attest_report_data(nonce: bytes, public_key: bytes) -> bytes:
    """The /attest rule (chutes-tdx-gate spec/SPEC.md §4.1): SHA-512(tag || 0x00 || nonce || public_key)."""
    return hashlib.sha512(ATTEST_TAG + b"\x00" + nonce + public_key).digest()


@dataclass
class Inputs:
    quote: bytes
    expected_report_data: bytes
    documents: list            # [(raw bytes, signature B64)], in listing order
    measurement_key: bytes     # 32 raw bytes
    image_sha256: str
    machine_type: str
    project_number: str        # the instance's project (what MR_OWNER's PZID names)
    zone: str
    instance_id: str
    allowed_projects: tuple = ()   # the project pin (required: empty refuses the platform row)
    allowed_regions: tuple = ()    # empty: any
    allowed_machine_types: tuple = ()
    floor: firmware.Floor = field(default_factory=firmware.Floor)


@dataclass
class Verifiers:
    """The network-backed checks (tests inject fakes)."""

    quote: Callable = None        # async (raw) -> verdict; raises TdxQuoteRejected / VerifierUnavailable
    admission: Callable = None    # (mrtd, floor, need_cfv) -> firmware.Admission; raises FirmwareUnavailable
    provenance: Callable = None   # async (raw, Instance) -> Provenance; raises ProvenanceRefused / Unavailable


def default_verifiers(now: Optional[dt.datetime] = None, firmware_dir=None, collateral_source=None) -> Verifiers:
    return Verifiers(
        # Never the vendored one-step verifier: it does not check who signed the collateral.
        quote=lambda raw: collateral.verify_quote(raw, collateral_source=collateral_source),
        admission=lambda mrtd, floor, need_cfv: firmware.admit(mrtd, floor, now=now, directory=firmware_dir, need_cfv=need_cfv),
        provenance=lambda raw, inst: gcp_tdx_provenance.verify(raw, inst, now=now or dt.datetime.now(dt.timezone.utc)),
    )


def _row(name, status, code=None, detail=""):
    return {"row": name, "status": status, "code": code, "detail": detail}


def _region(zone: str) -> str:
    return zone.rsplit("-", 1)[0]


def _debug(raw: bytes) -> bool:
    """TD_ATTRIBUTES bit 0 (absolute byte 168 of a v4 quote)."""
    return len(raw) > 168 and bool(raw[168] & 0x01)


def run(inputs: Inputs, verifiers: Verifiers) -> dict:
    """Every row with its status (pass, fail, incomplete, not_run) and code; ``pass`` only when all
    five pass."""
    rows = []
    raw = bytes(inputs.quote)
    try:
        parsed = quote_parser.parse_quote(raw)
    except quote_parser.QuoteParseError as exc:
        parsed = None
        parse_error = str(exc)

    # quote: Intel's collateral and its signers, TCB status and advisories, TD attributes, not debug.
    if parsed is None:
        rows.append(_row("quote", "fail", "endpoint_vm_quote_refused", f"not a TDX v4 quote: {parse_error}"))
    elif _debug(raw):
        rows.append(_row("quote", "fail", "endpoint_vm_quote_refused", "TD_ATTRIBUTES.DEBUG is set"))
    else:
        try:
            verdict = asyncio.run(verifiers.quote(raw))
            td_attributes = verdict.td10.get("td_attributes") if hasattr(verdict, "td10") else None
            if not verdict.passed:
                rows.append(_row("quote", "fail", "endpoint_vm_quote_refused",
                                 "; ".join(c.name for c in tdx_policy.failed(verdict.checks))))
            elif tdx_policy.debug_enabled(td_attributes) or not tdx_policy.td_attributes_valid(td_attributes):
                # Missing attributes count as debug: a verdict without them cannot show debug is off.
                rows.append(_row("quote", "fail", "endpoint_vm_quote_refused", "TD attributes missing or refused"))
            else:
                rows.append(_row("quote", "pass", None, f"Intel DCAP: {verdict.status}"))
        except tdx_verify.TdxQuoteRejected as exc:
            rows.append(_row("quote", "fail", "endpoint_vm_quote_refused", str(exc)))
        except tdx_verify.VerifierUnavailable as exc:
            rows.append(_row("quote", "incomplete", INCOMPLETE, str(exc)))

    # binding: a v4 TDX quote whose REPORTDATA is the expected one.
    if parsed is not None and bytes.fromhex(parsed.report_data) == inputs.expected_report_data:
        rows.append(_row("binding", "pass", None, "REPORTDATA binds the nonce and the key"))
    else:
        rows.append(_row("binding", "fail", "endpoint_vm_binding_mismatch", "REPORTDATA is not the expected value"))

    # platform: the project pinned, the zone's region and the machine type allowed. The pin is
    # required: a project the VM names is never its own pin.
    allowed = set(inputs.allowed_projects)
    problems = []
    if not allowed:
        problems.append("no project pin (allowed projects)")
    elif not _GCE_ID.fullmatch(inputs.project_number) or inputs.project_number not in allowed:
        problems.append(f"project {inputs.project_number} is not {sorted(allowed)}")
    if not _ZONE.fullmatch(inputs.zone) or (inputs.allowed_regions and _region(inputs.zone) not in inputs.allowed_regions):
        problems.append(f"zone {inputs.zone} is not in {list(inputs.allowed_regions)}")
    if inputs.allowed_machine_types and inputs.machine_type not in inputs.allowed_machine_types:
        problems.append(f"machine type {inputs.machine_type} is not offered")
    if not _GCE_ID.fullmatch(inputs.instance_id) or int(inputs.instance_id) >= 2 ** 64:
        problems.append("the instance id is not a GCE id")
    rows.append(_row("platform", "fail", "endpoint_vm_platform_mismatch", "; ".join(problems)) if problems
                else _row("platform", "pass", None, f"project {inputs.project_number}, {inputs.zone}, {inputs.machine_type}"))

    # measurements: every document verified, the MRTD admitted under the floor (every form), a match.
    matched = None
    entries, skipped = [], []
    for index, (raw_doc, signature) in enumerate(inputs.documents):
        try:
            entries.append(document.parse_document(raw_doc, signature, inputs.measurement_key, inputs.image_sha256))
        except document.DocumentRefused as exc:
            entries.append(None)
            skipped.append(f"document {index}: {exc.code}")
    if parsed is None:
        rows.append(_row("measurements", "fail", "endpoint_vm_measurements_unmatched", "no registers"))
    elif any(r["status"] != "pass" for r in rows if r["row"] in ("quote", "binding")):
        # An unproven quote's MRTD is never looked up in Google's firmware index (a caller could
        # otherwise make this verifier fetch for any MRTD it invents).
        rows.append(_row("measurements", "not_run", INCOMPLETE, "the quote or binding row did not pass"))
    else:
        observed = {"mrtd": parsed.mrtd.lower(), **{k: v.lower() for k, v in parsed.rtmrs.items()}}
        try:
            need_cfv = any(e is not None and "rtmr0_template" in entry for e in entries for entry in (e or []))
            admission = (firmware.Admission(False, ()) if all(e is None for e in entries)
                         else verifiers.admission(observed["mrtd"], inputs.floor, need_cfv))
            result = match(entries, inputs.machine_type, observed, list(admission.cfvs), admission.admitted)
            if isinstance(result, tuple):
                matched = {"document": result[0], "entry": result[1]}
                rows.append(_row("measurements", "pass", None,
                                 f"document {result[0]} entry {result[1]}" + (f" ({'; '.join(skipped)} skipped)" if skipped else "")))
            else:
                rows.append(_row("measurements", "fail", _MEASUREMENT_CODES[result],
                                 result + (f" ({'; '.join(skipped)})" if skipped else "")))
        except firmware.FirmwareUnavailable as exc:
            rows.append(_row("measurements", "incomplete", INCOMPLETE, str(exc)))

    # provider_root last: MRCONFIGID and MROWNERCONFIG zero, Google's provenance of the instance.
    failed = [r["row"] for r in rows if r["status"] != "pass"]
    if failed:
        rows.append(_row("provider_root", "not_run", INCOMPLETE, gcp_tdx_provenance.not_checked(failed)))
    elif parsed.mr_config_id != "0" * 96 or parsed.mr_owner_config != "0" * 96:
        rows.append(_row("provider_root", "fail", "endpoint_vm_provider_refused", "MRCONFIGID or MROWNERCONFIG is set"))
    else:
        instance = gcp_tdx_provenance.Instance(int(inputs.project_number), inputs.zone, int(inputs.instance_id))
        try:
            provenance = asyncio.run(verifiers.provenance(raw, instance))
            rows.append(_row("provider_root", "pass", None, provenance.detail()))
        except gcp_tdx_provenance.ProvenanceRefused as exc:
            rows.append(_row("provider_root", "fail", "endpoint_vm_provider_refused", f"{exc.code}: {exc.text}"))
        except tdx_verify.VerifierUnavailable as exc:
            rows.append(_row("provider_root", "incomplete", INCOMPLETE, str(exc)))

    return {
        "schema": "chutes.tdx-measure-verify.v1",
        "pass": all(r["status"] == "pass" for r in rows) and len(rows) == 5,
        "rows": rows,
        "match": matched,
        "observed": None if parsed is None else {"mrtd": parsed.mrtd.lower(),
                                                 **{k: v.lower() for k, v in parsed.rtmrs.items()}},
    }
