from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json

from chutes_tdx_measure.match import fold
from chutes_tdx_measure.vendor.chutes_attest import quote as quote_parser, rtmr_replay, tdx_policy, tdx_verify

EV_EFI_PLATFORM_FIRMWARE_BLOB2 = 0x8000000A
CAPTURE_TAG = b"chutes-tdx-capture-v1"
# What the command prints (to standard error) with every capture: verified, and not.
NOTICE = ("capture: Intel DCAP verified this quote (TCB status {status}) and its REPORTDATA carries your nonce: a "
          "genuine TD measured these registers after you chose the nonce. That does not make them your image's. "
          "Compare RTMR1 and RTMR2 with your own `predict` output for your own archive before you sign anything, and "
          "sign only values that prediction gives.")
NOTICE_UNVERIFIED = ("capture: NOT VERIFIED (--unverified): the quote's signature was not checked and no nonce binds "
                     "it, so nothing shows these registers came from a TD. Do not sign them. Compare them with your "
                     "own `predict` output for your own archive, and sign only values that prediction gives.")


class CaptureRefused(ValueError):
    pass


class CaptureUnavailable(RuntimeError):
    """No verdict on the quote (Intel's collateral did not answer): never a capture."""


def capture_report_data(nonce: bytes) -> bytes:
    return hashlib.sha512(CAPTURE_TAG + b"\x00" + nonce).digest()


def parse_serial_line(line: str) -> tuple:
    """(quote, ccel) from the capture variant's serial line."""
    prefix = "CHUTES-CAPTURE-V1 "
    line = line.strip()
    if not line.startswith(prefix):
        raise CaptureRefused("not a CHUTES-CAPTURE-V1 line")
    try:
        doc = json.loads(base64.b64decode(line[len(prefix):], validate=True))
        return base64.b64decode(doc["quote"], validate=True), base64.b64decode(doc["ccel"], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise CaptureRefused("the capture line does not decode") from None


def rtmr0_template(events) -> tuple:
    """(template, cfv_sha384) from the CCEL's RTMR0 events: exactly one CFV event."""
    rtmr0 = [e for e in events if e.mr_index == 1 and e.event_type != rtmr_replay.EV_NO_ACTION
             and rtmr_replay.TPM_ALG_SHA384 in e.digests]
    cfv = [i for i, e in enumerate(rtmr0) if e.event_type == EV_EFI_PLATFORM_FIRMWARE_BLOB2]
    if len(cfv) != 1:
        raise CaptureRefused(f"{len(cfv)} firmware-blob events in RTMR0, exactly one (the CFV) expected")
    register = bytes(48)
    for event in rtmr0[: cfv[0]]:
        register = hashlib.sha384(register + event.digests[rtmr_replay.TPM_ALG_SHA384]).digest()
    after = [e.digests[rtmr_replay.TPM_ALG_SHA384].hex() for e in rtmr0[cfv[0] + 1:]]
    if not 1 <= len(after) <= 32:
        raise CaptureRefused("the template needs 1..32 events after the CFV")
    template = {"before_cfv": register.hex(), "after_cfv": after}
    return template, rtmr0[cfv[0]].digests[rtmr_replay.TPM_ALG_SHA384].hex()


def verified_status(quote: bytes, verify_quote) -> str:
    """Intel's TCB status for a quote Intel DCAP verifies under the shared policy (``verify_quote``:
    async (raw) -> verdict, as ``verify.Verifiers.quote``), production attributes and debug off as
    ``verify-quote``'s ``quote`` row. ``CaptureRefused`` when Intel DCAP refuses it, ``CaptureUnavailable``
    when the verifier reached no verdict."""
    try:
        verdict = asyncio.run(verify_quote(bytes(quote)))
    except tdx_verify.TdxQuoteRejected as exc:
        raise CaptureRefused(f"Intel DCAP refuses the quote: {exc}") from None
    except tdx_verify.VerifierUnavailable as exc:
        raise CaptureUnavailable(f"Intel DCAP reached no verdict on the quote: {exc}") from None
    if not verdict.passed:
        raise CaptureRefused("Intel DCAP refuses the quote: " + "; ".join(c.name for c in tdx_policy.failed(verdict.checks)))
    td_attributes = verdict.td10.get("td_attributes") if hasattr(verdict, "td10") else None
    if tdx_policy.debug_enabled(td_attributes) or not tdx_policy.td_attributes_valid(td_attributes):
        raise CaptureRefused("Intel DCAP refuses the quote: TD attributes missing or refused (a debug TD's registers prove nothing)")
    return str(verdict.status)


def capture(quote: bytes, ccel: bytes, *, nonce: bytes = None, verify_quote=None) -> dict:
    """The registers (lower hex), checked: the CCEL replays to the quote's RTMR0-3; with ``nonce``,
    REPORTDATA is the capture rule over it. With ``verify_quote`` (``verified_status``) the quote is
    also Intel's and a nonce is required: ``quote_verification`` then names Intel's TCB status and
    the nonce. Without it ``quote_verification`` is null: the registers are whatever the bytes say."""
    try:
        parsed = quote_parser.parse_quote(quote)
    except quote_parser.QuoteParseError as exc:
        raise CaptureRefused(f"not a TDX v4 quote: {exc}") from None
    if verify_quote is not None and nonce is None:
        raise CaptureRefused("a verified capture needs the capture nonce: without it the quote may be any earlier one")
    try:
        events = rtmr_replay.parse_event_log(ccel)
        replayed = rtmr_replay.replay_sha384(events)
    except ValueError as exc:
        raise CaptureRefused(f"the CCEL does not parse: {exc}") from None
    for index in range(4):
        if replayed[f"RTMR{index}"].lower() != parsed.rtmrs[f"rtmr{index}"].lower():
            raise CaptureRefused(f"the CCEL does not replay to the quote's RTMR{index}")
    if nonce is not None and bytes.fromhex(parsed.report_data) != capture_report_data(nonce):
        raise CaptureRefused("REPORTDATA is not the capture rule over this nonce")
    # Intel's verdict last: nothing is fetched for a quote the local checks already refuse.
    verification = None
    if verify_quote is not None:
        verification = {"intel_dcap": verified_status(quote, verify_quote), "nonce": nonce.hex()}
    registers = {"mrtd": parsed.mrtd.lower(), **{k: v.lower() for k, v in parsed.rtmrs.items()}}
    out = {"schema": "chutes.tdx-measure-capture.v1", "registers": registers,
           "mr_config_id": parsed.mr_config_id.lower(), "mr_owner_config": parsed.mr_owner_config.lower(),
           "rtmr0_template": None, "cfv_sha384": None, "quote_verification": verification}
    try:
        template, cfv = rtmr0_template(events)
        if fold(template, cfv) != registers["rtmr0"]:
            raise CaptureRefused("the template does not fold to RTMR0")
        out["rtmr0_template"], out["cfv_sha384"] = template, cfv
    except CaptureRefused as exc:
        out["rtmr0_template_error"] = str(exc)
    return out
