"""capture: the CCEL must replay to the quote's RTMR0-3; the RTMR0 template around the CFV event; the
quote verified with Intel DCAP (the verifier injected) and bound to the caller's nonce."""

import base64
import hashlib
import json
import struct

import pytest

from chutes_tdx_measure import capture
from chutes_tdx_measure.match import fold
from chutes_tdx_measure.vendor.chutes_attest import tdx_policy, tdx_verify

EV_NO_ACTION, EV_SEPARATOR, HOB, CFV, VAR = 3, 4, 0x8000000B, 0x8000000A, 0x80000001


def spec_event():
    data = b"Spec ID Event03\x00" + bytes(8) + struct.pack("<I", 1) + struct.pack("<HH", 0x000C, 48) + b"\x00"
    return struct.pack("<II", 0, EV_NO_ACTION) + bytes(20) + struct.pack("<I", len(data)) + data


def event(mr, kind, payload):
    digest = hashlib.sha384(payload).digest()
    return struct.pack("<III", mr, kind, 1) + struct.pack("<H", 0x000C) + digest + struct.pack("<I", len(payload)) + payload, digest


def build(events):
    log = spec_event()
    regs = {i: bytes(48) for i in range(1, 5)}
    for mr, kind, payload in events:
        blob, digest = event(mr, kind, payload)
        log += blob
        regs[mr] = hashlib.sha384(regs[mr] + digest).digest()
    return log, regs


def quote(regs, report_data=bytes(64), mrtd=b"\x11" * 48):
    body = bytearray(584)
    body[136:184] = mrtd
    for i in range(4):
        body[328 + 48 * i: 376 + 48 * i] = regs[i + 1]
    body[520:584] = report_data
    header = struct.pack("<HHIHH", 4, 2, 0x81, 0, 0) + bytes(36)
    return header + bytes(body) + struct.pack("<I", 4) + bytes(4)


EVENTS = [(1, HOB, b"td hob"), (1, CFV, b"the CFV"), (1, VAR, b"SecureBoot"), (1, VAR, b"PK"), (1, EV_SEPARATOR, bytes(4)),
          (2, 0x80000007, b"Calling EFI Application from Boot Option"), (2, 0x80000003, b"uki")]


def test_capture_and_template():
    log, regs = build(EVENTS)
    nonce = bytes(range(32))
    out = capture.capture(quote(regs, capture.capture_report_data(nonce)), log, nonce=nonce)
    assert out["registers"]["rtmr0"] == regs[1].hex() and out["registers"]["rtmr3"] == "0" * 96
    assert out["cfv_sha384"] == hashlib.sha384(b"the CFV").hexdigest()
    assert out["rtmr0_template"]["before_cfv"] == hashlib.sha384(bytes(48) + hashlib.sha384(b"td hob").digest()).hexdigest()
    assert len(out["rtmr0_template"]["after_cfv"]) == 3
    assert fold(out["rtmr0_template"], out["cfv_sha384"]) == out["registers"]["rtmr0"]


def test_a_log_that_does_not_replay_is_refused():
    log, regs = build(EVENTS)
    regs[2] = hashlib.sha384(b"other").digest()
    with pytest.raises(capture.CaptureRefused, match="RTMR1"):
        capture.capture(quote(regs), log)


def test_wrong_capture_nonce_is_refused():
    log, regs = build(EVENTS)
    with pytest.raises(capture.CaptureRefused, match="REPORTDATA"):
        capture.capture(quote(regs, capture.capture_report_data(bytes(32))), log, nonce=b"\x01" * 32)


def test_serial_line():
    log, regs = build(EVENTS)
    q = quote(regs)
    line = "CHUTES-CAPTURE-V1 " + base64.b64encode(json.dumps({"quote": base64.b64encode(q).decode(),
                                                              "ccel": base64.b64encode(log).decode()}).encode()).decode()
    assert capture.parse_serial_line(line + "\n") == (q, log)
    with pytest.raises(capture.CaptureRefused):
        capture.parse_serial_line("CHUTES-CAPTURE-V0 x")


# ---- the quote's signature and the nonce: a quote is bytes anyone can write.

NONCE = bytes(range(32))


class Verdict:
    # td_attributes: SEPT_VE_DISABLE (bit 28) only, little-endian bytes as dcap-qvl writes them.
    passed, checks, status, td10 = True, [], "UpToDate", {"td_attributes": "0000001000000000"}


def intel(verdict=Verdict, error=None):
    """A stand-in for Intel DCAP (``verify.Verifiers.quote``) and the quotes it was asked about."""
    asked = []

    async def verify_quote(raw):
        asked.append(raw)
        if error is not None:
            raise error
        return verdict()
    return verify_quote, asked


def written():
    """A quote and a CCEL that agree with each other and with NONCE: no TD is needed to write them."""
    log, regs = build(EVENTS)
    return quote(regs, capture.capture_report_data(NONCE)), log


def test_a_verified_capture_names_intels_verdict_and_the_nonce():
    q, log = written()
    verify_quote, asked = intel()
    out = capture.capture(q, log, nonce=NONCE, verify_quote=verify_quote)
    assert out["quote_verification"] == {"intel_dcap": "UpToDate", "nonce": NONCE.hex()} and asked == [q]
    # Without the verifier the same bytes are read, and the output says nothing verified them.
    assert capture.capture(q, log, nonce=NONCE)["quote_verification"] is None


def test_a_quote_intel_did_not_sign_is_refused():
    q, log = written()
    verify_quote, _ = intel(error=tdx_verify.TdxQuoteRejected("signature invalid"))
    with pytest.raises(capture.CaptureRefused, match="Intel DCAP refuses the quote: signature invalid"):
        capture.capture(q, log, nonce=NONCE, verify_quote=verify_quote)


def test_no_verdict_from_intel_is_not_a_capture():
    q, log = written()
    verify_quote, _ = intel(error=tdx_verify.VerifierUnavailable("Intel PCS did not answer"))
    with pytest.raises(capture.CaptureUnavailable, match="no verdict"):
        capture.capture(q, log, nonce=NONCE, verify_quote=verify_quote)


def test_a_verified_capture_needs_the_nonce_and_intel_is_asked_last():
    q, log = written()
    verify_quote, asked = intel()
    with pytest.raises(capture.CaptureRefused, match="needs the capture nonce"):
        capture.capture(q, log, verify_quote=verify_quote)
    with pytest.raises(capture.CaptureRefused, match="REPORTDATA"):
        capture.capture(q, log, nonce=b"\x01" * 32, verify_quote=verify_quote)
    assert asked == []


class OutOfDate(Verdict):
    passed, checks, status = False, [tdx_policy.PolicyCheck("tcb_status", False, "OutOfDate")], "OutOfDate"


class Debug(Verdict):
    td10 = {"td_attributes": "0100001000000000"}


class NoAttributes(Verdict):
    td10 = {}


@pytest.mark.parametrize("verdict,why", [(OutOfDate, "tcb_status"), (Debug, "TD attributes"), (NoAttributes, "TD attributes")])
def test_a_verdict_the_policy_refuses_is_refused(verdict, why):
    q, log = written()
    with pytest.raises(capture.CaptureRefused, match=f"Intel DCAP refuses the quote: .*{why}"):
        capture.capture(q, log, nonce=NONCE, verify_quote=intel(verdict)[0])
