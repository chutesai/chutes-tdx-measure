"""verify-quote's rows on the synthetic quotes of quote.json, with the network verifiers (Intel's
collateral, Google's bucket and registry) injected."""

import base64
import json
import os

import pytest

from chutes_tdx_measure import document, firmware, verify
from chutes_tdx_measure.vendor.chutes_attest import gcp_tdx_provenance, tdx_verify
from intel_testkit import collateral_document, issued_now, other_chains, pin, serve

VECTORS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spec", "vectors")


def load(name):
    with open(os.path.join(VECTORS, name), "rb") as stream:
        return json.load(stream)


Q, M, RD = load("quote.json"), load("measurements.json"), load("reportdata.json")
QUOTES = {q["name"]: base64.b64decode(q["quote_b64"]) for q in Q["quotes"]}
EXACT = next(c for c in M["document_cases"] if c["name"] == "exact form, two machine types")
FOLLOW = next(c for c in M["document_cases"] if c["name"] == "firmware-following form")
KEY = base64.b64decode(M["keys"]["measurement-key-1"]["public_key_b64"])


class Verdict:
    # td_attributes: SEPT_VE_DISABLE (bit 28) only, little-endian bytes as dcap-qvl writes them.
    passed, checks, status, td10 = True, [], "UpToDate", {"td_attributes": "0000001000000000"}


class VerdictWithoutAttributes(Verdict):
    td10 = {}


async def quote_ok(raw):
    return Verdict()


async def quote_unavailable(raw):
    raise tdx_verify.VerifierUnavailable("Intel PCS did not answer")


async def quote_rejected(raw):
    raise tdx_verify.TdxQuoteRejected("signature invalid")


async def provenance_pzid(raw, inst):
    """Google's provenance with the registry faked: the real PZID check, then a pass."""
    if gcp_tdx_provenance.quote_mr_owner(raw) != gcp_tdx_provenance.pzid_mr_owner(inst):
        raise gcp_tdx_provenance.ProvenanceRefused("pzid_mismatch", "another instance")

    class P:
        def detail(self):
            return "fake registry"
    return P()


async def provenance_unavailable(raw, inst):
    raise gcp_tdx_provenance.ProvenanceUnavailable("timeout")


def inputs(**over):
    base = dict(
        quote=QUOTES["plain"], expected_report_data=bytes.fromhex(RD["cases"][0]["report_data_hex"]),
        documents=[(base64.b64decode(EXACT["document_b64"]), EXACT["signature_b64"])], measurement_key=KEY,
        image_sha256=M["image_sha256"], machine_type="c3-standard-4", project_number=Q["instance"]["project_number"],
        zone=Q["instance"]["zone"], instance_id=Q["instance"]["instance_id"],
        allowed_projects=(Q["instance"]["project_number"],))
    base.update(over)
    return verify.Inputs(**base)


def verifiers(**over):
    base = dict(quote=quote_ok, admission=lambda mrtd, floor, need: firmware.Admission(True, (M["build_cfvs"]["A"],)), provenance=provenance_pzid)
    base.update(over)
    return verify.Verifiers(**base)


def rows(result):
    return {r["row"]: (r["status"], r["code"]) for r in result["rows"]}


def test_all_rows_pass():
    result = verify.run(inputs(), verifiers())
    assert result["pass"], result["rows"]
    assert [r["row"] for r in result["rows"]] == ["quote", "binding", "platform", "measurements", "provider_root"]
    assert result["match"] == {"document": 0, "entry": 0}


def test_binding_and_nonce_key_rule():
    nonce = bytes.fromhex(RD["cases"][0]["nonce_hex"])
    key = base64.b64decode(RD["keys"]["vm-1"]["public_key_b64"])
    assert verify.attest_report_data(nonce, key) == inputs().expected_report_data
    result = verify.run(inputs(expected_report_data=verify.attest_report_data(nonce, key[::-1])), verifiers())
    assert rows(result)["binding"] == ("fail", "endpoint_vm_binding_mismatch")
    assert rows(result)["provider_root"][0] == "not_run" and not result["pass"]


@pytest.mark.parametrize("name,code", [("debug", "endpoint_vm_quote_refused")])
def test_debug_refused(name, code):
    result = verify.run(inputs(quote=QUOTES[name]), verifiers())
    assert rows(result)["quote"] == ("fail", code)


def test_quote_verifier_outcomes():
    assert rows(verify.run(inputs(), verifiers(quote=quote_rejected)))["quote"] == ("fail", "endpoint_vm_quote_refused")
    result = verify.run(inputs(), verifiers(quote=quote_unavailable))
    assert rows(result)["quote"] == ("incomplete", "endpoint_check_incomplete")
    assert rows(result)["provider_root"][0] == "not_run"


# A verdict without TD attributes cannot show debug is off: refused.
def test_missing_td_attributes_refused():
    async def no_attributes(raw):
        return VerdictWithoutAttributes()
    assert rows(verify.run(inputs(), verifiers(quote=no_attributes)))["quote"] == ("fail", "endpoint_vm_quote_refused")


# An unproven quote's MRTD is never looked up in Google's firmware index.
def test_no_firmware_lookup_for_an_unproven_quote():
    asked = []

    def admission(mrtd, floor, need):
        asked.append(mrtd)
        return firmware.Admission(True, (M["build_cfvs"]["A"],))
    result = verify.run(inputs(expected_report_data=bytes(64)), verifiers(admission=admission))
    assert rows(result)["binding"][0] == "fail" and rows(result)["measurements"] == ("not_run", "endpoint_check_incomplete")
    result = verify.run(inputs(), verifiers(quote=quote_rejected, admission=admission))
    assert rows(result)["measurements"][0] == "not_run"
    assert asked == []
    assert verify.run(inputs(), verifiers(admission=admission))["pass"] and len(asked) == 1


def test_platform_pins():
    # No pin at all: the project the VM names is never its own pin.
    assert rows(verify.run(inputs(allowed_projects=()), verifiers()))["platform"][0] == "fail"
    assert rows(verify.run(inputs(allowed_projects=("111111111111",)), verifiers()))["platform"][0] == "fail"
    assert rows(verify.run(inputs(allowed_regions=("us-east4",)), verifiers()))["platform"][0] == "fail"
    assert rows(verify.run(inputs(allowed_machine_types=("c3-standard-8",)), verifiers()))["platform"][0] == "fail"
    ok = verify.run(inputs(allowed_projects=(Q["instance"]["project_number"],), allowed_regions=("us-central1",),
                           allowed_machine_types=("c3-standard-4",)), verifiers())
    assert ok["pass"]


def test_measurement_outcomes():
    bad_sig = [(base64.b64decode(EXACT["document_b64"]), FOLLOW["signature_b64"])]
    assert rows(verify.run(inputs(documents=bad_sig), verifiers()))["measurements"] == ("fail", "endpoint_vm_measurements_unsigned")
    assert rows(verify.run(inputs(), verifiers(admission=lambda m, f, need: firmware.Admission(False, ()))))["measurements"] == ("fail", "endpoint_vm_firmware_refused")
    assert rows(verify.run(inputs(machine_type="c3-standard-16"), verifiers()))["measurements"] == ("fail", "endpoint_vm_measurements_unmatched")
    assert rows(verify.run(inputs(image_sha256="0" * 64), verifiers()))["measurements"] == ("fail", "endpoint_vm_measurements_unsigned")

    def unavailable(mrtd, floor, need):
        raise firmware.FirmwareUnavailable("Google's bucket did not answer")
    assert rows(verify.run(inputs(), verifiers(admission=unavailable)))["measurements"] == ("incomplete", "endpoint_check_incomplete")
    # Documents under another key are not this owner's.
    other = base64.b64decode(M["keys"]["measurement-key-2"]["public_key_b64"])
    assert rows(verify.run(inputs(measurement_key=other), verifiers()))["measurements"][1] == "endpoint_vm_measurements_unsigned"


def test_provider_root():
    for name in ("mr_config_id set", "mr_owner_config set"):
        assert rows(verify.run(inputs(quote=QUOTES[name]), verifiers()))["provider_root"] == ("fail", "endpoint_vm_provider_refused")
    other_instance = verify.run(inputs(instance_id="5813945712345678902"), verifiers())
    assert rows(other_instance)["provider_root"] == ("fail", "endpoint_vm_provider_refused")
    other_project = verify.run(inputs(project_number="111111111111", allowed_projects=("111111111111",)), verifiers())
    assert rows(other_project)["provider_root"] == ("fail", "endpoint_vm_provider_refused")
    assert rows(verify.run(inputs(), verifiers(provenance=provenance_unavailable)))["provider_root"] == (
        "incomplete", "endpoint_check_incomplete")


def test_the_real_provenance_refuses_a_quote_without_a_pck_chain():
    import datetime as dt

    async def real(raw, inst):
        return await gcp_tdx_provenance.verify(raw, inst, now=dt.datetime(2026, 11, 16, tzinfo=dt.timezone.utc),
                                               fetch=lambda *a: (_ for _ in ()).throw(AssertionError("registry asked")))
    result = verify.run(inputs(), verifiers(provenance=real))
    assert rows(result)["provider_root"] == ("fail", "endpoint_vm_provider_refused")


# ---- the collateral's signers: the default quote verifier judges them, whichever service
# answered, before the vendored verifier (which accepts any certificate under Intel's root).

@pytest.mark.parametrize("source", [None, "phala-pccs", "https://pccs.example/"])
def test_the_default_quote_verifier_refuses_collateral_intel_did_not_sign(monkeypatch, source):
    pki = pin(monkeypatch)
    genuine = collateral_document(pki.signer_chain, pki.signer_chain, issued=issued_now())
    asked, handed = serve(monkeypatch, genuine)
    result = verify.run(inputs(), verifiers(quote=verify.default_verifiers(collateral_source=source).quote))
    assert result["pass"], result["rows"]
    assert asked == [(QUOTES["plain"], source or "intel-pcs")] and [h[:2] for h in handed] == [
        (QUOTES["plain"], json.dumps(genuine, sort_keys=True, separators=(",", ":")))]
    # The same service with a TCB Info signed by a platform's PCK certificate: refused.
    forged = collateral_document(other_chains(pki)["a-pck-certificate"], pki.signer_chain, issued=issued_now())
    asked, handed = serve(monkeypatch, forged)
    result = verify.run(inputs(), verifiers(quote=verify.default_verifiers(collateral_source=source).quote))
    quote_row = result["rows"][0]
    assert (quote_row["row"], quote_row["status"], quote_row["code"]) == ("quote", "fail", "endpoint_vm_quote_refused")
    assert quote_row["detail"] == (f"the TDX collateral from {source or 'intel-pcs'} is not Intel's: the TCB Info is "
                                   "signed by 'Intel SGX PCK Certificate', not by 'Intel SGX TCB Signing'")
    assert not result["pass"] and rows(result)["measurements"][0] == "not_run" and len(asked) == 1 and handed == []
