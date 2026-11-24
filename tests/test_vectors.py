"""The test vectors (spec/vectors): measurements.json (16 document cases, 17 match cases, 4 key
proofs), rtmr0_template.json, quote.json and reportdata.json, through this package."""

import base64
import hashlib
import json
import os

import pytest

from chutes_tdx_measure import document, verify
from chutes_tdx_measure.match import fold, match
from chutes_tdx_measure.vendor.chutes_attest import gcp_tdx_provenance, quote as quote_parser

VECTORS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spec", "vectors")


def load(name):
    with open(os.path.join(VECTORS, name), "rb") as stream:
        return json.load(stream)


def test_sha256sums():
    with open(os.path.join(VECTORS, "SHA256SUMS")) as stream:
        for digest, name in (line.split() for line in stream if line.strip()):
            with open(os.path.join(VECTORS, name), "rb") as f:
                assert hashlib.sha256(f.read()).hexdigest() == digest, name


M = load("measurements.json")
KEYS = {name: base64.b64decode(k["public_key_b64"]) for name, k in M["keys"].items()}


@pytest.mark.parametrize("case", M["document_cases"], ids=[c["name"] for c in M["document_cases"]])
def test_document_cases(case):
    assert len(M["document_cases"]) == 16
    raw = base64.b64decode(case["document_b64"])
    assert hashlib.sha256(raw).hexdigest() == case["document_sha256"]
    try:
        entries = document.parse_document(raw, case["signature_b64"], KEYS[case["verify_with"]], case["endpoint_image_sha256"])
        got = {"entries": len(entries)}
    except document.DocumentRefused as exc:
        got = {"refused": exc.code}
    assert got == case["expect"]


@pytest.mark.parametrize("case", M["match_cases"], ids=[c["name"] for c in M["match_cases"]])
def test_match_cases(case):
    assert len(M["match_cases"]) == 17
    parsed = []
    for doc in case["documents"]:
        try:
            parsed.append(document.parse_document(base64.b64decode(doc["document_b64"]), doc["signature_b64"],
                                                  KEYS["measurement-key-1"], M["image_sha256"]))
        except document.DocumentRefused:
            parsed.append(None)
    result = match(parsed, case["endpoint_machine_type"], case["observed"], case["admitted_build_cfvs"])
    got = {"accepted": {"document": result[0], "entry": result[1]}} if isinstance(result, tuple) else {"refused": result}
    assert got == case["expect"]


@pytest.mark.parametrize("case", M["key_proofs"], ids=[c["name"] for c in M["key_proofs"]])
def test_key_proofs(case):
    assert len(M["key_proofs"]) == 4
    assert document.proof_message(case["user_id"], case["archive_sha256"]).hex() == case["message_hex"] or \
        case["name"] == "the proof of another account"
    ok = document.verify_proof(KEYS[case["verify_with"]], case["user_id"], case["archive_sha256"], case["proof_b64"])
    assert ok == (case["expect"] == "accepted")


def test_key_proof_made_by_this_tool():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(M["keys"]["measurement-key-1"]["ed25519_private_seed_hex"]))
    proof = document.sign_proof(key, M["key_proofs"][0]["user_id"], M["image_sha256"])
    assert proof == M["key_proofs"][0]["proof_b64"]  # Ed25519 is deterministic
    assert document.public_b64(key) == M["keys"]["measurement-key-1"]["public_key_b64"]
    assert document.fingerprint(document.public_raw(key)) == M["keys"]["measurement-key-1"]["fingerprint_sha256"]


def test_rtmr0_templates():
    cases = load("rtmr0_template.json")["cases"]
    assert len(cases) == 3
    for case in cases:
        assert fold(case["template"], case["cfv_sha384"]) == case["rtmr0"]


def test_quote_vectors():
    q = load("quote.json")
    assert len(q["quotes"]) == 4
    regs = q["registers_hex"]
    rd = load("reportdata.json")
    for entry in q["quotes"]:
        raw = base64.b64decode(entry["quote_b64"])
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        parsed = quote_parser.parse_quote(raw)
        offsets = q["layout"]["absolute_offsets"]
        assert raw[offsets["mrtd"][0]:offsets["mrtd"][1]].hex() == parsed.mrtd.lower() == regs["mrtd"]
        assert parsed.rtmr3.lower() == regs["rtmr3"] and parsed.mr_owner.lower() == q["mr_owner_hex"]
        assert parsed.report_data.lower() == rd["cases"][0]["report_data_hex"]
        assert verify._debug(raw) == (entry["name"] == "debug")
        assert (parsed.mr_config_id != "0" * 96) == (entry["name"] == "mr_config_id set")
        assert (parsed.mr_owner_config != "0" * 96) == (entry["name"] == "mr_owner_config set")
    inst = gcp_tdx_provenance.Instance(int(q["instance"]["project_number"]), q["instance"]["zone"], int(q["instance"]["instance_id"]))
    assert gcp_tdx_provenance.pzid_payload(inst).decode() == q["pzid"]
    assert gcp_tdx_provenance.pzid_mr_owner(inst).lower() == q["mr_owner_hex"]
    v5 = bytearray(base64.b64decode(q["quotes"][0]["quote_b64"]))
    v5[0] = 5
    with pytest.raises(quote_parser.QuoteParseError):
        quote_parser.parse_quote(bytes(v5))


def test_reportdata_vectors():
    v = load("reportdata.json")
    keys = {name: base64.b64decode(k["public_key_b64"]) for name, k in v["keys"].items()}
    for case in v["cases"]:
        assert verify.attest_report_data(bytes.fromhex(case["nonce_hex"]), keys[case["public_key"]]).hex() == case["report_data_hex"]
    first = v["cases"][0]["report_data_hex"]
    assert all(w["report_data_hex"] != first for w in v["wrong_forms_for_cases_0"])
