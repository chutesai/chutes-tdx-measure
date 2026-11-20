"""The command line, end to end: key create, key proof, write, sign, verify-document, verify-quote."""

import base64
import json
import os
import stat

import pytest

from chutes_tdx_measure import capture, cli, document, firmware, verify
from intel_testkit import collateral_document, issued_now, other_chains, pin, serve
from test_capture import NONCE, written
from test_verify import M, Q, RD, QUOTES, quote_ok, quote_rejected, quote_unavailable, provenance_pzid


DEFAULT_VERIFIERS = verify.default_verifiers  # the real one: the fixtures below replace it


def run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_key_document_round_trip(tmp_path, capsys):
    key = tmp_path / "key.pem"
    code, out, _ = run(["key", "create", "--out", str(key)], capsys)
    assert code == 0 and stat.S_IMODE(os.stat(key).st_mode) == 0o600
    public = out.split("register this): ")[1].split()[0]
    fingerprint = out.split("out of band): ")[1].split()[0]
    assert document.fingerprint(base64.b64decode(public)) == fingerprint
    assert run(["key", "create", "--out", str(key)], capsys)[0] == 2  # never overwrites a key

    image = "ab" * 32
    code, out, _ = run(["key", "proof", "--key", str(key), "--user-id", "u-1", "--archive-sha256", image], capsys)
    assert code == 0 and document.verify_proof(base64.b64decode(public), "u-1", image, out.strip())
    code, out, _ = run(["key", "proof", "--user-id", "u-1", "--archive-sha256", image, "--print-message"], capsys)
    assert out.encode() == b"chutes-tdx-measurement-key-proof-v1\x00u-1\x00" + image.encode()

    entries = tmp_path / "entries.json"
    entries.write_text(json.dumps([{"machine_type": "c3-standard-4", "mrtd": "11" * 48, "rtmr0": "22" * 48,
                                    "rtmr1": "33" * 48, "rtmr2": "44" * 48, "rtmr3": None}]))
    doc, sig = tmp_path / "m.json", tmp_path / "m.json.sig"
    assert run(["write", "--image-sha256", image, "--entries", str(entries), "-o", str(doc)], capsys)[0] == 0
    assert doc.read_bytes().endswith(b"}\n") and b'\n  "type"' in doc.read_bytes()
    assert run(["sign", "--key", str(key), str(doc), "-o", str(sig)], capsys)[0] == 0
    assert len(base64.b64decode(sig.read_text())) == 64 and not sig.read_text().endswith("\n")
    code, out, _ = run(["verify-document", "--public-key", public, "--image-sha256", image, str(doc), str(sig)], capsys)
    assert code == 0 and "valid: 1 entry" in out
    # A signature file with a trailing newline (as an editor saves it) is the same signature.
    sig_nl = tmp_path / "m.json.sig.nl"
    sig_nl.write_text(sig.read_text() + "\n")
    code, out, _ = run(["verify-document", "--public-key", public, "--image-sha256", image, str(doc), str(sig_nl)], capsys)
    assert code == 0 and "valid: 1 entry" in out
    # key proof without --key and without --print-message: a clear refusal, not a traceback.
    with pytest.raises(SystemExit, match="--key"):
        run(["key", "proof", "--user-id", "u-1", "--archive-sha256", image], capsys)
    code, out, _ = run(["verify-document", "--public-key", public, "--image-sha256", "cd" * 32, str(doc), str(sig)], capsys)
    assert code == 1 and "document_image_mismatch" in out
    doc.write_bytes(doc.read_bytes() + b" ")
    code, out, _ = run(["verify-document", "--public-key", public, "--image-sha256", image, str(doc), str(sig)], capsys)
    assert code == 1 and "document_signature_invalid" in out


def test_write_refuses_a_bad_entry(tmp_path, capsys):
    entries = tmp_path / "e.json"
    entries.write_text(json.dumps([{"machine_type": "c3-standard-4", "mrtd": "11" * 48, "rtmr0": "22" * 48,
                                    "rtmr1": "33" * 48, "rtmr2": "44" * 48}]))  # rtmr3 missing
    assert run(["write", "--image-sha256", "ab" * 32, "--entries", str(entries), "-o", str(tmp_path / "m")], capsys)[0] == 2


@pytest.fixture
def quote_files(tmp_path, monkeypatch):
    monkeypatch.setattr(verify, "default_verifiers", lambda **kw: verify.Verifiers(
        quote=quote_ok, admission=lambda m, f, need: firmware.Admission(True, (M["build_cfvs"]["A"],)), provenance=provenance_pzid))
    exact = next(c for c in M["document_cases"] if c["name"] == "exact form, two machine types")
    (tmp_path / "q").write_bytes(QUOTES["plain"])
    (tmp_path / "d").write_bytes(base64.b64decode(exact["document_b64"]))
    (tmp_path / "s").write_text(exact["signature_b64"])
    (tmp_path / "ek").write_text(RD["keys"]["vm-1"]["public_key_b64"])
    return tmp_path


def quote_args(p, **over):
    args = {"--quote": str(p / "q"), "--nonce": RD["cases"][0]["nonce_hex"], "--public-key-file": str(p / "ek"),
            "--documents": str(p / "d"), "--signatures": str(p / "s"),
            "--measurement-key": M["keys"]["measurement-key-1"]["public_key_b64"], "--image-sha256": M["image_sha256"],
            "--machine-type": "c3-standard-4", "--gce-project": Q["instance"]["project_number"],
            "--allowed-project": Q["instance"]["project_number"],
            "--zone": Q["instance"]["zone"], "--instance-id": Q["instance"]["instance_id"]}
    args.update(over)
    out = ["verify-quote", "--json"]
    for k, v in args.items():
        if v is not None:
            out += [k, v]
    return out


def test_verify_quote_cli(quote_files, capsys):
    code, out, _ = run(quote_args(quote_files), capsys)
    result = json.loads(out)
    assert code == 0 and result["pass"]
    code, out, _ = run(quote_args(quote_files, **{"--instance-id": "5813945712345678902"}), capsys)
    assert code == 1 and not json.loads(out)["pass"]
    # The key-service form: the expected REPORTDATA in place of nonce and key.
    code, out, _ = run(quote_args(quote_files, **{"--nonce": None, "--public-key-file": None,
                                                  "--report-data": RD["cases"][0]["report_data_hex"]}), capsys)
    assert code == 0
    code, out, _ = run(quote_args(quote_files, **{"--nonce": None, "--public-key-file": None,
                                                  "--report-data": "00" * 64}), capsys)
    assert code == 1
    # The quote on stdin, as base64 (how the reference key service passes it).
    import io
    import sys
    stdin = io.TextIOWrapper(io.BytesIO(base64.b64encode(QUOTES["plain"])))
    old = sys.stdin
    sys.stdin = stdin
    try:
        code, out, _ = run(quote_args(quote_files, **{"--quote": "-"}), capsys)
    finally:
        sys.stdin = old
    assert code == 0


def test_verify_quote_platform_document(quote_files, capsys):
    platform = {"schema": "chutes.cvm-platform.v1", "provider": "gcp", "tee_type": "tdx",
                "project_numbers": ["111111111111"], "regions": ["us-central1"], "machine_types": ["c3-standard-4"],
                "firmware_floor": {"min_cl_spec": 957008435, "min_svn": 2, "denied_builds": []}}
    (quote_files / "p.json").write_text(json.dumps(platform))
    code, out, _ = run(quote_args(quote_files, **{"--platform": str(quote_files / "p.json")}), capsys)
    rows = {r["row"]: r for r in json.loads(out)["rows"]}
    assert code == 1 and rows["platform"]["code"] == "endpoint_vm_platform_mismatch"


# The pin is required: --gce-project is the VM's claim.
def test_verify_quote_needs_a_pin(quote_files, capsys):
    with pytest.raises(SystemExit, match="allowed-project"):
        run(quote_args(quote_files, **{"--allowed-project": None}), capsys)
    code, out, _ = run(quote_args(quote_files, **{"--allowed-project": "111111111111"}), capsys)
    assert code == 1 and {r["row"]: r for r in json.loads(out)["rows"]}["platform"]["code"] == "endpoint_vm_platform_mismatch"
    # With --platform too, a project must be in both pins.
    platform = {"schema": "chutes.cvm-platform.v1", "provider": "gcp", "tee_type": "tdx",
                "project_numbers": [Q["instance"]["project_number"]], "regions": ["us-central1"],
                "machine_types": ["c3-standard-4"], "firmware_floor": {"min_cl_spec": 957008435, "min_svn": 2, "denied_builds": []}}
    (quote_files / "pin.json").write_text(json.dumps(platform))
    code, out, _ = run(quote_args(quote_files, **{"--platform": str(quote_files / "pin.json")}), capsys)
    assert code == 0
    code, out, _ = run(quote_args(quote_files, **{"--platform": str(quote_files / "pin.json"), "--allowed-project": "111111111111"}), capsys)
    assert code == 1 and {r["row"]: r for r in json.loads(out)["rows"]}["platform"]["code"] == "endpoint_vm_platform_mismatch"


# --floor and --platform's floor both apply: each minimum's maximum, every denied build.
def test_verify_quote_floors_combine(quote_files, capsys):
    project = Q["instance"]["project_number"]
    floor = {"min_cl_spec": 957008435, "min_svn": 2, "denied_builds": []}
    platform = {"schema": "chutes.cvm-platform.v1", "provider": "gcp", "tee_type": "tdx",
                "project_numbers": [project], "regions": ["us-central1"], "machine_types": ["c3-standard-4"],
                "firmware_floor": {"min_cl_spec": 957008435, "min_svn": 2, "denied_builds": ["ab" * 48]}}
    (quote_files / "f.json").write_text(json.dumps(floor))
    (quote_files / "p.json").write_text(json.dumps(platform))
    seen = []
    import chutes_tdx_measure.verify as verify_module
    real = verify_module.run

    def spy(inputs, verifiers):
        seen.append(inputs.floor)
        return real(inputs, verifiers)
    verify_module.run = spy
    try:
        run(quote_args(quote_files, **{"--floor": str(quote_files / "f.json"), "--platform": str(quote_files / "p.json"),
                                       "--allowed-project": None}), capsys)
    finally:
        verify_module.run = real
    assert seen and seen[0].denied_builds == frozenset({"ab" * 48})


# capture: the quote verified with Intel DCAP and bound to the caller's nonce by default.
@pytest.fixture
def capture_files(tmp_path):
    q, log = written()
    (tmp_path / "q").write_bytes(q)
    (tmp_path / "c").write_text(base64.b64encode(log).decode())
    (tmp_path / "line").write_text("CHUTES-CAPTURE-V1 " + base64.b64encode(json.dumps(
        {"quote": base64.b64encode(q).decode(), "ccel": base64.b64encode(log).decode()}).encode()).decode() + "\n")
    return tmp_path


def intel_is(monkeypatch, quote):
    asked = []

    def default_verifiers(**kw):
        asked.append(kw)
        return verify.Verifiers(quote=quote)
    monkeypatch.setattr(verify, "default_verifiers", default_verifiers)
    return asked


def test_capture_verifies_the_quote_and_binds_the_nonce(capture_files, capsys, monkeypatch):
    asked = intel_is(monkeypatch, quote_ok)
    files = ["--quote", str(capture_files / "q"), "--ccel", str(capture_files / "c")]
    code, out, err = run(["capture", *files, "--nonce", NONCE.hex()], capsys)
    assert code == 0 and json.loads(out)["quote_verification"] == {"intel_dcap": "UpToDate", "nonce": NONCE.hex()}
    # Intel's own service, whatever the environment names.
    assert asked == [{"collateral_source": "intel-pcs"}]
    assert err.strip() == capture.NOTICE.format(status="UpToDate")
    assert "Compare RTMR1 and RTMR2 with your own `predict` output for your own archive before you sign anything" in err
    code, out, _ = run(["capture", "--serial-line", str(capture_files / "line"), "--nonce", NONCE.hex()], capsys)
    assert code == 0 and json.loads(out)["quote_verification"]["intel_dcap"] == "UpToDate"
    # No nonce: nothing binds the quote to this run of the command, so it is not read as verified.
    with pytest.raises(SystemExit, match="--nonce"):
        run(["capture", *files], capsys)
    code, out, err = run(["capture", *files, "--nonce", "01" * 32], capsys)
    assert (code, out) == (2, "") and "REPORTDATA is not the capture rule over this nonce" in err


@pytest.mark.parametrize("quote,why", [(quote_rejected, "Intel DCAP refuses the quote: signature invalid"),
                                       (quote_unavailable, "Intel DCAP reached no verdict on the quote")])
def test_capture_prints_no_registers_for_a_quote_intel_does_not_verify(capture_files, capsys, monkeypatch, quote, why):
    intel_is(monkeypatch, quote)
    code, out, err = run(["capture", "--quote", str(capture_files / "q"), "--ccel", str(capture_files / "c"),
                          "--nonce", NONCE.hex()], capsys)
    assert (code, out) == (2, "") and why in err


def test_capture_unverified_says_so(capture_files, capsys, monkeypatch):
    asked = intel_is(monkeypatch, quote_rejected)
    code, out, err = run(["capture", "--quote", str(capture_files / "q"), "--ccel", str(capture_files / "c"),
                          "--unverified"], capsys)
    assert code == 0 and json.loads(out)["quote_verification"] is None and asked == []
    assert err.strip() == capture.NOTICE_UNVERIFIED and "NOT VERIFIED" in err and "Do not sign them" in err


# The collateral's signers: capture and verify-quote both judge them before Intel's verifier,
# capture from Intel's own service and verify-quote from whichever service is named.
def test_capture_refuses_collateral_intel_did_not_sign(capture_files, capsys, monkeypatch):
    pki = pin(monkeypatch)
    monkeypatch.setenv("TDX_COLLATERAL_SOURCE", "https://pccs.example/")
    argv = ["capture", "--quote", str(capture_files / "q"), "--ccel", str(capture_files / "c"), "--nonce", NONCE.hex()]
    forged = collateral_document(pki.signer_chain, other_chains(pki)["platform-ca"], issued=issued_now())
    asked, handed = serve(monkeypatch, forged)
    code, out, err = run(argv, capsys)
    assert (code, out) == (2, "") and handed == [] and [source for _, source in asked] == ["intel-pcs"]
    assert ("Intel DCAP refuses the quote: the TDX collateral from intel-pcs is not Intel's: the QE Identity is signed "
            "by 'Intel SGX PCK Platform CA', not by 'Intel SGX TCB Signing'") in err
    asked, handed = serve(monkeypatch, collateral_document(pki.signer_chain, pki.signer_chain, issued=issued_now()))
    code, out, err = run(argv, capsys)
    assert code == 0 and json.loads(out)["quote_verification"]["intel_dcap"] == "UpToDate" and len(handed) == 1


def test_verify_quote_refuses_collateral_intel_did_not_sign(quote_files, capsys, monkeypatch):
    pki = pin(monkeypatch)
    monkeypatch.setattr(verify, "default_verifiers", lambda **kw: verify.Verifiers(
        quote=DEFAULT_VERIFIERS(**kw).quote, admission=lambda m, f, need: firmware.Admission(True, (M["build_cfvs"]["A"],)),
        provenance=provenance_pzid))
    argv = quote_args(quote_files, **{"--collateral-source": "https://pccs.example/"})
    forged = collateral_document(other_chains(pki)["platform-ca"], pki.signer_chain, issued=issued_now())
    asked, handed = serve(monkeypatch, forged)
    code, out, _ = run(argv, capsys)
    quote_row = json.loads(out)["rows"][0]
    assert code == 1 and (quote_row["row"], quote_row["status"], quote_row["code"]) == (
        "quote", "fail", "endpoint_vm_quote_refused")
    assert "from https://pccs.example/ is not Intel's: the TCB Info is signed by" in quote_row["detail"]
    assert handed == [] and [source for _, source in asked] == ["https://pccs.example/"]
    asked, handed = serve(monkeypatch, collateral_document(pki.signer_chain, pki.signer_chain, issued=issued_now()))
    code, out, _ = run(argv, capsys)
    assert code == 0 and json.loads(out)["pass"] and len(handed) == 1
