"""``chutes-tdx-measure``: predict, capture, write, sign and verify TDX measurement documents
for Chutes' TDX VM endpoints. The Chutes client ships the same code as ``chutes tdx …``.

Exit status: 0 success (every row passed), 1 a decided refusal, 2 no verdict or a usage error.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys

from chutes_tdx_measure import __version__, capture, document, firmware, platform, predict, verify


def _out(value, path=None):
    text = json.dumps(value, indent=1) + "\n"
    if path:
        with open(path, "w") as stream:
            stream.write(text)
    else:
        sys.stdout.write(text)


def _read(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as stream:
        return stream.read()


def _raw_or_b64(data: bytes, size: int = None) -> bytes:
    """Raw bytes, or their base64 text (whitespace around it allowed)."""
    if size is not None and len(data) == size:
        return data
    try:
        decoded = base64.b64decode(data.strip(), validate=True)
        if size is None or len(decoded) == size:
            return decoded
    except (binascii.Error, ValueError):
        pass
    if size is None:
        return data
    raise SystemExit(f"expected {size} bytes or their base64")


def cmd_key_create(args):
    key = document.create_key(args.out)
    public = document.public_raw(key)
    print(f"public key (register this): {document.b64(public)}")
    print(f"fingerprint (confirm out of band): {document.fingerprint(public)}")


def cmd_key_proof(args):
    message = document.proof_message(args.user_id, args.archive_sha256)
    if args.print_message:
        sys.stdout.buffer.write(message)
        return
    if not args.key:
        raise SystemExit("give --key (the measurement key), or --print-message to sign elsewhere")
    print(document.sign_proof(document.load_key(args.key), args.user_id, args.archive_sha256))


def cmd_predict(args):
    data = platform.parse_platform_data(_read(args.platform_data)) if args.platform_data else None
    if args.inputs:
        result = predict.predict_inputs(json.loads(_read(args.inputs)), args.machine_type, data, secure_boot=args.secure_boot)
    else:
        result = predict.predict_uki(args.archive, args.machine_type, data)
    _out(result, args.output)


def cmd_capture(args):
    if args.serial_line:
        quote, ccel = capture.parse_serial_line(_read(args.serial_line).decode("ascii", "replace"))
    else:
        quote, ccel = _raw_or_b64(_read(args.quote)), _raw_or_b64(_read(args.ccel))
    nonce = bytes.fromhex(args.nonce) if args.nonce else None
    verifier = None
    if not args.unverified:
        if nonce is None:
            raise SystemExit("give --nonce (the capture nonce you set for your test boot): the quote is verified with "
                             "Intel DCAP and must carry it; or --unverified for registers nothing authenticates")
        # Intel's own service only, whatever TDX_COLLATERAL_SOURCE says. collateral.py checks the
        # signers from any source; capture's registers can end up signed, so no PCCS chooses which
        # of Intel's collateral they are verified under.
        verifier = verify.default_verifiers(collateral_source="intel-pcs").quote
    result = capture.capture(quote, ccel, nonce=nonce, verify_quote=verifier)
    _out(result, args.output)
    verification = result["quote_verification"]
    print(capture.NOTICE.format(status=verification["intel_dcap"]) if verification else capture.NOTICE_UNVERIFIED,
          file=sys.stderr)


def cmd_write(args):
    entries = json.loads(_read(args.entries))
    if isinstance(entries, dict) and "entries" in entries:
        entries = entries["entries"]  # a predict output
    raw = document.write_document(args.image_sha256, entries)
    with open(args.output, "wb") as stream:
        stream.write(raw)
    print(f"wrote {args.output} ({len(raw)} bytes, sha256 {hashlib.sha256(raw).hexdigest()})")


def cmd_sign(args):
    signature = document.sign_document(document.load_key(args.key), _read(args.document))
    with open(args.output, "w") as stream:
        stream.write(signature)


def cmd_verify_document(args):
    public = document.load_public(args.public_key)
    try:
        entries = document.parse_document(_read(args.document), _read(args.signature).decode("ascii").strip(), public,
                                          args.image_sha256)
    except document.DocumentRefused as exc:
        print(f"refused: {exc.code}")
        return 1
    print(f"valid: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}, key fingerprint {document.fingerprint(public)}")
    return 0


def cmd_verify_quote(args):
    quote = _raw_or_b64(_read(args.quote))
    if args.report_data:
        expected = bytes.fromhex(args.report_data)
        if len(expected) != 64:
            raise SystemExit("--report-data is 128 hex characters")
    else:
        if not (args.nonce and args.public_key_file):
            raise SystemExit("give --nonce and --public-key-file, or --report-data")
        expected = verify.attest_report_data(bytes.fromhex(args.nonce), _raw_or_b64(_read(args.public_key_file), 1184))
    if len(args.documents) != len(args.signatures):
        raise SystemExit("one signature per document")
    docs = [(_read(d), _read(s).decode("ascii").strip()) for d, s in zip(args.documents, args.signatures)]
    if not args.platform and not args.allowed_project:
        raise SystemExit("give the project pin: --allowed-project N (repeatable) or --platform (--gce-project is the "
                         "VM's claim, not a pin)")
    floors = [json.loads(_read(args.floor))] if args.floor else []
    allowed_projects, regions, machines = tuple(args.allowed_project or ()), (), ()
    if args.platform:
        pdoc = platform.parse_platform(_read(args.platform))
        pinned = tuple(pdoc["project_numbers"])
        # Both pins given: a project must satisfy both.
        allowed_projects = tuple(p for p in pinned if p in allowed_projects) if args.allowed_project else pinned
        regions, machines = tuple(pdoc["regions"]), tuple(pdoc["machine_types"])
        floors.append(pdoc["firmware_floor"])
    inputs = verify.Inputs(
        quote=quote, expected_report_data=expected, documents=docs,
        measurement_key=document.load_public(args.measurement_key), image_sha256=args.image_sha256,
        machine_type=args.machine_type, project_number=args.gce_project, zone=args.zone, instance_id=args.instance_id,
        allowed_projects=allowed_projects, allowed_regions=regions, allowed_machine_types=machines,
        floor=firmware.Floor.combine([firmware.Floor.from_document(f) for f in floors]))
    result = verify.run(inputs, verify.default_verifiers(firmware_dir=args.firmware_dir,
                                                         collateral_source=args.collateral_source))
    if args.json:
        _out(result)
    else:
        for row in result["rows"]:
            print(f"{row['row']:14} {row['status']:10} {row['code'] or ''}  {row['detail']}")
        print("PASS" if result["pass"] else "REFUSED")
    if result["pass"]:
        return 0
    return 2 if any(r["status"] in ("incomplete",) for r in result["rows"]) else 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="chutes-tdx-measure", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    key = sub.add_parser("key").add_subparsers(dest="key_command", required=True)
    k = key.add_parser("create", help="a new Ed25519 measurement key (PKCS#8 PEM, mode 0600)")
    k.add_argument("--out", required=True)
    k.set_defaults(func=cmd_key_create)
    k = key.add_parser("proof", help="the registration's proof of possession")
    k.add_argument("--key")
    k.add_argument("--user-id", required=True)
    k.add_argument("--archive-sha256", required=True)
    k.add_argument("--print-message", action="store_true", help="print the bytes to sign (for an HSM) instead")
    k.set_defaults(func=cmd_key_proof)

    k = sub.add_parser("predict", help="RTMR1 and RTMR2 from the archive; MRTD and RTMR0 from the platform data")
    k.add_argument("--archive", help="disk.tar.gz (or a raw disk)")
    k.add_argument("--inputs", help="a chutes.gcp-prediction-inputs.v1 manifest (shim and GRUB layouts)")
    k.add_argument("--secure-boot", action="store_true")
    k.add_argument("--platform-data")
    k.add_argument("--machine-type", required=True)
    k.add_argument("-o", "--output")
    k.set_defaults(func=cmd_predict)

    k = sub.add_parser("capture", help="the registers of a booted VM: its quote verified with Intel DCAP and bound "
                       "to your nonce, its CCEL replayed to them")
    k.add_argument("--quote")
    k.add_argument("--ccel")
    k.add_argument("--serial-line", help="a file holding the capture variant's CHUTES-CAPTURE-V1 line")
    k.add_argument("--nonce", help="the capture nonce you set for the test boot (64 hex): REPORTDATA must carry it "
                   "(required unless --unverified)")
    k.add_argument("--unverified", action="store_true", help="do not verify the quote with Intel DCAP (no network) "
                   "and do not require a nonce: the registers are then whatever the bytes say, never values to sign")
    k.add_argument("-o", "--output")
    k.set_defaults(func=cmd_capture)

    k = sub.add_parser("write", help="the measurement document")
    k.add_argument("--image-sha256", required=True)
    k.add_argument("--entries", required=True, help="a JSON list of entries, or a predict output")
    k.add_argument("-o", "--output", required=True)
    k.set_defaults(func=cmd_write)

    k = sub.add_parser("sign", help="Ed25519 over the document's exact bytes")
    k.add_argument("--key", required=True)
    k.add_argument("document")
    k.add_argument("-o", "--output", required=True)
    k.set_defaults(func=cmd_sign)

    k = sub.add_parser("verify-document", help="steps 1-5 of the document's verification")
    k.add_argument("--public-key", required=True)
    k.add_argument("--image-sha256", required=True)
    k.add_argument("document")
    k.add_argument("signature")
    k.set_defaults(func=cmd_verify_document)

    k = sub.add_parser("verify-quote", help="the gateway's checks against a quote")
    k.add_argument("--quote", required=True, help="the quote (raw or base64; - for stdin)")
    k.add_argument("--nonce")
    k.add_argument("--public-key-file")
    k.add_argument("--report-data", help="the expected REPORTDATA (128 hex) in place of --nonce and --public-key-file")
    k.add_argument("--documents", nargs="+", required=True)
    k.add_argument("--signatures", nargs="+", required=True)
    k.add_argument("--measurement-key", required=True)
    k.add_argument("--image-sha256", required=True)
    k.add_argument("--machine-type", required=True)
    k.add_argument("--gce-project", required=True, help="the project the VM names (its claim; checked against the pin)")
    k.add_argument("--allowed-project", action="append", help="a project number the VM may run in (the pin); "
                   "required unless --platform names them; with both, a project must be in each")
    k.add_argument("--zone", required=True)
    k.add_argument("--instance-id", required=True)
    k.add_argument("--floor", help="a firmware_floor document; with --platform, both apply (each minimum's "
                   "maximum, every denied build)")
    k.add_argument("--platform", help="a chutes.cvm-platform.v1 document: pins projects, regions, machine types, floor")
    k.add_argument("--firmware-dir")
    k.add_argument("--collateral-source", help="where Intel's DCAP collateral is fetched: intel-pcs, phala-pccs or "
                   "an https:// PCCS URL (default: TDX_COLLATERAL_SOURCE, else intel-pcs). Whichever answers, the "
                   "quote is refused unless Intel's TCB signing certificate, under the pinned Intel SGX root, signed "
                   "the TCB Info and the QE Identity")
    k.add_argument("--json", action="store_true")
    k.set_defaults(func=cmd_verify_quote)

    k = sub.add_parser("version")
    k.set_defaults(func=lambda args: print(f"chutes-tdx-measure {__version__}"))
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        code = args.func(args)
    except (ValueError, OSError, predict.PredictionError, capture.CaptureRefused, capture.CaptureUnavailable) as exc:
        print(f"chutes-tdx-measure: {exc}", file=sys.stderr)
        return 2
    return code or 0


if __name__ == "__main__":
    sys.exit(main())
