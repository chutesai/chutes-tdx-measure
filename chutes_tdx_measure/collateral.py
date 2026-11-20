from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509.oid import NameOID

from chutes_tdx_measure.vendor.chutes_attest import intel_root, tdx_policy, tdx_verify

# The subject common name of the certificate Intel signs TCB Info and QE Identity with.
TCB_SIGNING_CN = "Intel SGX TCB Signing"
_SIGNED_COLLATERAL = (("tcb_info_issuer_chain", "TCB Info"), ("qe_identity_issuer_chain", "QE Identity"))
# An issuer chain is exactly two ``CERTIFICATE`` blocks of canonical base64 with only whitespace
# around them: dcap-qvl takes the first PEM block of the chain text, whatever its label, as the
# signer, while other PEM readers skip a block of another label, so no such block is let through.
_SIGNER_CHAIN = re.compile(
    r"\s*-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----"
    r"\s*-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*",
    re.ASCII,
)


def _certificate_der(body: str) -> bytes:
    """The DER of one PEM block's base64 ``body``; ``ValueError`` unless it is canonical base64, so
    the bytes judged here are the bytes any other decoder reads."""
    text = "".join(body.split())
    der = base64.b64decode(text, validate=True)
    if base64.b64encode(der).decode("ascii") != text:
        raise ValueError("not canonical base64")
    return der


def collateral_signers(document: dict) -> Optional[str]:
    root_der = intel_root.INTEL_SGX_ROOT_CA_DER
    root = x509.load_der_x509_certificate(root_der)
    for member, what in _SIGNED_COLLATERAL:
        chain = document.get(member)
        match = _SIGNER_CHAIN.fullmatch(chain) if isinstance(chain, str) else None
        if match is None:
            return f"the {what} issuer chain is not exactly two PEM certificates"
        try:
            signer_der, issuer_der = (_certificate_der(body) for body in match.groups())
            signer = x509.load_der_x509_certificate(signer_der)
            common = signer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        except ValueError:
            return f"the {what} issuer chain holds a certificate that does not parse"
        if issuer_der != root_der:
            return f"the {what} issuer chain does not end at the pinned Intel SGX root CA"
        names = [str(attribute.value) for attribute in common]
        if names != [TCB_SIGNING_CN]:
            named = ", ".join(repr(name[:64]) for name in names) or "no common name"
            return f"the {what} is signed by {named}, not by {TCB_SIGNING_CN!r}"
        try:
            signer.verify_directly_issued_by(root)
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
            return f"the {what} signer was not issued by the pinned Intel SGX root CA"
    return None


async def verify_quote(raw: bytes, *, collateral_source: Optional[str] = None, now: Optional[int] = None):
    """The vendored ``verify_tdx_quote_bytes`` (same source rule, same verdict, same errors) with the
    signer rule (``collateral_signers``) between its fetch and its verification. ``now`` is Unix
    seconds (default: the wall clock). Raises ``VerifierUnavailable`` (no verdict) or
    ``TdxQuoteRejected`` (decided)."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise tdx_verify.TdxQuoteRejected("TDX quote bytes are required")
    raw = bytes(raw)
    if isinstance(now, bool) or (now is not None and not isinstance(now, int)):
        raise ValueError("now must be integer Unix seconds")
    now_secs = int(time.time()) if now is None else now
    source = tdx_verify.resolve_collateral_source(collateral_source)
    try:
        fetched = await tdx_verify._fetch_collateral(raw, source)
    except tdx_verify.VerifierUnavailable:
        raise
    except ValueError as exc:
        raise tdx_verify.TdxQuoteRejected(f"TDX quote/collateral request is invalid: {exc}") from exc
    except Exception as exc:
        raise tdx_verify.VerifierUnavailable(
            f"TDX collateral from {source} is unavailable: {type(exc).__name__}: {exc}") from exc
    text = tdx_verify.canonical_collateral_json(fetched)
    document = None if text is None else json.loads(text)
    if not isinstance(document, dict):
        raise tdx_verify.VerifierUnavailable(f"TDX collateral from {source} is malformed")
    try:
        freshness = tdx_policy.check_collateral_freshness(document.get("tcb_info"), document.get("qe_identity"),
                                                          now=now_secs)
    except tdx_policy.TdxPolicyError as exc:
        raise tdx_verify.VerifierUnavailable(f"TDX collateral from {source} is malformed") from exc
    if not tdx_policy.all_passed(freshness):
        raise tdx_verify.VerifierUnavailable(
            f"stale TDX collateral from {source}: "
            + "; ".join(f"{check.name}: {check.detail}" for check in tdx_policy.failed(freshness)))
    refused = collateral_signers(document)
    if refused is not None:
        raise tdx_verify.TdxQuoteRejected(f"the TDX collateral from {source} is not Intel's: {refused}")
    # The text that was judged, never a second fetch: the verifier reads these chains.
    return await asyncio.to_thread(tdx_verify.verify_tdx_quote_with_collateral, raw, text, now=now_secs)
