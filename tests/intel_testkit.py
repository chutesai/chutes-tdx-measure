"""A test PKI shaped as Intel's SGX one (a synthetic root CA, the TCB signing certificate it issues,
other certificates under it), synthetic DCAP collateral, and stand-ins for Intel's collateral
service and Intel's verifier, so the collateral signer rule (``chutes_tdx_measure.collateral``) runs
without the network."""

import base64
import datetime as dt
import functools
import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from chutes_tdx_measure.vendor.chutes_attest import intel_root, tdx_verify

TCB_SIGNING_CN = "Intel SGX TCB Signing"
NOT_BEFORE = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER = dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc)
# The instant the tests judge at, and the collateral's issue time (fresh at NOW).
NOW = int(dt.datetime(2026, 11, 18, 12, tzinfo=dt.timezone.utc).timestamp())
ISSUED = "2026-11-18T06:00:00Z"


def key(label: str):
    value = int.from_bytes(hashlib.sha256(label.encode()).digest(), "big")
    return ec.derive_private_key(value % (2 ** 255) + 1, ec.SECP256R1())


def cert(common_name, cert_key, issuer, issuer_key, *, ca):
    """A certificate shaped as Intel's SGX ones (P-256, ECDSA-SHA256); ``issuer`` None: self-signed."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation")])
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject if issuer is None else issuer.subject)
            .public_key(cert_key.public_key())
            .serial_number(int.from_bytes(hashlib.sha256(common_name.encode()).digest()[:8], "big"))
            .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256()))


def der(certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def pem_chain(*certs) -> str:
    """An issuer chain as Intel PCS sends it: the PEM certificates one after another."""
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs)


def pem_block(body: str) -> str:
    """One ``CERTIFICATE`` block around the base64 ``body`` as it is given."""
    lines = [body[at: at + 64] for at in range(0, len(body), 64)]
    return "\n".join(["-----BEGIN CERTIFICATE-----", *lines, "-----END CERTIFICATE-----", ""])


class IntelPki:
    """A synthetic Intel SGX root CA and the TCB signing certificate it issues."""

    def __init__(self):
        self.root_key = key("intel-sgx-root")
        self.root = cert("Intel SGX Root CA", self.root_key, None, self.root_key, ca=True)
        self.tcb_signing = cert(TCB_SIGNING_CN, key("intel-tcb-signing"), self.root, self.root_key, ca=False)
        self.root_der = der(self.root)
        # The issuer chain of a TCB Info or a QE Identity: the TCB signing certificate, the root.
        self.signer_chain = pem_chain(self.tcb_signing, self.root)


@functools.lru_cache(maxsize=1)
def intel_pki() -> IntelPki:
    return IntelPki()


def pin(monkeypatch) -> IntelPki:
    """Pin the synthetic root where this package reads Intel's (``vendor/chutes_attest/intel_root.py``),
    with no collateral source named by the environment."""
    pki = intel_pki()
    monkeypatch.setattr(intel_root, "INTEL_SGX_ROOT_CA_DER", pki.root_der)
    monkeypatch.delenv(tdx_verify.COLLATERAL_SOURCE_ENV, raising=False)
    return pki


def respelled(pki: IntelPki) -> str:
    """The base64 of a genuine TCB signing certificate with the unused bits of its last character
    set: another spelling, which a lenient decoder reads as the same DER. Only a padded body has
    such bits, and an ECDSA signature's length varies, so the certificate is issued until one is."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for _ in range(256):
        signer = cert(TCB_SIGNING_CN, key("intel-tcb-signing"), pki.root, pki.root_key, ca=False)
        body = base64.b64encode(der(signer)).decode()
        if body.endswith("="):
            break
    else:
        raise AssertionError("no padded certificate in 256 issues")
    stem = body.rstrip("=")
    other = stem[:-1] + alphabet[alphabet.index(stem[-1]) + 1] + body[len(stem):]
    assert other != body and base64.b64decode(other) == der(signer)
    return other


def other_chains(pki: IntelPki) -> dict:
    """Issuer chains that are not Intel's TCB signing certificate under the pinned root, each as a
    holder of another key under that root, or of another root, could present it."""
    platform_key = key("pck-platform-ca")
    platform = cert("Intel SGX PCK Platform CA", platform_key, pki.root, pki.root_key, ca=True)
    pck_key = key("pck")
    pck = cert("Intel SGX PCK Certificate", pck_key, platform, platform_key, ca=False)
    renamed = cert(TCB_SIGNING_CN, pck_key, platform, platform_key, ca=False)
    other_key = key("another-root")
    other_root = cert("Intel SGX Root CA", other_key, None, other_key, ca=True)
    forged = cert(TCB_SIGNING_CN, pck_key, other_root, other_key, ca=False)
    genuine = pki.signer_chain
    # The genuine certificate naming a signature algorithm nothing can verify.
    ecdsa_with_sha256 = bytes.fromhex("06082a8648ce3d040302")
    unverifiable = der(pki.tcb_signing).replace(ecdsa_with_sha256, ecdsa_with_sha256[:-1] + b"\x09")
    return {
        "pck-chain": pem_chain(pck, platform, pki.root),
        "platform-ca": pem_chain(platform, pki.root),
        "a-pck-certificate": pem_chain(pck, pki.root),
        "named-as-the-signer-under-the-platform-ca": pem_chain(renamed, pki.root),
        "named-as-the-signer-under-another-root": pem_chain(forged, pki.root),
        "another-root-of-the-same-name": pem_chain(forged, other_root),
        "the-signer-alone": pem_chain(pki.tcb_signing),
        "the-root-first": pem_chain(pki.root, pki.tcb_signing),
        "the-signer-twice": pem_chain(pki.tcb_signing, pki.tcb_signing),
        "a-third-certificate": genuine + pem_chain(pck),
        "a-block-of-another-label-first": pem_chain(pck).replace("CERTIFICATE", "X509 CERTIFICATE") + genuine,
        "text-before-the-chain": "Proc-Type: 4,ENCRYPTED\n" + genuine,
        "text-after-the-chain": genuine + "trailing data",
        "respelled-base64": pem_block(respelled(pki)) + pem_chain(pki.root),
        "an-unknown-signature-algorithm": pem_block(base64.b64encode(unverifiable).decode()) + pem_chain(pki.root),
        "not-certificates": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" * 2,
        "empty": "",
    }


def issued_now() -> str:
    """An issue time fresh at the wall clock (the instant ``verify.default_verifiers`` judges at)."""
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def collateral_document(tcb_info_chain: str, qe_identity_chain: str, issued: str = ISSUED) -> dict:
    """dcap-qvl's collateral document (``QuoteCollateralV3``'s JSON) with these issuer chains: the
    signed bodies carry only what the freshness rule reads, the signatures and CRLs are filler."""
    body = json.dumps({"issueDate": issued, "tcbEvaluationDataNumber": 19})
    return {
        "pck_crl_issuer_chain": "", "root_ca_crl": "00", "pck_crl": "00",
        "tcb_info_issuer_chain": tcb_info_chain, "tcb_info": body, "tcb_info_signature": "00" * 64,
        "qe_identity_issuer_chain": qe_identity_chain, "qe_identity": body, "qe_identity_signature": "00" * 64,
    }


class Fetched:
    """What the collateral seam returns, reduced to what this package reads: an object with a JSON form."""

    def __init__(self, document):
        self.document = document

    def to_json(self) -> str:
        return json.dumps(self.document)


class Verdict:
    # td_attributes: SEPT_VE_DISABLE (bit 28) only, little-endian bytes as dcap-qvl writes them.
    passed, checks, status, td10 = True, [], "UpToDate", {"td_attributes": "0000001000000000"}


def serve(monkeypatch, document, error=None, fetched=Fetched):
    """Stand-ins for the vendored collateral seam and the vendored verifier. The seam answers every
    source with ``document`` (or raises ``error``); the verifier, as dcap-qvl 0.5.3, accepts
    collateral under any signer. Returns (asked, handed): the (quote, source) pairs the seam was
    asked for and the (quote, collateral text, now) triples the verifier was handed."""
    asked, handed = [], []

    async def fetch(raw, source):
        asked.append((raw, source))
        if error is not None:
            raise error
        return fetched(document)

    def verifier(raw, collateral_json, *, now):
        handed.append((raw, collateral_json, now))
        return Verdict()

    monkeypatch.setattr(tdx_verify, "_fetch_collateral", fetch)
    monkeypatch.setattr(tdx_verify, "verify_tdx_quote_with_collateral", verifier)
    return asked, handed
