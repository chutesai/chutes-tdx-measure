"""Google's provenance of a GCP Intel TDX machine: which instance it is, as Google vouches for it.

Google documents two checks ("Verify an Intel TDX VM instance runs on Google Cloud",
https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/tdx-provenance; the
reference tool is google/go-tdx-guest ``tools/gceprovenance``, the PZID ``gce/pzid.go`` @23b3eac9):

- **Instance.** Google's host sets MR_OWNER of every GCE TDX guest to SHA-384 of the exact ASCII
  payload ``{"instanceId":<id>,"numericalProjectId":<n>,"zone":"<zone>"}`` (decimal integers, no
  whitespace, keys in that order: a format string, never ``json.dumps``).
- **Host.** The PPID of the quote's PCK certificate names the physical platform. An anonymous GET of
  ``https://storage.googleapis.com/confidential-host-registry/<ppid>`` answers
  ``{"timestamp", "zone"}`` for a Google host and 404 for any other.

Google's reference (go-tdx-guest ``FetchProvenanceData``) only requires that the registry document
exists; the instance's zone is bound by the PZID in MR_OWNER. This module also requires the
document's zone to be in the **same region** as the named zone: Google lists some hosts under
another zone of their region (on 2026-11-07, three distinct europe-west4-a hosts were listed as
``europe-west4-b``). A zone is
``<region>-<letter>`` and its region is the zone minus that last ``-<letter>``
(:func:`zone_region`); a zone of another shape is refused (``identity_invalid`` for the named zone,
``registry_invalid`` for the document's), and a host in another region is ``host_region_mismatch``.

MR_OWNER is chosen by the host VMM, so an Intel-signed quote with the right PZID alone proves only
"a genuine TDX platform whose VMM claims to be instance I": a TD that Chutes ran on its own TDX
hardware with Google's published firmware could carry any MR_OWNER. The registry is what makes the
platform Google's, and on a Google host only Google's VMM sets MR_OWNER. Both facts come from ONE
quote: the one the caller already verified with dcap-qvl (signature chain, TCB, CRLs), whose
REPORTDATA binds the caller's nonce and the attested TLS key. This module re-checks that quote's
signature chain offline, so the PPID is the one of the PCK leaf that certified exactly these bytes:
the quote signature by its attestation key, the QE report signature by the PCK leaf, the QE's
binding of the attestation key, and leaf <- intermediate <- the pinned Intel SGX Root CA, each
certificate valid at ``now``. Never a second quote, and never a value the guest names.

Outcomes of :func:`verify`: a :class:`Provenance` (Google vouches for the instance), a
:class:`ProvenanceRefused` with a fixed code (a decided negative: refuse), or
:class:`ProvenanceUnavailable` (no verdict: the registry did not answer). Unavailable is a
``tdx_verify.VerifierUnavailable``: callers refuse and ask for a retry; it is never a pass and
never the earlier "unassured" result.

Trust: Intel (the PCK chain and its PPID) and Google (its VMM sets MR_OWNER; its registry lists
only its hosts). The registry document is unsigned: its trust is TLS to storage.googleapis.com
(the WebPKI, through httpx: certifi's roots unless ``SSL_CERT_FILE`` or ``SSL_CERT_DIR`` name
others; proxies and ``NO_PROXY`` from the environment are honoured) and Google holding the bucket
``confidential-host-registry`` (go-tdx-guest's gceprovenance default). It names the zone and a
timestamp only; the project comes from the PZID. A verifier reveals the PPID it checks to Google
Cloud Storage. The request asks for the stored bytes (``Accept-Encoding: identity``), reads at most
``REGISTRY_MAX_BYTES`` + 1 of them before any decoding, refuses an answer in any other encoding,
and the whole request has one deadline (``REGISTRY_TIMEOUT_SECONDS``).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from .tdx_verify import VerifierUnavailable

PZID_FORMAT = '{"instanceId":%d,"numericalProjectId":%d,"zone":"%s"}'
REGISTRY_BASE_URL = "https://storage.googleapis.com/confidential-host-registry/"
REGISTRY_MAX_BYTES = 4096
REGISTRY_TIMEOUT_SECONDS = 30.0
MAX_QUOTE_BYTES = 64 * 1024

# The refusal codes (each a decided negative) and the one no-verdict code.
CODES = (
    "identity_invalid",
    "pzid_mismatch",
    "quote_invalid",
    "host_unregistered",
    "host_region_mismatch",
    "registry_invalid",
)
UNAVAILABLE_CODE = "registry_unavailable"

_ZONE = re.compile(r"[a-z0-9-]{1,63}")
# A GCE zone: its region (letters, hyphen-joined words, then the region's number, e.g. "europe-west4")
# and one zone letter. The registry's zone must share the named zone's region.
_ZONE_IN_REGION = re.compile(r"(?P<region>[a-z]+(?:-[a-z]+)+[0-9]+)-[a-z]")
_DIGITS = re.compile(r"[0-9]{1,20}")
_PPID = re.compile(r"[0-9a-f]{32}")
_MR = re.compile(r"[0-9A-Fa-f]{96}")

QUOTE_VERSION = 4
ATT_KEY_ECDSA_P256 = 2
TEE_TYPE_TDX = 0x81
HEADER_BYTES = 48
BODY_BYTES = 584
QE_REPORT_BYTES = 384
CERT_DATA_QE_REPORT = 6
CERT_DATA_PCK_CHAIN = 5
MR_OWNER_OFFSET = HEADER_BYTES + 232
SGX_EXTENSION_OID = "1.2.840.113741.1.13.1"
PPID_OID = SGX_EXTENSION_OID + ".1"


class ProvenanceRefused(ValueError):
    """A decided negative: Google does not vouch for the named instance. ``code`` is in CODES."""

    def __init__(self, code: str, text: str):
        super().__init__(f"GCP TDX provenance refused ({code}): {text}")
        self.code, self.text = code, text


class ProvenanceUnavailable(VerifierUnavailable):
    """No verdict: Google's host registry did not answer. The caller refuses and asks for a
    retry; never a pass."""

    code = UNAVAILABLE_CODE

    def __init__(self, text: str):
        super().__init__(
            f"Google's host registry did not answer ({text}); the instance's provenance "
            "cannot be checked now: connect again"
        )
        self.text = text


@dataclass(frozen=True)
class Instance:
    """The GCE instance someone names: project number, zone, instance id."""

    project_number: int
    zone: str
    instance_id: int

    def text(self) -> str:
        return f"project {self.project_number}, zone {self.zone}, instance {self.instance_id}"


@dataclass(frozen=True)
class Provenance:
    """What Google vouches for: MR_OWNER is the named instance's PZID, and the quote's host is a
    Google host in the named zone's region (``registry_zone``, the zone Google's registry lists it
    under, can be another zone of that region)."""

    instance: Instance
    mr_owner: str
    ppid: str
    registry_zone: str
    registered_at: str

    def summary(self) -> dict:
        return {
            "project_number": str(self.instance.project_number),
            "zone": self.instance.zone,
            "instance_id": str(self.instance.instance_id),
            "ppid": self.ppid,
            "registry_zone": self.registry_zone,
            "registered_at": self.registered_at,
        }

    def detail(self) -> str:
        return (
            "Google TDX provenance: MR_OWNER is the PZID Google's host sets for "
            f"{self.instance.text()}; the quote's host (PPID {self.ppid}) is a Google host in "
            f"{self.registry_zone} (Google's host registry, entry {self.registered_at})"
        )


# --- the instance and its PZID -------------------------------------------------------------------


def _uint64(value, name) -> int:
    if isinstance(value, str) and _DIGITS.fullmatch(value):
        value = int(value)
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ProvenanceRefused(
            "identity_invalid", f"{name} is not an unsigned 64-bit integer"
        )
    return value


def zone_region(zone) -> Optional[str]:
    """The GCE region of ``zone``: the zone minus its last ``-<letter>`` ("europe-west4-a" ->
    "europe-west4"), or None for anything that is not ``<region>-<letter>``."""
    if not isinstance(zone, str) or not _ZONE.fullmatch(zone):
        return None
    match = _ZONE_IN_REGION.fullmatch(zone)
    return match.group("region") if match else None


def instance(project_number, zone, instance_id) -> Instance:
    """The named instance, its integers given as int or as decimal strings, its zone
    ``<region>-<letter>``."""
    if zone_region(zone) is None:
        raise ProvenanceRefused(
            "identity_invalid", "zone is not a GCE zone name (<region>-<letter>)"
        )
    return Instance(
        project_number=_uint64(project_number, "project_number"),
        zone=zone,
        instance_id=_uint64(instance_id, "instance_id"),
    )


def pzid_payload(named: Instance) -> bytes:
    """The exact ASCII bytes Google hashes into MR_OWNER."""
    return (PZID_FORMAT % (named.instance_id, named.project_number, named.zone)).encode(
        "ascii"
    )


def pzid_mr_owner(named: Instance) -> str:
    """MR_OWNER of that GCE instance: SHA-384 of its PZID payload, upper-case hex (96)."""
    return hashlib.sha384(pzid_payload(named)).hexdigest().upper()


# --- the quote's PCK chain and PPID --------------------------------------------------------------


def _quote_invalid(text: str) -> ProvenanceRefused:
    return ProvenanceRefused("quote_invalid", text)


@dataclass(frozen=True)
class _Certified:
    signed: bytes
    signature: bytes
    attestation_key: bytes
    qe_report: bytes
    qe_report_signature: bytes
    qe_auth_data: bytes
    pck_chain_pem: bytes


def _certified(raw: bytes) -> _Certified:
    """The signed part and certification data of a TDX v4 ECDSA-P256 quote whose certification
    data is a QE report (type 6) wrapping the PCK chain (type 5)."""
    if not isinstance(raw, (bytes, bytearray)) or not (
        HEADER_BYTES + BODY_BYTES + 4 <= len(raw) <= MAX_QUOTE_BYTES
    ):
        raise _quote_invalid("the TD quote is not a bounded TDX quote")
    raw = bytes(raw)
    version, att_key_type, tee_type = struct.unpack_from("<HHI", raw, 0)
    if (
        version != QUOTE_VERSION
        or att_key_type != ATT_KEY_ECDSA_P256
        or tee_type != TEE_TYPE_TDX
    ):
        raise _quote_invalid(
            f"not a TDX v4 ECDSA-P256 quote (version {version}, key type {att_key_type}, "
            f"TEE 0x{tee_type:x})"
        )
    position = HEADER_BYTES + BODY_BYTES
    (signature_length,) = struct.unpack_from("<I", raw, position)
    position += 4
    if signature_length > len(raw) - position or signature_length < 64 + 64 + 6:
        raise _quote_invalid("the quote's signature data is truncated")
    data = raw[position : position + signature_length]
    cert_type, cert_size = struct.unpack_from("<HI", data, 128)
    if cert_type != CERT_DATA_QE_REPORT or cert_size > len(data) - 134:
        raise _quote_invalid("the quote does not carry QE report certification data")
    cert = data[134 : 134 + cert_size]
    if len(cert) < QE_REPORT_BYTES + 64 + 2:
        raise _quote_invalid("the QE report certification data is truncated")
    (auth_length,) = struct.unpack_from("<H", cert, QE_REPORT_BYTES + 64)
    auth_end = QE_REPORT_BYTES + 64 + 2 + auth_length
    if auth_end + 6 > len(cert):
        raise _quote_invalid("the QE authentication data is truncated")
    inner_type, inner_size = struct.unpack_from("<HI", cert, auth_end)
    if inner_type != CERT_DATA_PCK_CHAIN or inner_size > len(cert) - auth_end - 6:
        raise _quote_invalid("the quote does not carry its PCK certificate chain")
    return _Certified(
        signed=raw[: HEADER_BYTES + BODY_BYTES],
        signature=data[:64],
        attestation_key=data[64:128],
        qe_report=cert[:QE_REPORT_BYTES],
        qe_report_signature=cert[QE_REPORT_BYTES : QE_REPORT_BYTES + 64],
        qe_auth_data=cert[QE_REPORT_BYTES + 66 : auth_end],
        pck_chain_pem=cert[auth_end + 6 : auth_end + 6 + inner_size],
    )


def _p256(raw_xy: bytes):
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b"\x04" + raw_xy
        )
    except ValueError:
        raise _quote_invalid(
            "the quote's attestation key is not a P-256 point"
        ) from None


def _ecdsa_ok(key, signature_rs: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    der = encode_dss_signature(
        int.from_bytes(signature_rs[:32], "big"),
        int.from_bytes(signature_rs[32:], "big"),
    )
    try:
        key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def _der_items(buffer: bytes):
    """(tag, value) of each DER TLV in ``buffer`` (definite lengths of at most 4 bytes)."""
    position = 0
    while position < len(buffer):
        if len(buffer) - position < 2:
            raise ValueError("truncated DER")
        tag, length = buffer[position], buffer[position + 1]
        position += 2
        if length & 0x80:
            count = length & 0x7F
            if not 1 <= count <= 4 or position + count > len(buffer):
                raise ValueError("unsupported DER length")
            length = int.from_bytes(buffer[position : position + count], "big")
            position += count
        if position + length > len(buffer):
            raise ValueError("DER length runs past its container")
        yield tag, buffer[position : position + length]
        position += length


def _oid_text(raw: bytes) -> str:
    if not raw:
        raise ValueError("empty OID")
    parts, value = [raw[0] // 40, raw[0] % 40], 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


def pck_ppid(leaf) -> str:
    """The PPID (16 bytes, lower-case hex) of a PCK leaf's SGX extension."""
    from cryptography import x509

    try:
        extension = leaf.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(SGX_EXTENSION_OID)
        )
        ((tag, sequence),) = list(_der_items(extension.value.value))
        if tag != 0x30:
            raise ValueError("not a SEQUENCE")
        for _, item in _der_items(sequence):
            (oid_tag, oid), (value_tag, value) = list(_der_items(item))[:2]
            if oid_tag == 0x06 and _oid_text(oid) == PPID_OID:
                if value_tag != 0x04 or len(value) != 16:
                    raise ValueError("the PPID is not 16 bytes")
                return value.hex()
    except (x509.ExtensionNotFound, ValueError, TypeError):
        pass
    raise _quote_invalid("the PCK certificate names no PPID")


def quote_ppid(
    raw: bytes, *, now: dt.datetime, root_der: Optional[bytes] = None
) -> str:
    """The PPID of the PCK leaf that certified exactly ``raw``: the quote signature under its
    attestation key, the QE report signature by the PCK leaf, the QE's binding of the
    attestation key, and the chain leaf <- intermediate <- the pinned Intel SGX Root CA, each
    certificate valid at ``now``. Collateral, TCB and revocation are the caller's dcap-qvl
    verification of the same bytes. ``quote_invalid`` otherwise."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding

    if root_der is None:
        from .intel_root import INTEL_SGX_ROOT_CA_DER

        root_der = INTEL_SGX_ROOT_CA_DER
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    quote = _certified(raw)
    if not _ecdsa_ok(_p256(quote.attestation_key), quote.signature, quote.signed):
        raise _quote_invalid(
            "the quote's signature does not verify under its attestation key"
        )
    try:
        chain = x509.load_pem_x509_certificates(quote.pck_chain_pem.rstrip(b"\x00"))
    except ValueError:
        raise _quote_invalid("the PCK certificate chain does not parse") from None
    if len(chain) != 3:
        raise _quote_invalid(
            f"the PCK certificate chain has {len(chain)} certificates, not 3"
        )
    leaf, intermediate, root = chain
    if root.public_bytes(Encoding.DER) != bytes(root_der):
        raise _quote_invalid(
            "the PCK chain does not end in the pinned Intel SGX Root CA"
        )
    for child, parent in ((leaf, intermediate), (intermediate, root)):
        try:
            child.verify_directly_issued_by(parent)
        except Exception:  # noqa: BLE001 - InvalidSignature and shape errors alike
            raise _quote_invalid("the PCK certificate chain does not verify") from None
        if not child.not_valid_before_utc <= now <= child.not_valid_after_utc:
            raise _quote_invalid("a PCK chain certificate is not valid now")
    key = leaf.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not _ecdsa_ok(
        key, quote.qe_report_signature, quote.qe_report
    ):
        raise _quote_invalid(
            "the QE report's signature does not verify under the PCK certificate"
        )
    bound = quote.qe_report[320:384]
    if bound[:32] != hashlib.sha256(
        quote.attestation_key + quote.qe_auth_data
    ).digest() or bound[32:] != bytes(32):
        raise _quote_invalid("the QE report does not bind the quote's attestation key")
    return pck_ppid(leaf)


# --- Google's host registry ----------------------------------------------------------------------


@dataclass(frozen=True)
class RegistryEntry:
    zone: str
    timestamp: str


Fetch = Callable[[str, int, float], Awaitable[tuple]]


async def registry_get(url: str, max_bytes: int, timeout: float) -> tuple:
    """An anonymous GET that follows no redirect and asks for the stored bytes
    (``Accept-Encoding: identity``): (HTTP status, at most ``max_bytes`` + 1 raw body bytes, read
    before any content decoding). An answer in another ``Content-Encoding`` is returned with the
    body ``None`` and never decoded (a 200 is then ``registry_invalid``). ``timeout`` bounds each
    phase; :func:`registry_entry` puts one deadline on the whole request."""
    import httpx

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        async with client.stream(
            "GET", url, headers={"Accept-Encoding": "identity"}
        ) as response:
            encoding = response.headers.get("content-encoding", "").strip().lower()
            if encoding not in ("", "identity"):
                return response.status_code, None
            body = bytearray()
            async for chunk in response.aiter_raw():
                body.extend(chunk)
                if len(body) > max_bytes:
                    break
            return response.status_code, bytes(body[: max_bytes + 1])


def _no_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


async def registry_entry(ppid: str, *, fetch: Optional[Fetch] = None) -> RegistryEntry:
    """Google's host-registry document of ``ppid``: 200 and ``{"timestamp", "zone"}``; else
    ``host_unregistered`` (404), ``registry_invalid`` (not that document) or
    :class:`ProvenanceUnavailable` (any other answer, none, or none within
    ``REGISTRY_TIMEOUT_SECONDS`` for the whole request)."""
    if not isinstance(ppid, str) or not _PPID.fullmatch(ppid):
        raise _quote_invalid("the PPID is not 16 bytes of lower-case hex")
    try:
        status, body = await asyncio.wait_for(
            (fetch or registry_get)(
                REGISTRY_BASE_URL + ppid, REGISTRY_MAX_BYTES, REGISTRY_TIMEOUT_SECONDS
            ),
            REGISTRY_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 - transport failure, deadline: no verdict
        raise ProvenanceUnavailable(type(exc).__name__) from None
    if status == 404:
        raise ProvenanceRefused(
            "host_unregistered",
            f"Google's host registry does not know this TD's host (PPID {ppid}): it is "
            "not a Google host",
        )
    if status != 200:
        raise ProvenanceUnavailable(f"HTTP {status} for PPID {ppid}")
    invalid = ProvenanceRefused(
        "registry_invalid",
        f"Google's host registry entry for PPID {ppid} is not a host document",
    )
    if not isinstance(body, (bytes, bytearray)) or len(body) > REGISTRY_MAX_BYTES:
        raise invalid
    try:
        document = json.loads(
            bytes(body).decode("utf-8"), object_pairs_hook=_no_duplicates
        )
    except (ValueError, UnicodeDecodeError):
        raise invalid from None
    if (
        not isinstance(document, dict)
        or zone_region(document.get("zone")) is None
        or not isinstance(document.get("timestamp"), str)
        or not 1 <= len(document["timestamp"]) <= 64
        or not document["timestamp"].isprintable()
    ):
        raise invalid
    return RegistryEntry(zone=document["zone"], timestamp=document["timestamp"])


# --- the check -----------------------------------------------------------------------------------


def quote_mr_owner(raw: bytes) -> str:
    """MR_OWNER of a TDX v4 quote's TD body, upper-case hex (the bytes :func:`quote_ppid` signs).
    Another quote version or TEE type (whose body is elsewhere) is ``quote_invalid``, never read
    at the v4 offset."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < MR_OWNER_OFFSET + 48:
        raise _quote_invalid("the TD quote is too short to carry MR_OWNER")
    version, _, tee_type = struct.unpack_from("<HHI", raw, 0)
    if version != QUOTE_VERSION or tee_type != TEE_TYPE_TDX:
        raise _quote_invalid(
            f"not a TDX v4 quote (version {version}, TEE 0x{tee_type:x}): MR_OWNER is not read"
        )
    return bytes(raw[MR_OWNER_OFFSET : MR_OWNER_OFFSET + 48]).hex().upper()


async def verify(
    raw_quote: bytes,
    named: Instance,
    *,
    now: dt.datetime,
    fetch: Optional[Fetch] = None,
    root_der: Optional[bytes] = None,
) -> Provenance:
    """Google's provenance of the TD whose (already dcap-verified) quote is ``raw_quote``, for the
    instance someone names: MR_OWNER equals SHA-384 of the named instance's PZID
    (``pzid_mismatch``), the quote's PCK leaf names a PPID (``quote_invalid``), and Google's host
    registry knows that PPID (``host_unregistered``) under a zone of the named zone's region
    (``host_region_mismatch``). A named zone that is not ``<region>-<letter>`` is
    ``identity_invalid`` before any request.
    Raises :class:`ProvenanceRefused` or :class:`ProvenanceUnavailable`."""
    if not isinstance(named, Instance):
        raise ProvenanceRefused("identity_invalid", "no instance is named")
    region = zone_region(named.zone)
    if region is None:
        raise ProvenanceRefused(
            "identity_invalid", "zone is not a GCE zone name (<region>-<letter>)"
        )
    mr_owner = quote_mr_owner(raw_quote)
    expected = pzid_mr_owner(named)
    if mr_owner != expected:
        raise ProvenanceRefused(
            "pzid_mismatch",
            f"MR_OWNER {mr_owner[:16]}... is not the PZID Google's host sets for "
            f"{named.text()} ({expected[:16]}...)",
        )
    ppid = quote_ppid(raw_quote, now=now, root_der=root_der)
    entry = await registry_entry(ppid, fetch=fetch)
    if zone_region(entry.zone) != region:
        raise ProvenanceRefused(
            "host_region_mismatch",
            f"the quote's host (PPID {ppid}) is a Google host in {entry.zone}, not in "
            f"{named.zone}'s region {region}",
        )
    return Provenance(
        instance=named,
        mr_owner=mr_owner,
        ppid=ppid,
        registry_zone=entry.zone,
        registered_at=entry.timestamp,
    )


def not_checked(failed) -> str:
    """The detail of a provenance row a verifier did not check because the rows ``failed`` names
    already failed: Google's host registry is asked only after every other row passed, so its
    outage never turns a decided failure into "connect again"."""
    return (
        "Google's provenance not checked: "
        + ", ".join(failed)
        + " failed, so Google's host registry was not asked"
    )


def utc(now) -> dt.datetime:
    """``now`` (Unix seconds, an aware datetime, or None for the wall clock) as an aware
    datetime."""
    if now is None:
        return dt.datetime.now(dt.timezone.utc)
    if isinstance(now, dt.datetime):
        if now.tzinfo is None:
            raise ValueError("now must be a timezone-aware datetime")
        return now
    if isinstance(now, (int, float)) and not isinstance(now, bool):
        return dt.datetime.fromtimestamp(now, dt.timezone.utc)
    raise ValueError("now must be Unix seconds or a timezone-aware datetime")


def is_mr(value) -> bool:
    return isinstance(value, str) and _MR.fullmatch(value) is not None
