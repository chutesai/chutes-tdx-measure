"""Google's GCE launch endorsements and a firmware index built from them (the Chutes SDK's module).

On GCP SEV-SNP the hardware MEASUREMENT covers only Google's OVMF and the VMSAs, so a verifier
accepts any MEASUREMENT Google endorses for the shape's vCPU count. On GCP TDX the endorsements list
the MRTDs of each firmware build, and Google's published binary of the build gives its CFV. The
firmware index is a directory of Google's ``VMLaunchEndorsement`` documents
(``<uefi_sha384>.binarypb``) and TDX binaries (``<uefi_sha384>.fd``), every one re-verified under
Google's pinned GCE confidential-computing root each time the index loads; the index document is
``chutes.gce-firmware-index.v1``. A floor (``min_endorsed_at`` and an optional ``min_svn``) refuses
older endorsed firmware (``firmware_below_floor``).

Everything from ``GceEndorsementError`` to ``gce_firmware_binary_object_name`` below is the
endorsement verifier Chutes' validator runs. ``firmware_dir`` and ``_publish`` use the SDK's state
directory and need the Chutes SDK; this package passes its own directory and does not call them.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class GceEndorsementError(ValueError):
    """A launch endorsement that is malformed or does not verify (never admitted)."""


# GCE-cc-tcb-root_1.crt (https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt):
# CN=GCE-cc-tcb-root, serialNumber=1, valid 2023-10-16 to 2048-10-15, BasicConstraints critical
# CA:TRUE pathlen 0, RSA 4096, self-signed with RSASSA-PSS/SHA-256/salt 32.  The DER bytes are
# pinned by GCE_CC_TCB_ROOT_SHA256.
_GCE_CC_TCB_ROOT_DER_B64 = (
    "MIIGHjCCA9KgAwIBAgIBATBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZI"
    "hvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwezEMMAoGA1UEBhMDVVNBMQswCQYDVQQIEwJXQTER"
    "MA8GA1UEBxMIS2lya2xhbmQxDzANBgNVBAoTBkdvb2dsZTEUMBIGA1UECxMLRW5naW5lZXJpbmcx"
    "GDAWBgNVBAMTD0dDRS1jYy10Y2Itcm9vdDEKMAgGA1UEBRMBMTAeFw0yMzEwMTYyMTU0MjVaFw00"
    "ODEwMTUyMTU0MjVaMHsxDDAKBgNVBAYTA1VTQTELMAkGA1UECBMCV0ExETAPBgNVBAcTCEtpcmts"
    "YW5kMQ8wDQYDVQQKEwZHb29nbGUxFDASBgNVBAsTC0VuZ2luZWVyaW5nMRgwFgYDVQQDEw9HQ0Ut"
    "Y2MtdGNiLXJvb3QxCjAIBgNVBAUTATEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2"
    "GuLnK6pVKXDcDKpo8l4NZF8hG4oWKv52PO08Eu+1TAYH3AATrCJUCaBxBDygSCzUzQk3dups43+H"
    "Z9TJh5W6jLeVOdF17xkxgRHCW4UPEu0UroNyhRQ+gPjyS55U4IJmk1s6St9m4eIIX2OJ8+dX3lTg"
    "xn/+InmhshF7PsGno24/ZDBXGwU+p4U3XvIG5mAKvxh1fBJB98lubVHZsAHySXkLY2PY4mZLjPgj"
    "EP/vk6om3sc0Qi+XgQCw47bTftURx1xhwVFj6/jp3qWP8R76TsEffW68dsRVNA6e4YgtMtMRXIe2"
    "vIuAeAq+Pb4e8F/pIEhOQk75udkJ7uO6nhau26KiGIeSZGBOFnDozxrSYmsmGYPXub82JXEcbZph"
    "huqpWLGdPmQdvcuV8hWJunYkosiREVDFzAtrBAorV5FvNMwE7bwhhaFL+3DHeumFFbUrBIjK4PA2"
    "QjC5b8kCtLHWSm3DUUHFJKW4b72Z6+Kt1jF7+q5AJOIlbEljGyOHVLU575lGZ2GP/cxGYHUlRsof"
    "DPx3eud1m+oDs7dvqAquuDBU5Xnf0ZAV7DnoLTS0xypR24cgvpSUUj7hbykzLasuwND0dlwqljHV"
    "nk6NXluJQm70fIrMhlkoCvmVMWnIUkY1RUYzPWLk92XCe2L1AL5mHSLq0bQKEbJ8lRvxWoTgywID"
    "AQABo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUcaed"
    "0BFhtbEk9n3trP2C+/FrJT0wQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqG"
    "SIb3DQEBCDANBglghkgBZQMEAgEFAKIDAgEgA4ICAQB4s9gtkHCJ2y6EHrjhPjcdX7ylSOsyJ/89"
    "CJm5x8cal601dKvq+g6I7ggW9birP7/49ioK4IqlwQqhp2+JTwI/yrJTJ2bFR6aL1DVdgv0bLSyB"
    "xs06uewyD5mY5GRU1KaE9kVqA/yOwjnTNsC+vjjjzzzbwx8wx5gVcx3YbmQm3FYpR+WEL7ckRh/8"
    "hiO9zkr9nJslVVpwtnUwIDoyv9IJYTfkEDFpfT2OMK/rcYZw5xeusPDysXaWL1F5AqtwzXkXEtFZ"
    "4oSAIPdHqziGFPxSw6kxQDcCPvUWzZxNHn1SN7heBtZQdAZJLAD0y1kz41p9XuZFqmOOTwKy4NIb"
    "+5sefpRARBi+3xL/hxGpSGNhYcIugQ0QgKo1GdISECtHBN5R5iFg7JdHc3tTAt9XhLW6Neyq1wtG"
    "5mNqBL03sLHxp0Y+HspTA3p/iI8tsVEp5QB6ujChMFIbEhdXJN683NgyLOJv3NbArO/vkIvHZgi9"
    "seyE5JIdPG4Tu8IPMzhHMu1PfuG7YCG7rjxq8JTFUyQyLK14OUk+NmuK0xXaPZ//UTlu8EeAa+SA"
    "6uL7shniCvWpheIJVH0WcJurm3grpJM4BvP8vBjn8gt3iyX60vgT10PHRYrXDGWQWwPzDxvBUTTE"
    "iAL5l2bYSHzjwqbIXG9gmjSKOyfQkrT0LtfccBXpCw=="
)
GCE_CC_TCB_ROOT_DER: bytes = base64.b64decode(_GCE_CC_TCB_ROOT_DER_B64, validate=True)
GCE_CC_TCB_ROOT_SHA256 = "e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c"
if hashlib.sha256(GCE_CC_TCB_ROOT_DER).hexdigest() != GCE_CC_TCB_ROOT_SHA256:  # pragma: no cover
    raise RuntimeError("the embedded GCE confidential-computing TCB root does not hash to its pin")

# Google's CVM UEFI family id (gce-tcb-verifier sev/endorsement.go GCEUefiFamilyID).
GCE_UEFI_FAMILY_ID = "f73a6949-e8f3-473b-9553-e40e056fa3a2"
# A golden measurement dated after this instant must name its build provenance (a changelist number
# or a commit); gce-tcb-verifier verify/verify.go uefiReleaseChangeDate.
PROVENANCE_REQUIRED_AFTER = dt.datetime(2024, 8, 2, tzinfo=dt.timezone.utc)
# The lowest firmware SVN any acceptance admits whatever a pin's signed floor says: every
# endorsement observed carries SVN 2 for both technologies.
GCE_FIRMWARE_SVN_CODE_FLOOR = 2
MAX_ENDORSEMENT_BYTES = 64 * 1024
MIN_SIGNER_RSA_BITS = 3072

_PSS_SHA256_SALT32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
_HEX96 = re.compile(r"[0-9a-fA-F]{96}")
_MAX_TIMESTAMP_SECONDS = 253402300799  # 9999-12-31T23:59:59Z, google.protobuf.Timestamp's bound

# --- the strict protobuf reader ----------------------------------------------------------------

_VARINT = 0
_LEN = 2

# message -> {field number: (name, wire type, repeated)}; proto/endorsement.proto of
# google/gce-tcb-verifier at 022f7554.
_ENDORSEMENT_FIELDS = {1: ("serialized_uefi_golden", _LEN, False), 2: ("signature", _LEN, False)}
_GOLDEN_FIELDS = {
    1: ("timestamp", _LEN, False),
    2: ("cl_spec", _VARINT, False),
    3: ("commit", _LEN, False),
    4: ("cert", _LEN, False),
    5: ("digest", _LEN, False),
    6: ("ca_bundle", _LEN, False),
    7: ("sev_snp", _LEN, False),
    8: ("tdx", _LEN, False),
}
_TIMESTAMP_FIELDS = {1: ("seconds", _VARINT, False), 2: ("nanos", _VARINT, False)}
_SNP_FIELDS = {
    1: ("svn", _VARINT, False),
    2: ("measurements", _LEN, True),
    3: ("family_id", _LEN, False),
    4: ("image_id", _LEN, False),
    5: ("policy", _VARINT, False),
    6: ("ca_bundle", _LEN, False),
    7: ("svsm_measurement", _LEN, False),
}
_SNP_MEASUREMENTS_ENTRY_FIELDS = {1: ("key", _VARINT, False), 2: ("value", _LEN, False)}
_TDX_FIELDS = {1: ("svn", _VARINT, False), 2: ("measurements", _LEN, True)}
_TDX_MEASUREMENT_FIELDS = {
    1: ("ram_gib", _VARINT, False),
    2: ("early_accept", _VARINT, False),
    3: ("mrtd", _LEN, False),
}


def _read_varint(buf: bytes, pos: int, end: int, where: str) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if pos >= end:
            raise GceEndorsementError(f"{where}: truncated varint")
        byte = buf[pos]
        pos += 1
        if index == 9 and byte > 1:
            raise GceEndorsementError(f"{where}: varint longer than 64 bits")
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, pos
    raise GceEndorsementError(f"{where}: varint longer than 10 bytes")  # pragma: no cover


def _parse_message(buf: bytes, schema: dict, message: str) -> dict[str, list]:
    """Every field of ``buf`` by name; any field number ``schema`` does not know is refused."""
    fields: dict[str, list] = {}
    pos, end = 0, len(buf)
    while pos < end:
        key, pos = _read_varint(buf, pos, end, f"{message} field key")
        number, wire_type = key >> 3, key & 7
        spec = schema.get(number)
        if spec is None:
            raise GceEndorsementError(
                f"{message}: unknown field number {number} (wire type {wire_type}) refused"
            )
        name, expected_wire_type, repeated = spec
        where = f"{message}.{name} (field {number})"
        if wire_type != expected_wire_type:
            raise GceEndorsementError(
                f"{where}: wire type {wire_type}, expected {expected_wire_type}"
            )
        if wire_type == _VARINT:
            value, pos = _read_varint(buf, pos, end, where)
        else:
            length, pos = _read_varint(buf, pos, end, where)
            if length > end - pos:
                raise GceEndorsementError(
                    f"{where}: length {length} runs past the end of {message}"
                )
            value = bytes(buf[pos : pos + length])
            pos += length
        values = fields.setdefault(name, [])
        if values and not repeated:
            raise GceEndorsementError(f"{where}: a singular field appears more than once")
        values.append(value)
    return fields


def _single(fields: dict[str, list], name: str, default):
    values = fields.get(name)
    return values[0] if values else default


def _unsigned(value: int, bits: int, where: str) -> int:
    if value >= 1 << bits:
        raise GceEndorsementError(f"{where}: {value} does not fit uint{bits}")
    return value


def _length(value: bytes, sizes: tuple[int, ...], where: str) -> bytes:
    if len(value) not in sizes:
        expected = " or ".join(str(size) for size in sizes)
        raise GceEndorsementError(f"{where}: {len(value)} bytes, expected {expected}")
    return value


@dataclass(frozen=True)
class ParsedSnpEndorsement:
    svn: int
    measurements: tuple[tuple[int, bytes], ...]
    family_id: bytes
    image_id: bytes
    policy: int
    ca_bundle: bytes
    svsm_measurement: bytes


@dataclass(frozen=True)
class ParsedTdxMeasurement:
    ram_gib: int
    early_accept: bool
    mrtd: bytes


@dataclass(frozen=True)
class ParsedTdxEndorsement:
    svn: int
    measurements: tuple[ParsedTdxMeasurement, ...]


@dataclass(frozen=True)
class ParsedGoldenMeasurement:
    timestamp: Optional[dt.datetime]
    cl_spec: int
    commit: bytes
    cert: bytes
    digest: bytes
    ca_bundle: bytes
    sev_snp: Optional[ParsedSnpEndorsement]
    tdx: Optional[ParsedTdxEndorsement]


@dataclass(frozen=True)
class ParsedLaunchEndorsement:
    """A strictly parsed, NOT verified endorsement (``verify_launch_endorsement`` verifies)."""

    serialized_uefi_golden: bytes
    signature: bytes
    golden: ParsedGoldenMeasurement


def _parse_timestamp(buf: bytes) -> dt.datetime:
    fields = _parse_message(buf, _TIMESTAMP_FIELDS, "Timestamp")
    seconds = _single(fields, "seconds", 0)
    nanos = _single(fields, "nanos", 0)
    if seconds >= 1 << 63 or seconds > _MAX_TIMESTAMP_SECONDS:
        raise GceEndorsementError("Timestamp.seconds is outside 1970-01-01 .. 9999-12-31")
    if nanos >= 10**9:
        raise GceEndorsementError("Timestamp.nanos must be below 10^9")
    return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc) + dt.timedelta(
        microseconds=nanos // 1000
    )


def _parse_snp(buf: bytes) -> ParsedSnpEndorsement:
    fields = _parse_message(buf, _SNP_FIELDS, "VMSevSnp")
    measurements: dict[int, bytes] = {}
    for entry in fields.get("measurements", []):
        entry_fields = _parse_message(
            entry, _SNP_MEASUREMENTS_ENTRY_FIELDS, "VMSevSnp.measurements entry"
        )
        key = _unsigned(_single(entry_fields, "key", 0), 32, "VMSevSnp.measurements key")
        value = _length(_single(entry_fields, "value", b""), (48,), f"VMSevSnp.measurements[{key}]")
        if key in measurements:
            raise GceEndorsementError(f"VMSevSnp.measurements: duplicate map key {key}")
        measurements[key] = value
    return ParsedSnpEndorsement(
        svn=_unsigned(_single(fields, "svn", 0), 32, "VMSevSnp.svn"),
        measurements=tuple(sorted(measurements.items())),
        family_id=_length(_single(fields, "family_id", b""), (16,), "VMSevSnp.family_id"),
        image_id=_length(_single(fields, "image_id", b""), (16,), "VMSevSnp.image_id"),
        policy=_single(fields, "policy", 0),
        ca_bundle=_single(fields, "ca_bundle", b""),
        svsm_measurement=_length(
            _single(fields, "svsm_measurement", b""), (0, 48), "VMSevSnp.svsm_measurement"
        ),
    )


def _parse_tdx(buf: bytes) -> ParsedTdxEndorsement:
    fields = _parse_message(buf, _TDX_FIELDS, "VMTdx")
    measurements = []
    for entry in fields.get("measurements", []):
        entry_fields = _parse_message(entry, _TDX_MEASUREMENT_FIELDS, "VMTdx.Measurement")
        early_accept = _single(entry_fields, "early_accept", 0)
        if early_accept not in (0, 1):
            raise GceEndorsementError("VMTdx.Measurement.early_accept is not a bool")
        measurements.append(
            ParsedTdxMeasurement(
                ram_gib=_unsigned(_single(entry_fields, "ram_gib", 0), 32, "VMTdx.ram_gib"),
                early_accept=bool(early_accept),
                mrtd=_length(_single(entry_fields, "mrtd", b""), (48,), "VMTdx.Measurement.mrtd"),
            )
        )
    return ParsedTdxEndorsement(
        svn=_unsigned(_single(fields, "svn", 0), 32, "VMTdx.svn"),
        measurements=tuple(measurements),
    )


def parse_launch_endorsement(blob: bytes) -> ParsedLaunchEndorsement:
    """Strictly parse a serialized ``VMLaunchEndorsement`` (no signature is checked here)."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise GceEndorsementError("a launch endorsement must be bytes")
    blob = bytes(blob)
    if not blob:
        raise GceEndorsementError("the launch endorsement is empty")
    if len(blob) > MAX_ENDORSEMENT_BYTES:
        raise GceEndorsementError(
            f"the launch endorsement is {len(blob)} bytes, "
            f"over the {MAX_ENDORSEMENT_BYTES}-byte bound"
        )
    outer = _parse_message(blob, _ENDORSEMENT_FIELDS, "VMLaunchEndorsement")
    payload = _single(outer, "serialized_uefi_golden", b"")
    signature = _single(outer, "signature", b"")
    if not payload:
        raise GceEndorsementError("VMLaunchEndorsement carries no serialized_uefi_golden")
    if not signature:
        raise GceEndorsementError("VMLaunchEndorsement carries no signature")
    fields = _parse_message(payload, _GOLDEN_FIELDS, "VMGoldenMeasurement")
    timestamp = _single(fields, "timestamp", None)
    sev_snp = _single(fields, "sev_snp", None)
    tdx = _single(fields, "tdx", None)
    golden = ParsedGoldenMeasurement(
        timestamp=None if timestamp is None else _parse_timestamp(timestamp),
        cl_spec=_single(fields, "cl_spec", 0),
        commit=_length(_single(fields, "commit", b""), (0, 20), "VMGoldenMeasurement.commit"),
        cert=_single(fields, "cert", b""),
        digest=_length(_single(fields, "digest", b""), (48,), "VMGoldenMeasurement.digest"),
        ca_bundle=_single(fields, "ca_bundle", b""),
        sev_snp=None if sev_snp is None else _parse_snp(sev_snp),
        tdx=None if tdx is None else _parse_tdx(tdx),
    )
    return ParsedLaunchEndorsement(
        serialized_uefi_golden=payload, signature=signature, golden=golden
    )


# --- a minimal DER reader (no Name is ever decoded) ----------------------------------------------

_OID_RSASSA_PSS = bytes.fromhex("2a864886f70d01010a")
_OID_MGF1 = bytes.fromhex("2a864886f70d010108")
_OID_SHA256 = bytes.fromhex("608648016503040201")


def _der_element(buf: bytes, pos: int, end: int, where: str) -> tuple[int, int, int, int]:
    """One TLV at ``pos``: (tag, element start, content start, element end)."""
    if end - pos < 2:
        raise GceEndorsementError(f"{where}: truncated DER element")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise GceEndorsementError(f"{where}: multi-byte DER tags are not used here")
    first = buf[pos + 1]
    content = pos + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or end - content < count:
            raise GceEndorsementError(f"{where}: unsupported DER length")
        length = int.from_bytes(buf[content : content + count], "big")
        content += count
    if length > end - content:
        raise GceEndorsementError(f"{where}: DER length runs past its container")
    return tag, pos, content, content + length


def _der_children(buf: bytes, start: int, end: int, where: str) -> list[tuple[int, int, int, int]]:
    children = []
    pos = start
    while pos < end:
        element = _der_element(buf, pos, end, where)
        children.append(element)
        pos = element[3]
    return children


def _der_sequence_children(buf: bytes, where: str) -> list[tuple[int, int, int, int]]:
    tag, _, content, element_end = _der_element(buf, 0, len(buf), where)
    if tag != 0x30 or element_end != len(buf):
        raise GceEndorsementError(f"{where}: not one DER SEQUENCE")
    return _der_children(buf, content, element_end, where)


@dataclass(frozen=True)
class _CertificateParts:
    tbs_signature_algorithm: bytes
    outer_signature_algorithm: bytes
    issuer_der: bytes
    subject_der: bytes


def _certificate_parts(der: bytes, where: str) -> _CertificateParts:
    """The raw DER of a certificate's two AlgorithmIdentifiers, issuer and subject."""
    top = _der_sequence_children(der, where)
    if len(top) != 3 or top[0][0] != 0x30 or top[1][0] != 0x30:
        raise GceEndorsementError(f"{where}: not a certificate")
    tbs_start, tbs_end = top[0][2], top[0][3]
    tbs = _der_children(der, tbs_start, tbs_end, where)
    if tbs and tbs[0][0] == 0xA0:  # [0] EXPLICIT version
        tbs = tbs[1:]
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ...
    if len(tbs) < 6 or tbs[1][0] != 0x30 or tbs[2][0] != 0x30 or tbs[4][0] != 0x30:
        raise GceEndorsementError(f"{where}: malformed TBSCertificate")
    return _CertificateParts(
        tbs_signature_algorithm=der[tbs[1][1] : tbs[1][3]],
        outer_signature_algorithm=der[top[1][1] : top[1][3]],
        issuer_der=der[tbs[2][1] : tbs[2][3]],
        subject_der=der[tbs[4][1] : tbs[4][3]],
    )


def _is_sha256_algorithm(buf: bytes, where: str) -> bool:
    children = _der_sequence_children(buf, where)
    if not children or children[0][0] != 0x06:
        return False
    if buf[children[0][2] : children[0][3]] != _OID_SHA256:
        return False
    rest = children[1:]
    # parameters absent or NULL
    return not rest or (len(rest) == 1 and rest[0][0] == 0x05 and rest[0][2] == rest[0][3])


def _require_pss_sha256_salt32(algorithm: bytes, where: str) -> None:
    """``algorithm`` (an AlgorithmIdentifier) must be RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32."""
    children = _der_sequence_children(algorithm, where)
    if (
        len(children) != 2
        or children[0][0] != 0x06
        or algorithm[children[0][2] : children[0][3]] != _OID_RSASSA_PSS
        or children[1][0] != 0x30
    ):
        raise GceEndorsementError(f"{where}: the signature algorithm is not RSASSA-PSS")
    params = {}
    for tag, start, content, element_end in _der_children(
        algorithm, children[1][2], children[1][3], where
    ):
        if tag in params or tag not in (0xA0, 0xA1, 0xA2, 0xA3):
            raise GceEndorsementError(f"{where}: malformed RSASSA-PSS parameters")
        params[tag] = algorithm[content:element_end]
    if set(params) - {0xA3} != {0xA0, 0xA1, 0xA2}:
        raise GceEndorsementError(f"{where}: RSASSA-PSS parameters must name hash, MGF and salt")
    if not _is_sha256_algorithm(params[0xA0], where):
        raise GceEndorsementError(f"{where}: the RSASSA-PSS hash is not SHA-256")
    mgf = _der_sequence_children(params[0xA1], where)
    if (
        len(mgf) != 2
        or mgf[0][0] != 0x06
        or params[0xA1][mgf[0][2] : mgf[0][3]] != _OID_MGF1
        or not _is_sha256_algorithm(params[0xA1][mgf[1][1] : mgf[1][3]], where)
    ):
        raise GceEndorsementError(f"{where}: the RSASSA-PSS mask generation is not MGF1-SHA-256")
    if params[0xA2] != b"\x02\x01\x20":
        raise GceEndorsementError(f"{where}: the RSASSA-PSS salt length is not 32")
    if 0xA3 in params and params[0xA3] != b"\x02\x01\x01":
        raise GceEndorsementError(f"{where}: the RSASSA-PSS trailer field is not 1")


# --- verification --------------------------------------------------------------------------------


@dataclass(frozen=True)
class _TrustedRoot:
    public_key: rsa.RSAPublicKey
    subject_der: bytes
    subject_key_identifier: bytes


def _trusted_root(root_der: bytes) -> _TrustedRoot:
    try:
        root = x509.load_der_x509_certificate(root_der)
        basic = root.extensions.get_extension_for_class(x509.BasicConstraints).value
        ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise GceEndorsementError(f"the trusted root certificate is unusable: {exc}") from None
    key = root.public_key()
    if not basic.ca or not isinstance(key, rsa.RSAPublicKey) or key.key_size < MIN_SIGNER_RSA_BITS:
        raise GceEndorsementError("the trusted root is not an RSA CA of at least 3072 bits")
    return _TrustedRoot(
        public_key=key,
        subject_der=_certificate_parts(root_der, "the trusted root").subject_der,
        subject_key_identifier=ski,
    )


def _verified_signer(cert_der: bytes, root: _TrustedRoot, now: dt.datetime) -> x509.Certificate:
    where = "the endorsement signer certificate"
    if not cert_der:
        raise GceEndorsementError("VMGoldenMeasurement carries no signer certificate")
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except ValueError as exc:
        raise GceEndorsementError(f"{where} does not parse: {exc}") from None
    parts = _certificate_parts(cert_der, where)
    if parts.issuer_der != root.subject_der:
        raise GceEndorsementError(f"{where} was not issued by the GCE confidential-computing root")
    if parts.tbs_signature_algorithm != parts.outer_signature_algorithm:
        raise GceEndorsementError(f"{where}: its two signature algorithm fields differ")
    _require_pss_sha256_salt32(parts.tbs_signature_algorithm, where)
    try:
        root.public_key.verify(
            cert.signature, cert.tbs_certificate_bytes, _PSS_SHA256_SALT32, hashes.SHA256()
        )
    except InvalidSignature:
        raise GceEndorsementError(f"{where} does not verify under the trusted root") from None
    try:
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise GceEndorsementError(f"{where}: {exc}") from None
    if aki.key_identifier != root.subject_key_identifier:
        raise GceEndorsementError(f"{where}: its authority key id is not the root's key id")
    usage = key_usage.value
    if (
        not key_usage.critical
        or not usage.digital_signature
        or usage.content_commitment
        or usage.key_encipherment
        or usage.data_encipherment
        or usage.key_agreement
        or usage.key_cert_sign
        or usage.crl_sign
    ):
        raise GceEndorsementError(f"{where}: key usage must be critical digitalSignature only")
    if basic.ca:
        raise GceEndorsementError(f"{where} is a CA certificate")
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < MIN_SIGNER_RSA_BITS:
        raise GceEndorsementError(f"{where} does not carry an RSA key of at least 3072 bits")
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise GceEndorsementError(
            f"{where} is not valid at {now.isoformat()} "
            f"({cert.not_valid_before_utc.isoformat()} .. {cert.not_valid_after_utc.isoformat()})"
        )
    return cert


@dataclass(frozen=True)
class VerifiedSnpEndorsement:
    svn: int
    # launch-VMSA count -> lower-case hex of the 48-byte MEASUREMENT, ascending by count
    measurements: tuple[tuple[int, str], ...]
    family_id: str
    image_id: str
    policy: int
    svsm_measurement: Optional[str]

    def measurement(self, vmsas: int) -> Optional[str]:
        for count, value in self.measurements:
            if count == vmsas:
                return value
        return None


@dataclass(frozen=True)
class VerifiedTdxMeasurement:
    ram_gib: int
    early_accept: bool
    mrtd: str


@dataclass(frozen=True)
class VerifiedTdxEndorsement:
    svn: int
    measurements: tuple[VerifiedTdxMeasurement, ...]


@dataclass(frozen=True)
class VerifiedGceEndorsement:
    """A launch endorsement whose chain and payload signature verified at ``now``."""

    uefi_sha384: str
    timestamp: dt.datetime
    cl_spec: int
    commit: str
    signer_serial: int
    signer_spki_sha256: str
    signer_not_after: dt.datetime
    endorsement_sha256: str
    snp: Optional[VerifiedSnpEndorsement]
    tdx: Optional[VerifiedTdxEndorsement]


def verify_launch_endorsement(
    blob: bytes, *, now: dt.datetime, trusted_root_der: Optional[bytes] = None
) -> VerifiedGceEndorsement:
    """Verify a ``VMLaunchEndorsement`` against the pinned GCE root at ``now``.

    ``trusted_root_der`` is a test-only root seam (the negative chains); other callers only
    forward their own parameter, which tests alone set.
    """
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise TypeError("now must be a timezone-aware datetime")
    parsed = parse_launch_endorsement(blob)
    golden = parsed.golden
    # (1) Google's provenance rule.
    if golden.timestamp is None:
        raise GceEndorsementError("VMGoldenMeasurement carries no timestamp")
    if golden.timestamp > PROVENANCE_REQUIRED_AFTER and golden.cl_spec == 0 and not golden.commit:
        raise GceEndorsementError(
            "VMGoldenMeasurement after 2024-08-02 names neither a cl_spec nor a commit "
            "(missing provenance)"
        )
    # (2) the signer certificate under the pinned root (never a ca_bundle).
    root = _trusted_root(
        GCE_CC_TCB_ROOT_DER if trusted_root_der is None else bytes(trusted_root_der)
    )
    signer = _verified_signer(golden.cert, root, now)
    # (3) the payload signature: one scheme, over the exact serialized golden bytes.
    try:
        signer.public_key().verify(
            parsed.signature, parsed.serialized_uefi_golden, _PSS_SHA256_SALT32, hashes.SHA256()
        )
    except InvalidSignature:
        raise GceEndorsementError(
            "the launch endorsement's payload signature does not verify"
        ) from None
    spki = signer.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    snp = golden.sev_snp
    tdx = golden.tdx
    return VerifiedGceEndorsement(
        uefi_sha384=golden.digest.hex(),
        timestamp=golden.timestamp,
        cl_spec=golden.cl_spec,
        commit=golden.commit.hex(),
        signer_serial=signer.serial_number,
        signer_spki_sha256=hashlib.sha256(spki).hexdigest(),
        signer_not_after=signer.not_valid_after_utc,
        endorsement_sha256=hashlib.sha256(bytes(blob)).hexdigest(),
        snp=None
        if snp is None
        else VerifiedSnpEndorsement(
            svn=snp.svn,
            measurements=tuple((count, value.hex()) for count, value in snp.measurements),
            family_id=str(uuid.UUID(bytes=snp.family_id)),
            image_id=str(uuid.UUID(bytes=snp.image_id)),
            policy=snp.policy,
            svsm_measurement=snp.svsm_measurement.hex() or None,
        ),
        tdx=None
        if tdx is None
        else VerifiedTdxEndorsement(
            svn=tdx.svn,
            measurements=tuple(
                VerifiedTdxMeasurement(
                    ram_gib=item.ram_gib, early_accept=item.early_accept, mrtd=item.mrtd.hex()
                )
                for item in tdx.measurements
            ),
        ),
    )


# --- object names (the operator tool and refusal messages only; nothing here fetches) ----------

_TEE_OBJECT_DIRECTORIES = {"tdx": "tdx", "sev-snp": "sevsnp"}


def gce_endorsement_object_name(tee: str, value: str) -> str:
    """Google's storage object of the endorsement indexed by a TDX MRTD or SEV-SNP MEASUREMENT."""
    directory = _TEE_OBJECT_DIRECTORIES.get(tee)
    if directory is None:
        raise ValueError(f"unknown TEE {tee!r}: expected 'tdx' or 'sev-snp'")
    if not isinstance(value, str) or not _HEX96.fullmatch(value):
        raise ValueError("a launch value must be 96 hex digits")
    return f"ovmf_x64_csm/{directory}/{value.lower()}.binarypb"


def gce_firmware_binary_object_name(uefi_sha384: str) -> str:
    """Google's storage object of the published firmware binary of one build."""
    if not isinstance(uefi_sha384, str) or not _HEX96.fullmatch(uefi_sha384):
        raise ValueError("a UEFI digest must be 96 hex digits")
    return f"ovmf_x64_csm/{uefi_sha384.lower()}.fd"


# === The TDVF CFV derivation and the RTMR0 template ==============================================
# Chutes' validator's GCP TDX functions: the TDVF constants, ``_le``, ``derive_cfv_sha384`` (the
# logic of ``measure_cfv`` in platform-predictor/src/tdvf.rs) and ``evaluate_rtmr0_template``.
# ``GceFirmwareBundleError`` is the validator's name for a binary whose TDVF layout is refused.

import struct  # noqa: E402
from typing import Mapping  # noqa: E402


class GceFirmwareBundleError(ValueError):
    """A firmware binary whose TDVF layout is refused (never indexed)."""


# OVMF GUIDed table footer and the TDX metadata entry (QEMU hw/i386/pc_sysfw_ovmf.c; tdx-measure
# tdvf.rs).  The table ends 32 bytes before the end of the binary.
_TABLE_FOOTER_GUID = uuid.UUID("96b582de-1fb2-45f7-baea-a366c55a082d").bytes_le
_TDX_METADATA_GUID = uuid.UUID("e47a6535-984a-4798-865e-4685a7bf8ec2").bytes_le
_BYTES_AFTER_TABLE_FOOTER = 32
_TDVF_SECTION_TD_CFV = 0x01


def _le(fmt: str, buf: bytes, offset: int, what: str) -> tuple:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(buf):
        raise GceFirmwareBundleError(f"TDVF metadata: {what} lies outside the binary")
    return struct.unpack_from(fmt, buf, offset)


def derive_cfv_sha384(binary: bytes) -> str:
    """SHA-384 (lower-case hex) of the one TDVF section of type 1 (the CFV) of an OVMF binary."""
    size = len(binary)
    footer_end = size - _BYTES_AFTER_TABLE_FOOTER
    if footer_end < 18 or binary[footer_end - 16 : footer_end] != _TABLE_FOOTER_GUID:
        raise GceFirmwareBundleError("TDVF metadata: the OVMF table footer GUID is absent")
    (footer_length,) = _le("<H", binary, footer_end - 18, "the table footer length")
    table_length = footer_length - 18
    table_end = footer_end - 18
    if table_length < 0 or table_length > table_end:
        raise GceFirmwareBundleError("TDVF metadata: invalid OVMF table length")
    table = binary[table_end - table_length : table_end]
    position = len(table)
    entry_data = None
    while position >= 18:
        (entry_length,) = _le("<H", table, position - 18, "an OVMF table entry")
        if entry_length < 18 or entry_length > position:
            raise GceFirmwareBundleError("TDVF metadata: invalid OVMF table entry length")
        if table[position - 16 : position] == _TDX_METADATA_GUID:
            entry_data = table[position - entry_length : position - 18]
            break
        position -= entry_length
    if entry_data is None or len(entry_data) < 4:
        raise GceFirmwareBundleError("TDVF metadata: the TDX metadata offset entry is absent")
    (offset_from_end,) = struct.unpack_from("<I", entry_data, len(entry_data) - 4)
    descriptor = size - offset_from_end
    (signature, _length, version, sections) = _le("<4sIII", binary, descriptor, "the descriptor")
    if signature != b"TDVF":
        raise GceFirmwareBundleError("TDVF metadata: invalid TDVF descriptor")
    if version != 1:
        raise GceFirmwareBundleError("TDVF metadata: unsupported TDVF version")
    if sections == 0 or sections > 64:
        raise GceFirmwareBundleError("TDVF metadata: implausible section count")
    cfv = []
    for index in range(sections):
        data_offset, raw_size, _address, _memory_size, kind, _attributes = _le(
            "<IIQQII", binary, descriptor + 16 + 32 * index, f"section {index}"
        )
        if kind == _TDVF_SECTION_TD_CFV:
            cfv.append((data_offset, raw_size))
    if len(cfv) != 1:
        raise GceFirmwareBundleError(
            f"TDVF metadata: {len(cfv)} CFV sections, exactly one expected"
        )
    data_offset, raw_size = cfv[0]
    if raw_size == 0 or data_offset + raw_size > size:
        raise GceFirmwareBundleError("TDVF metadata: the CFV section lies outside the binary")
    return hashlib.sha384(binary[data_offset : data_offset + raw_size]).hexdigest()


def evaluate_rtmr0_template(template: Mapping, cfv_sha384: str) -> str:
    """``RTMR0 = fold(sha384(before_cfv || cfv), after_cfv)`` (upper-case hex), where
    ``before_cfv`` is the register after the TD HOB event and ``after_cfv`` the ordered event
    digests that follow the configuration-volume event."""
    register = hashlib.sha384(
        bytes.fromhex(template["before_cfv"]) + bytes.fromhex(cfv_sha384)
    ).digest()
    for digest in template["after_cfv"]:
        register = hashlib.sha384(register + bytes.fromhex(digest)).digest()
    return register.hex().upper()

# === The firmware index =========================================================================

import contextlib  # noqa: E402
import os  # noqa: E402
import stat  # noqa: E402
from pathlib import Path  # noqa: E402

GCE_FIRMWARE_INDEX_SCHEMA = "chutes.gce-firmware-index.v1"
GCE_TCB_INTEGRITY_BASE_URL = "https://storage.googleapis.com/gce_tcb_integrity/"
MAX_INDEX_BUILDS = 64
MAX_BINARY_BYTES = 4 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 30
_BUILD_FILE = re.compile(r"([0-9a-f]{96})\.(binarypb|fd)")
_HEX96_LOWER = re.compile(r"[0-9a-f]{96}")


class FirmwareRefusal(ValueError):
    """A refusal of the GCP firmware value or of the firmware index, with its code:
    ``firmware_unendorsed``, ``firmware_vcpu_mismatch``, ``firmware_below_floor``,
    ``firmware_index_invalid`` or ``firmware_refresh_failed``."""

    def __init__(self, code: str, text: str):
        self.code, self.text = code, text
        super().__init__(f"GCP firmware refused ({code}): {text}")


@dataclass(frozen=True)
class SnpBuild:
    """One verified build of the index (its SEV-SNP members)."""

    uefi_sha384: str
    endorsement_sha256: str
    endorsed_at: dt.datetime
    signer_not_after: dt.datetime
    svn: int
    # launch-VMSA (vCPU) count -> lower-case MEASUREMENT hex, GCE family, counts of at least 2
    measurements: tuple[tuple[int, str], ...]
    # The build's changelist number (0: none named), the key the firmware floor compares.
    cl_spec: int = 0


@dataclass(frozen=True)
class SnpAdmission:
    build: SnpBuild
    vcpus: int

    def display(self) -> str:
        """The build's display line."""
        return (
            f"Google firmware {self.build.uefi_sha384}, endorsed "
            f"{self.build.endorsed_at.strftime('%Y-%m-%d')}"
        )


@dataclass(frozen=True)
class TdxBuild:
    """One verified build of the index (its TDX members): the MRTDs Google endorses for any
    RAM size (``ram_gib`` 0) or one RAM size, never an early-accept entry, and the CFV derived from
    Google's binary of that build (None until the binary is in the index: never admitted then)."""

    uefi_sha384: str
    endorsement_sha256: str
    endorsed_at: dt.datetime
    signer_not_after: dt.datetime
    svn: int
    mrtds: tuple[tuple[int, str], ...]  # (ram_gib, lower-case MRTD hex)
    cfv_sha384: Optional[str]
    cl_spec: int = 0


@dataclass(frozen=True)
class TdxAdmission:
    build: TdxBuild
    mrtd: str

    def display(self) -> str:
        return (
            f"Google firmware {self.build.uefi_sha384}, endorsed "
            f"{self.build.endorsed_at.strftime('%Y-%m-%d')} (TDX MRTD {self.mrtd[:16]}…)"
        )


class OwnerFirmwareIndex:
    """The lookup index of the verified endorsements (immutable)."""

    def __init__(self, builds, root_sha256: str, tdx_builds=()):
        self.builds = tuple(sorted(builds, key=lambda build: build.uefi_sha384))
        self.tdx_builds = tuple(sorted(tdx_builds, key=lambda build: build.uefi_sha384))
        self.root_sha256 = root_sha256
        self.valid_until = min(
            (build.signer_not_after for build in (*self.builds, *self.tdx_builds)), default=None
        )
        self.sha256 = hashlib.sha256(self.canonical_bytes()).hexdigest()

    def admissions(self, measurement: str) -> tuple[SnpAdmission, ...]:
        value = str(measurement).lower()
        return tuple(
            SnpAdmission(build, vcpus)
            for build in self.builds
            for vcpus, item in build.measurements
            if item == value
        )

    def tdx_admissions(self, mrtd: str, ram_gib: Optional[int]) -> tuple[TdxAdmission, ...]:
        """Builds whose endorsement lists ``mrtd`` for any RAM size or for ``ram_gib``."""
        value = str(mrtd).lower()
        return tuple(
            TdxAdmission(build, value)
            for build in self.tdx_builds
            if any(item == value and gib in (0, ram_gib) for gib, item in build.mrtds)
        )

    def document(self) -> dict:
        """``chutes.gce-firmware-index.v1`` with the validator's key set."""

        def iso(when):
            return when.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if when else None

        snp = {build.uefi_sha384: build for build in self.builds}
        tdx = {build.uefi_sha384: build for build in self.tdx_builds}
        documents = []
        for uefi in sorted(set(snp) | set(tdx)):
            first = snp.get(uefi) or tdx[uefi]
            documents.append({
                "uefi_sha384": uefi,
                "endorsement_sha256": first.endorsement_sha256,
                "signer_not_after": iso(first.signer_not_after),
                "snp": None if uefi not in snp else {
                    "svn": snp[uefi].svn,
                    "measurements": {str(vcpus): value for vcpus, value in snp[uefi].measurements},
                },
                "tdx": None if uefi not in tdx else {
                    "svn": tdx[uefi].svn,
                    "mrtds": [value for _, value in tdx[uefi].mrtds],
                },
                "cfv_sha384": tdx[uefi].cfv_sha384 if uefi in tdx else None,
            })
        return {
            "schema": GCE_FIRMWARE_INDEX_SCHEMA,
            "root_sha256": self.root_sha256,
            "valid_until": iso(self.valid_until),
            "builds": documents,
        }

    def canonical_bytes(self) -> bytes:
        import json

        return json.dumps(self.document(), sort_keys=True, separators=(",", ":")).encode("utf-8")


def firmware_dir() -> Path:
    from chutes.entrypoint.owner_vm_state import state_dir

    return state_dir() / "firmware"


def _snp_build(verified: VerifiedGceEndorsement) -> Optional[SnpBuild]:
    snp = verified.snp
    if snp is None or snp.family_id != GCE_UEFI_FAMILY_ID:
        return None
    rows, seen = [], {}
    for vcpus, value in snp.measurements:
        if vcpus < 2:  # key 1 selects Google's SVSM value; key 0 none (the validator's rule)
            continue
        if value in seen:
            raise FirmwareRefusal(
                "firmware_index_invalid",
                f"build {verified.uefi_sha384} lists one measurement under two vCPU keys",
            )
        seen[value] = vcpus
        rows.append((vcpus, value))
    if not rows:
        return None
    return SnpBuild(
        uefi_sha384=verified.uefi_sha384,
        endorsement_sha256=verified.endorsement_sha256,
        endorsed_at=verified.timestamp,
        signer_not_after=verified.signer_not_after,
        svn=snp.svn,
        measurements=tuple(rows),
        cl_spec=verified.cl_spec,
    )


def _tdx_build(verified: VerifiedGceEndorsement, cfv_sha384: Optional[str]) -> Optional[TdxBuild]:
    tdx = verified.tdx
    if tdx is None:
        return None
    rows = []
    for entry in tdx.measurements:
        if entry.early_accept:  # the validator's rule: an early-accept MRTD is never admitted
            continue
        row = (entry.ram_gib, entry.mrtd)
        if row in rows:
            raise FirmwareRefusal(
                "firmware_index_invalid", f"build {verified.uefi_sha384} lists one TDX MRTD twice"
            )
        rows.append(row)
    if not rows:
        return None
    return TdxBuild(
        uefi_sha384=verified.uefi_sha384,
        endorsement_sha256=verified.endorsement_sha256,
        endorsed_at=verified.timestamp,
        signer_not_after=verified.signer_not_after,
        svn=tdx.svn,
        mrtds=tuple(rows),
        cfv_sha384=cfv_sha384,
        cl_spec=verified.cl_spec,
    )


def _read_file(path: Path, bound: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise FirmwareRefusal("firmware_index_invalid", f"{path} is not your private regular file")
        blob = stream.read(bound + 1)
    if len(blob) > bound:
        raise FirmwareRefusal("firmware_index_invalid", f"{path} exceeds {bound} bytes")
    return blob


def _read_build(path: Path) -> bytes:
    return _read_file(path, MAX_ENDORSEMENT_BYTES)


def binary_cfv(binary: bytes, uefi_sha384: str) -> str:
    """The CFV of Google's binary of build ``uefi_sha384``: the binary must hash (SHA-384) to the
    endorsed digest; its TDVF layout then names exactly one CFV section."""
    if hashlib.sha384(binary).hexdigest() != uefi_sha384:
        raise FirmwareRefusal("firmware_index_invalid", f"the binary is not build {uefi_sha384[:16]}…")
    try:
        return derive_cfv_sha384(binary)
    except GceFirmwareBundleError as exc:
        raise FirmwareRefusal("firmware_index_invalid", f"build {uefi_sha384[:16]}…: {exc}") from None


def load_index(directory: Optional[Path] = None, *, now: dt.datetime, trusted_root_der=None):
    """Verify every endorsement in the directory under Google's root at ``now`` and index them;
    a TDX build's CFV comes from its binary ``<uefi_sha384>.fd`` when present (it must hash to the
    name and have an endorsement). Any entry other than ``<uefi_sha384>.binarypb`` or ``.fd``, a
    symlink, a name that is not its endorsement's digest or an endorsement that does not verify
    refuses the whole index (``firmware_index_invalid``); an absent directory is an empty index."""
    directory = directory or firmware_dir()
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except FileNotFoundError:
        entries = []
    endorsements, binaries = {}, {}
    for entry in entries:
        if entry.name.startswith(".") and entry.name.endswith(".tmp"):
            continue
        match = _BUILD_FILE.fullmatch(entry.name)
        if match is None or entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            raise FirmwareRefusal(
                "firmware_index_invalid", f"unexpected entry {entry.name!r} in {directory}"
            )
        (endorsements if match.group(2) == "binarypb" else binaries)[match.group(1)] = Path(entry.path)
    if len(endorsements) > MAX_INDEX_BUILDS:
        raise FirmwareRefusal("firmware_index_invalid", f"more than {MAX_INDEX_BUILDS} builds")
    stray = sorted(set(binaries) - set(endorsements))
    if stray:
        raise FirmwareRefusal("firmware_index_invalid", f"the binary {stray[0][:16]}….fd has no endorsement")
    builds, tdx_builds = [], []
    for name, path in endorsements.items():
        try:
            verified = verify_launch_endorsement(_read_build(path), now=now, trusted_root_der=trusted_root_der)
        except GceEndorsementError as exc:
            raise FirmwareRefusal("firmware_index_invalid", f"{path.name}: {exc}") from None
        if verified.uefi_sha384 != name:
            raise FirmwareRefusal(
                "firmware_index_invalid", f"{path.name} is not named by its endorsement's digest"
            )
        build = _snp_build(verified)
        if build is not None:
            builds.append(build)
        cfv = binary_cfv(_read_file(binaries[name], MAX_BINARY_BYTES), name) if name in binaries else None
        tdx_build = _tdx_build(verified, cfv)
        if tdx_build is not None:
            tdx_builds.append(tdx_build)
    root = GCE_CC_TCB_ROOT_DER if trusted_root_der is None else bytes(trusted_root_der)
    return OwnerFirmwareIndex(builds, hashlib.sha256(root).hexdigest(), tdx_builds)


def parse_floor(gcp_block: dict) -> tuple[dt.datetime, int]:
    """The signed ``owner_vm.gcp`` floor: ``min_endorsed_at`` (RFC 3339, UTC) and the SVN floor
    (``min_svn`` when signed, never below the code floor)."""
    text = gcp_block.get("min_endorsed_at")
    if not isinstance(text, str):
        raise FirmwareRefusal("firmware_below_floor", "the signed release names no min_endorsed_at")
    try:
        when = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise FirmwareRefusal("firmware_below_floor", "the signed min_endorsed_at is not a time") from None
    if when.tzinfo is None:
        raise FirmwareRefusal("firmware_below_floor", "the signed min_endorsed_at has no time zone")
    min_svn = gcp_block.get("min_svn", GCE_FIRMWARE_SVN_CODE_FLOOR)
    if type(min_svn) is not int:
        raise FirmwareRefusal("firmware_below_floor", "the signed min_svn is not an integer")
    return when, max(min_svn, GCE_FIRMWARE_SVN_CODE_FLOOR)


def _require_current(index: OwnerFirmwareIndex, now) -> None:
    if index.valid_until is not None and now > index.valid_until:
        raise FirmwareRefusal(
            "firmware_index_invalid", "an endorsement signer of your index has expired; refresh it"
        )


def check_measurement(index: OwnerFirmwareIndex, measurement: str, vcpus: int, gcp_block: dict, *, now):
    """The admission of ``measurement`` for a ``vcpus`` shape under the signed floor, or a
    :class:`FirmwareRefusal` (``firmware_unendorsed``, ``firmware_vcpu_mismatch``,
    ``firmware_below_floor``)."""
    _require_current(index, now)
    found = index.admissions(measurement)
    if not found:
        raise FirmwareRefusal(
            "firmware_unendorsed",
            f"MEASUREMENT {str(measurement).lower()[:16]}… is not in your firmware index",
        )
    shaped = [admission for admission in found if admission.vcpus == vcpus]
    if not shaped:
        raise FirmwareRefusal(
            "firmware_vcpu_mismatch",
            f"Google endorses this MEASUREMENT for {sorted({a.vcpus for a in found})} vCPUs, not {vcpus}",
        )
    min_endorsed_at, min_svn = parse_floor(gcp_block)
    current = [
        admission
        for admission in shaped
        if admission.build.endorsed_at >= min_endorsed_at and admission.build.svn >= min_svn
    ]
    if not current:
        raise FirmwareRefusal(
            "firmware_below_floor",
            f"the endorsed firmware predates the release's floor ({gcp_block.get('min_endorsed_at')}, "
            f"SVN {min_svn})",
        )
    return max(current, key=lambda admission: admission.build.endorsed_at)


def check_mrtd(index: OwnerFirmwareIndex, mrtd: str, ram_gib: Optional[int], gcp_block: dict, *, now):
    """GCP TDX, the MRTD from the endorsed set: the builds admitting ``mrtd`` for this RAM
    size under the signed floor, newest first, each with its CFV; or ``firmware_unendorsed`` (no
    endorsement lists it, or no listing build's binary is in the index) or
    ``firmware_below_floor``."""
    _require_current(index, now)
    found = [admission for admission in index.tdx_admissions(mrtd, ram_gib)
             if admission.build.cfv_sha384 is not None]
    if not found:
        raise FirmwareRefusal(
            "firmware_unendorsed",
            f"TDX MRTD {str(mrtd).lower()[:16]}… is not in your firmware index (with its binary)",
        )
    min_endorsed_at, min_svn = parse_floor(gcp_block)
    current = [
        admission
        for admission in found
        if admission.build.endorsed_at >= min_endorsed_at and admission.build.svn >= min_svn
    ]
    if not current:
        raise FirmwareRefusal(
            "firmware_below_floor",
            f"the endorsed firmware predates the release's floor ({gcp_block.get('min_endorsed_at')}, "
            f"SVN {min_svn})",
        )
    return sorted(current, key=lambda admission: admission.build.endorsed_at, reverse=True)


@dataclass(frozen=True)
class Rtmr0Selection:
    """The admitted build and the RTMR0 values accepted on it: ``values[0]`` is the
    base template's, ``values[n]`` the n-th signed ACPI-variant alternative's, each at that
    build's CFV; ``matched`` is the index the pre-read RTMR0 equals, or None."""

    admission: TdxAdmission
    values: tuple
    matched: Optional[int]


def select_rtmr0(admissions, templates, observed_rtmr0: Optional[str]) -> Rtmr0Selection:
    """The admitted build and template whose value equals the pre-read RTMR0 (builds that share an
    MRTD differ in the CFV only; ``templates`` = [the base template, *its signed ACPI-variant
    alternatives]), else the newest build with no match: the verifier's exact RTMR0 compare then
    decides (the validator's rules). Values are exact, one per signed template: no pattern."""
    observed = str(observed_rtmr0 or "").upper()
    selections = []
    for admission in admissions:
        values = tuple(evaluate_rtmr0_template(template, admission.build.cfv_sha384) for template in templates)
        matched = values.index(observed) if observed in values else None
        selections.append(Rtmr0Selection(admission, values, matched))
    return next((item for item in selections if item.matched is not None), selections[0])


def _download(url: str, max_bytes: int) -> bytes:  # pragma: no cover - network; tests inject
    from urllib.request import HTTPRedirectHandler, Request, build_opener

    class _NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise FirmwareRefusal("firmware_refresh_failed", "redirects are refused")

    opener = build_opener(_NoRedirect)
    with opener.open(Request(url, method="GET"), timeout=FETCH_TIMEOUT_SECONDS) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise FirmwareRefusal("firmware_refresh_failed", f"{url} exceeds {max_bytes} bytes")
    return data


def _publish(directory: Path, name: str, blob: bytes) -> None:
    from chutes.entrypoint.owner_vm_state import ensure_dir, write_atomic

    ensure_dir(directory.parent)
    ensure_dir(directory)
    target = directory / name
    try:
        if target.read_bytes() == blob:
            return
    except FileNotFoundError:
        pass
    write_atomic(target, blob)


def _fetch_verified(fetch, url, now, trusted_root_der):
    try:
        blob = fetch(url, MAX_ENDORSEMENT_BYTES)
        return blob, verify_launch_endorsement(blob, now=now, trusted_root_der=trusted_root_der)
    except FirmwareRefusal:
        raise
    except GceEndorsementError as exc:
        raise FirmwareRefusal("firmware_refresh_failed", f"{url}: {exc}") from None
    except Exception as exc:  # noqa: BLE001 - any transport failure: nothing written
        raise FirmwareRefusal("firmware_refresh_failed", f"{url}: {type(exc).__name__}: {exc}") from None


def _fetch_binary(fetch, directory: Path, uefi_sha384: str) -> Optional[bytes]:
    """Google's binary of a TDX build (verified against the endorsed digest and its TDVF layout),
    or None when the index already holds it."""
    if (directory / f"{uefi_sha384}.fd").exists():
        return None
    url = GCE_TCB_INTEGRITY_BASE_URL + gce_firmware_binary_object_name(uefi_sha384)
    try:
        binary = fetch(url, MAX_BINARY_BYTES)
    except FirmwareRefusal:
        raise
    except Exception as exc:  # noqa: BLE001 - any transport failure: nothing written
        raise FirmwareRefusal("firmware_refresh_failed", f"{url}: {type(exc).__name__}: {exc}") from None
    try:
        binary_cfv(bytes(binary), uefi_sha384)
    except FirmwareRefusal as exc:
        raise FirmwareRefusal("firmware_refresh_failed", f"{url}: {exc.text}") from None
    return bytes(binary)


def refresh(
    measurements=(),
    *,
    mrtds=(),
    directory: Optional[Path] = None,
    now: dt.datetime,
    fetch=None,
    trusted_root_der=None,
    refetch_stored: bool = True,
):
    """Fetch Google's endorsement for each SEV-SNP ``measurement`` and each TDX ``mrtd`` (and,
    with ``refetch_stored``, again for every build already in the index, by its first indexed
    value), verify each under Google's root, keep only those that verify and list the value, and
    drop a stored build that no longer verifies. A TDX build also gets Google's binary of that
    build (``ovmf_x64_csm/<uefi>.fd``), kept only when it hashes to the endorsed digest and names
    one CFV. Returns ``(index, lines)``. Nothing is written for a refused endorsement or binary.
    A stored build whose refetch fails (Google no longer serves its object, or serves it changed) is
    kept as it is and reported: removal is not revocation. A stored build that no longer verifies is
    removed."""
    directory = directory or firmware_dir()
    fetch = fetch or _download
    lines = []
    wanted = [("sev-snp", str(value).lower()) for value in measurements]
    wanted += [("tdx", str(value).lower()) for value in mrtds]
    for tee, value in wanted:
        if not _HEX96_LOWER.fullmatch(value):
            raise FirmwareRefusal("firmware_refresh_failed",
                                  "a MEASUREMENT or MRTD is 96 hex digits")
    try:
        stored = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except FileNotFoundError:
        stored = []
    stored_refetch = set()
    for entry in stored:
        match = _BUILD_FILE.fullmatch(entry.name)
        if match is None or entry.is_symlink() or match.group(2) != "binarypb":
            continue
        try:
            verified = verify_launch_endorsement(
                _read_build(Path(entry.path)), now=now, trusted_root_der=trusted_root_der
            )
            build, tdx_build = _snp_build(verified), _tdx_build(verified, None)
        except (GceEndorsementError, FirmwareRefusal) as exc:
            os.unlink(entry.path)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(directory / f"{match.group(1)}.fd")
            lines.append(f"removed {entry.name[:16]}… (no longer verifies: {exc})")
            continue
        if refetch_stored and build is not None and ("sev-snp", build.measurements[0][1]) not in wanted:
            wanted.append(("sev-snp", build.measurements[0][1]))
            stored_refetch.add(("sev-snp", build.measurements[0][1]))
        if refetch_stored and tdx_build is not None and ("tdx", tdx_build.mrtds[0][1]) not in wanted:
            wanted.append(("tdx", tdx_build.mrtds[0][1]))
            stored_refetch.add(("tdx", tdx_build.mrtds[0][1]))
    for tee, value in wanted:
        url = GCE_TCB_INTEGRITY_BASE_URL + gce_endorsement_object_name(tee, value)
        try:
            blob, verified = _fetch_verified(fetch, url, now, trusted_root_der)
            if tee == "sev-snp":
                build = _snp_build(verified)
                if build is None or not any(item == value for _, item in build.measurements):
                    raise FirmwareRefusal("firmware_refresh_failed", f"{url} does not list {value[:16]}…")
                svn = build.svn
                binary = None
            else:
                tdx_build = _tdx_build(verified, None)
                if tdx_build is None or not any(item == value for _, item in tdx_build.mrtds):
                    raise FirmwareRefusal("firmware_refresh_failed", f"{url} does not list {value[:16]}…")
                svn = tdx_build.svn
                binary = _fetch_binary(fetch, directory, verified.uefi_sha384)
        except FirmwareRefusal as exc:
            if (tee, value) not in stored_refetch:
                raise
            lines.append(f"kept {value[:16]}… as stored (Google does not serve it now: {exc.text})")
            continue
        _publish(directory, f"{verified.uefi_sha384}.binarypb", bytes(blob))
        if binary is not None:
            _publish(directory, f"{verified.uefi_sha384}.fd", binary)
        lines.append(
            f"endorsed build {verified.uefi_sha384[:16]}… (SVN {svn}, "
            f"{verified.timestamp.strftime('%Y-%m-%d')})"
            + (", with its binary" if binary is not None else "")
        )
    index = load_index(directory, now=now, trusted_root_der=trusted_root_der)
    lines.append(f"index sha256 {index.sha256} ({len(index.builds) + len(index.tdx_builds)} builds)")
    return index, lines
