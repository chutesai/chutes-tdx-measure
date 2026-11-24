"""The GCP measurement-prediction model.

A pure model of what a GCP Confidential VM measures while it boots Chutes' GCP image layout (shim,
GRUB with a static ``grub.cfg``, a dm-verity root): every image-dependent register is computed from
the image's own boot-chain digests (a ``chutes.gcp-prediction-inputs.v1`` manifest read from the
sealed disk, never from a booted VM), the per-shape platform profile and UEFI-defaults era, the
``dbx`` the boot measures and the Secure Boot posture.
Such an image is created with its sealed root's signed ``dbx`` update (``dbxupdate_x64.bin``,
an ``EFI_VARIABLE_AUTHENTICATION_2``, the form Canonical's stock images carry) as its ``dbx``
initial state; the firmware replaces Google's default ``dbx`` with the update's payload, and the
image masks every ``dbx`` writer, so the predictor passes that payload
(``authenticated_update_payload``). The model itself takes any ``dbx``: an image with no ``dbx``
initial state measures the era's default on its first boot and, on later boots, the default with
the update appended (``dbx_after_update``).

* **TDX (CCEL, SHA-384).** RTMR1 (PCR2-6 folded): the calling action, a separator, the GPT, shim,
  GRUB (+ the kernel with Secure Boot on) and the two exit-boot-services actions. RTMR2 (PCR8-15
  folded): shim's three MOK events, then GRUB's commands and files and the kernel command line of
  the static ``grub.cfg`` (one literal list, no GRUB interpreter). RTMR0: the signed **template**
  ``{before_cfv, after_cfv[]}`` -- the profile's TD HOB before the configuration-volume slot, the
  Secure Boot variables, the profile's ACPI tables, the boot options and shim's ``SbatLevel``
  after it -- evaluated with the CFV of a Google-endorsed firmware build.
* **SEV-SNP (GCE vTPM, SHA-256).** PCR4: the calling action, a separator, shim, GRUB (+ kernel with
  Secure Boot on); PCR7: SecureBoot, PK, KEK, db, ``dbx``, a separator (+ the db authority that
  verified shim with Secure Boot on), ``SbatLevel`` (+ the ``MokListRT`` authority with Secure Boot
  on); PCR8: GRUB's commands and the kernel command line; PCR9: GRUB's file reads and the Linux EFI
  stub's ``LoadOptions`` and ``Linux initrd`` events. PCR0 is **not pinned**: it is GCE's firmware
  statement, ``gce_pcr0(svn, "sev-snp")``, checked by derivation (Chutes' validator computes the
  same function).

Only GRUB's behaviour on the static ``grub.cfg`` is modelled: a ``grub.cfg`` that is not exactly
the template's rendering is refused, so the GRUB part of RTMR2/PCR8/PCR9 is a literal list. Every
``EV_NO_ACTION`` record (the TCG Spec ID event, the SP800-155 records) extends no register and is
never part of a list. Standard library only (the Authenticode signer is located by a minimal DER walk).
"""

from __future__ import annotations

import datetime
import hashlib
import re
import struct
import uuid
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Iterable,
    Mapping,
    NamedTuple,
    NoReturn,
    Optional,
    Sequence,
)

INPUTS_SCHEMA = "chutes.gcp-prediction-inputs.v1"
PREDICTION_SCHEMA = "chutes.gcp-measurement-prediction.v1"
PCR0_RULE = "gce-pcr0-v1"

EV_NO_ACTION = 0x00000003
EV_SEPARATOR = 0x00000004
EV_EVENT_TAG = 0x00000006
EV_S_CRTM_VERSION = 0x00000008
EV_PLATFORM_CONFIG_FLAGS = 0x0000000A
EV_IPL = 0x0000000D
EV_NONHOST_INFO = 0x00000011
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
EV_EFI_VARIABLE_BOOT = 0x80000002
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
EV_EFI_GPT_EVENT = 0x80000006
EV_EFI_ACTION = 0x80000007
EV_EFI_PLATFORM_FIRMWARE_BLOB2 = 0x8000000A
EV_EFI_HANDOFF_TABLES2 = 0x8000000B
EV_EFI_VARIABLE_AUTHORITY = 0x800000E0

EFI_GLOBAL_VARIABLE = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
EFI_IMAGE_SECURITY_DATABASE = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
SHIM_LOCK = uuid.UUID("605dab50-e046-4300-abb6-3dd810dd8b23")
EFI_CERT_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256 = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
EFI_CERT_TYPE_PKCS7 = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
EFI_SYSTEM_PARTITION = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
XBOOTLDR_PARTITION = uuid.UUID("bc13c2ff-59e6-4262-a352-b275fd6f7172")
WIN_CERT_TYPE_EFI_GUID = 0x0EF1
WIN_CERT_REVISION_2_0 = 0x0200
# PKCS#7 (RFC 2315) content types, as DER OBJECT IDENTIFIER contents: id-data, id-signedData.
PKCS7_DATA_OID = bytes.fromhex("2a864886f70d010701")
PKCS7_SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
# The algorithms the UEFI profile of an EFI_VARIABLE_AUTHENTICATION_2's SignedData admits (UEFI 2.10
# 8.2.2): id-sha256 (NIST), rsaEncryption and sha256WithRSAEncryption (PKCS #1).
ID_SHA256_OID = bytes.fromhex("608648016503040201")
RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")
SHA256_WITH_RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d01010b")

ALGORITHMS = {"sha256": 32, "sha384": 48}
CALLING_EFI_APPLICATION = b"Calling EFI Application from Boot Option"
EXIT_BOOT_SERVICES_INVOCATION = b"Exit Boot Services Invocation"
EXIT_BOOT_SERVICES_SUCCESS = b"Exit Boot Services Returned with Success"
SEPARATOR = bytes(4)
LST_FILES = ("command", "fs", "crypto", "terminal")
STATIC_MENU_TITLE = "chutes"
# The TCG PC Client tagged events of the Linux EFI stub (PCR9, vTPM only).
_LOAD_OPTIONS_TAG = struct.pack("<II", 0x8F3B22ED, 26) + b"LOADED_IMAGE::LoadOptions\0"
_INITRD_TAG = struct.pack("<II", 0x8F3B22EC, 13) + b"Linux initrd\0"
# GCE vTPM PCR0 (go-tpm-tools server/policy_constants.go).
GCE_PCR0_TECHNOLOGIES = {"sev": 1, "sev-es": 2, "tdx": 3, "sev-snp": 4}
# A kernel command-line token GRUB measures verbatim: no quoting, escaping or variable syntax.
_CMDLINE_TOKEN_RE = re.compile(r"[A-Za-z0-9._/=:@,+-]+")
_KERNEL_RELEASE_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[a-z0-9]+")
_UUID_TEXT_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# The ESP's GRUB stub (Ubuntu's grub-install): find /boot by filesystem UUID, read its grub.cfg.
_ESP_STUB_RE = re.compile(
    rb"search\.fs_uuid (" + _UUID_TEXT_RE.encode() + rb") root[ \t]*\n"
    rb"set prefix=\(\$root\)'/grub'[ \t]*\n"
    rb"configfile \$prefix/grub\.cfg[ \t]*\n?"
)


class PredictionError(ValueError):
    """An input outside the model (fail closed: the build stops, naming the input)."""


# --- events and replay ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelEvent:
    """One predicted event: its TCG PCR, type, the bytes it hashes (or precomputed digests) and a
    short description (the GRUB event text, the variable name, the action)."""

    pcr: int
    event_type: int
    what: str
    payload: Optional[bytes] = None
    digests: Optional[Mapping[str, str]] = None

    def digest(self, algorithm: str) -> bytes:
        if self.digests is not None:
            value = self.digests.get(algorithm)
            if not isinstance(value, str) or len(value) != 2 * ALGORITHMS[algorithm]:
                raise PredictionError(f"{self.what}: no {algorithm} digest")
            return bytes.fromhex(value)
        if self.payload is None:
            raise PredictionError(f"{self.what}: no payload")
        return hashlib.new(algorithm, self.payload).digest()

    def entry(self, algorithm: str) -> dict[str, Any]:
        """The prediction's per-event record ``{type, digest, what}`` (digest upper-case hex)."""
        return {
            "type": self.event_type,
            "digest": self.digest(algorithm).hex().upper(),
            "what": self.what,
        }


def replay(digests: Iterable[bytes], algorithm: str) -> str:
    """Extend a register from zero with ``digests`` (upper-case hex)."""
    register = bytes(ALGORITHMS[algorithm])
    for digest in digests:
        register = hashlib.new(algorithm, register + digest).digest()
    return register.hex().upper()


def replay_events(events: Sequence[ModelEvent], algorithm: str) -> str:
    return replay((event.digest(algorithm) for event in events), algorithm)


def digests_of(data: bytes) -> dict[str, str]:
    return {name: hashlib.new(name, data).hexdigest() for name in ALGORITHMS}


# --- UEFI variables, signature lists, dbx --------------------------------------------------------


def uefi_variable_data(guid: uuid.UUID, name: str, value: bytes) -> bytes:
    """The ``UEFI_VARIABLE_DATA`` a configuration variable or authority event hashes."""
    encoded = name.encode("utf-16-le")
    return guid.bytes_le + struct.pack("<QQ", len(name), len(value)) + encoded + value


def esl(
    signature_type: uuid.UUID, owner: uuid.UUID, payloads: Sequence[bytes]
) -> bytes:
    """One ``EFI_SIGNATURE_LIST`` of equal-size signatures, each owned by ``owner``."""
    size = 16 + len(payloads[0])
    if any(16 + len(payload) != size for payload in payloads):
        raise PredictionError("an EFI_SIGNATURE_LIST holds signatures of one size")
    body = b"".join(owner.bytes_le + payload for payload in payloads)
    return signature_type.bytes_le + struct.pack("<III", 28 + len(body), 0, size) + body


def signature_lists(
    data: bytes, *, where: str
) -> list[tuple[bytes, bytes, list[bytes]]]:
    """Parse an ``EFI_SIGNATURE_LIST`` sequence: [(type GUID bytes, header, [signature data])]."""
    lists = []
    offset = 0
    if not data:
        raise PredictionError(f"{where}: empty signature-list sequence")
    while offset < len(data):
        if offset + 28 > len(data):
            raise PredictionError(f"{where}: truncated EFI_SIGNATURE_LIST header")
        list_size, header_size, signature_size = struct.unpack_from(
            "<III", data, offset + 16
        )
        if (
            list_size < 28 + header_size
            or signature_size < 16
            or offset + list_size > len(data)
            or (list_size - 28 - header_size) % signature_size
        ):
            raise PredictionError(f"{where}: malformed EFI_SIGNATURE_LIST at {offset}")
        start = offset + 28 + header_size
        signatures = [
            data[cursor : cursor + signature_size]
            for cursor in range(start, offset + list_size, signature_size)
        ]
        lists.append(
            (
                data[offset : offset + 16],
                data[offset + 28 : offset + 28 + header_size],
                signatures,
            )
        )
        offset += list_size
    return lists


# --- the authenticated variable's CertData --------------------------------------------------------

_DER_MAX_DEPTH = 32
_PRINTABLE_STRING = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
)
_UTC_TIME_RE = re.compile(rb"[0-9]{12}Z")
_GENERALIZED_TIME_RE = re.compile(rb"[0-9]{14}Z")


class _Der(NamedTuple):
    """One DER element of a ``CertData``: its tag, where it starts (its tag octet), where its
    contents start and end, and the elements its contents hold (a constructed element only).
    """

    tag: int
    start: int
    content: int
    end: int
    children: tuple[_Der, ...]


def _der_integer_is_minimal(value: bytes) -> bool:
    return bool(value) and not (
        len(value) > 1
        and (
            (value[0] == 0x00 and value[1] < 0x80)
            or (value[0] == 0xFF and value[1] >= 0x80)
        )
    )


def _der_bit_string_is_valid(value: bytes) -> bool:
    """At least one octet; an unused-bits octet 0-7, 0 when it is the only octet; the unused
    bits zero."""
    if not value or value[0] > 7:
        return False
    if len(value) == 1:
        return value[0] == 0
    return value[-1] & ((1 << value[0]) - 1) == 0


def _der_object_identifier_is_valid(value: bytes) -> bool:
    """At least one octet; every sub-identifier minimal (never led by 0x80) and terminated (its
    last octet's bit 8 clear)."""
    return (
        bool(value)
        and value[-1] < 0x80
        and all(
            octet != 0x80 or (index and value[index - 1] & 0x80)
            for index, octet in enumerate(value)
        )
    )


def _der_time_is_valid(value: bytes, generalized: bool) -> bool:
    """UTCTime ``YYMMDDHHMMSSZ`` (its century RFC 5280's: 50-99 are 19xx, 00-49 20xx) or
    GeneralizedTime ``YYYYMMDDHHMMSSZ`` (no fraction), a real calendar instant. Form and
    calendar only: no time is compared with a clock."""
    if not (_GENERALIZED_TIME_RE if generalized else _UTC_TIME_RE).fullmatch(value):
        return False
    digits = value[:-1].decode("ascii")
    if generalized:
        year, rest = int(digits[:4]), digits[4:]
    else:
        year, rest = int(digits[:2]), digits[2:]
        year += 1900 if year >= 50 else 2000
    month, day, hour, minute, second = (int(rest[i : i + 2]) for i in range(0, 10, 2))
    try:
        datetime.datetime(year, month, day, hour, minute, second)
    except ValueError:
        return False
    return True


def _der_utf8_is_valid(value: bytes) -> bool:
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# X.690's content rules, by tag number, for the universal primitive types the strict DER check
# covers.
# Any other type's contents (OCTET STRING, T61String, UniversalString, ...) are not interpreted.
_DER_CONTENT_RULES: dict[int, tuple[str, Callable[[bytes], bool]]] = {
    0x01: ("BOOLEAN", lambda value: value in (b"\x00", b"\xff")),
    0x02: ("INTEGER", _der_integer_is_minimal),
    0x03: ("BIT STRING", _der_bit_string_is_valid),
    0x05: ("NULL", lambda value: not value),
    0x06: ("OBJECT IDENTIFIER", _der_object_identifier_is_valid),
    0x0C: ("UTF8String", _der_utf8_is_valid),
    0x12: (
        "NumericString",
        lambda value: all(octet in b"0123456789 " for octet in value),
    ),
    0x13: (
        "PrintableString",
        lambda value: all(octet in _PRINTABLE_STRING for octet in value),
    ),
    0x16: ("IA5String", lambda value: all(octet < 0x80 for octet in value)),
    0x17: ("UTCTime", lambda value: _der_time_is_valid(value, generalized=False)),
    0x18: (
        "GeneralizedTime",
        lambda value: _der_time_is_valid(value, generalized=True),
    ),
    0x1A: (
        "VisibleString",
        lambda value: all(0x20 <= octet <= 0x7E for octet in value),
    ),
    0x1E: ("BMPString", lambda value: len(value) % 2 == 0),
}


def _strict_der(data: bytes, start: int, end: int, depth: int = 0) -> tuple[_Der, ...]:
    """The DER (X.690) elements that fill ``data[start:end]`` exactly, each with the elements
    inside it, at every depth.

    Framing: a low tag number, never end-of-contents (tag ``00``); a definite length, minimally
    encoded in at most four octets, that stays inside its parent; nothing truncated, overrunning
    or trailing; nesting at most 32 deep. Form: of the universal types only SEQUENCE and SET are
    constructed, and they are never primitive. Contents of the universal primitives: BOOLEAN one
    octet, ``00`` or ``FF``; INTEGER at least one octet, minimal; BIT STRING at least one octet,
    an unused-bits octet 0-7 (0 when it is the only octet) and the unused bits zero; NULL empty;
    OBJECT IDENTIFIER at least one octet, every sub-identifier minimal and terminated; UTCTime
    ``YYMMDDHHMMSSZ`` and GeneralizedTime ``YYYYMMDDHHMMSSZ`` (no fraction), each a real calendar
    instant (form and calendar only); PrintableString, IA5String, NumericString and
    VisibleString in their character sets; UTF8String valid UTF-8; BMPString of even length.
    Not refusal reasons: SET OF order and an encoded DEFAULT value (X.690 11.5, 11.6); the
    contents of OCTET STRINGs, of other string types and of context-specific primitives (the
    schema, ``_pkcs7_signed_data``, reads the ones it names); and the values this bound neither
    checks nor names: the primitive encodings of EXTERNAL, EMBEDDED PDV and CHARACTER STRING (X.690
    encodes them constructed, the form refused above), the contents of REAL, ENUMERATED and
    RELATIVE-OID, and a context-specific element in an any-element slot (a certificate's
    AlgorithmIdentifier parameters, a Name attribute's value).
    """
    if depth > _DER_MAX_DEPTH:
        raise PredictionError("dbx update: its CertData nests DER too deeply")
    elements = []
    cursor = start
    while cursor < end:
        if cursor + 2 > end:
            raise PredictionError(
                "dbx update: its CertData has a truncated DER element"
            )
        tag, first = data[cursor], data[cursor + 1]
        if tag == 0x00:
            raise PredictionError(
                "dbx update: its CertData has a DER end-of-contents element (tag 00)"
            )
        if tag & 0x1F == 0x1F:
            raise PredictionError(
                "dbx update: its CertData has a high-tag-number DER element"
            )
        content = cursor + 2
        length = first
        if first & 0x80:
            count = first & 0x7F
            if not 1 <= count <= 4 or content + count > end:
                raise PredictionError(
                    "dbx update: its CertData has a DER element without a definite length"
                )
            length = int.from_bytes(data[content : content + count], "big")
            if data[content] == 0 or length < 0x80:
                raise PredictionError(
                    "dbx update: its CertData has a DER length that is not minimally encoded"
                )
            content += count
        if content + length > end:
            raise PredictionError(
                "dbx update: its CertData has a DER element that overruns it"
            )
        constructed = bool(tag & 0x20)
        if tag & 0xC0 == 0:
            number = tag & 0x1F
            if constructed != (number in (0x10, 0x11)):
                raise PredictionError(
                    f"dbx update: its CertData has a universal DER element (tag {tag:02x}) in "
                    "the wrong form (only SEQUENCE and SET are constructed, and always)"
                )
            rule = _DER_CONTENT_RULES.get(number)
            if rule is not None and not rule[1](data[content : content + length]):
                raise PredictionError(
                    f"dbx update: its CertData has a DER {rule[0]} whose contents are not "
                    "valid DER"
                )
        children = (
            _strict_der(data, content, content + length, depth + 1)
            if constructed
            else ()
        )
        elements.append(_Der(tag, cursor, content, content + length, children))
        cursor = content + length
    return tuple(elements)


def _pkcs7_signed_data(certificate: bytes) -> None:
    """Refuse a ``CertData`` outside this bound: strict DER at every depth (``_strict_der``),
    then an RFC 2315 ``SignedData`` under the UEFI profile (UEFI 2.10 8.2.2, "Using the
    EFI_VARIABLE_AUTHENTICATION_2 descriptor"), bare or in its
    ``ContentInfo`` (``id-signedData``, ``[0]`` EXPLICIT):

    * version 1; digestAlgorithms exactly one AlgorithmIdentifier, id-sha256 (parameters absent
      or NULL); contentInfo exactly ``SEQUENCE { id-data }`` (detached: the signed data is the
      variable's, never carried here);
    * certificates ``[0]`` present, every member an X.509 Certificate (``_x509``; an RFC
      2315 ExtendedCertificate ``[0]`` is refused); crls ``[1]`` refused (no dbx update carries
      them);
    * one or more SignerInfos, each: version 1; issuerAndSerialNumber byte-equal (issuer Name,
      serial INTEGER) to one carried certificate's issuer and serial (the profile's "the
      signer's certificate"); digestAlgorithm id-sha256 (parameters absent or NULL); no
      authenticatedAttributes; digestEncryptionAlgorithm rsaEncryption or
      sha256WithRSAEncryption (RSASSA-PKCS1-v1_5; parameters absent or NULL); encryptedDigest a
      non-empty OCTET STRING; no unauthenticatedAttributes.

    Canonical's ``dbxupdate_x64.bin`` carries the bare ``SignedData``: one SHA-256/RSA
    SignerInfo without attributes, its signer's certificate and that certificate's issuer, no
    CRLs. Not checked here: the signature, the chain, any certificate's validity against a clock
    (UEFI has no trusted time; both of Canonical's certificates have expired) and an extension's
    contents -- the firmware's when it applies the variable.
    """

    def refuse(what: str) -> NoReturn:
        raise PredictionError(
            "dbx update: its WIN_CERTIFICATE_UEFI_GUID CertData is not a PKCS#7 SignedData of "
            f"the UEFI profile ({what})"
        )

    def value(element: _Der) -> bytes:
        return certificate[element.content : element.end]

    def encoding(element: _Der) -> bytes:
        return certificate[element.start : element.end]

    def algorithm(
        element: _Der, what: str, allowed: Optional[frozenset[bytes]] = None
    ) -> None:
        """An AlgorithmIdentifier: ``SEQUENCE { OID, at most one element }``; with ``allowed``,
        one of those OIDs, its parameters absent or NULL."""
        fields = element.children if element.tag == 0x30 else ()
        if not 1 <= len(fields) <= 2 or fields[0].tag != 0x06:
            refuse(f"{what}: not an AlgorithmIdentifier")
        if allowed is not None and (
            value(fields[0]) not in allowed
            or (len(fields) == 2 and fields[1].tag != 0x05)
        ):
            refuse(f"{what}: an algorithm or parameters the profile does not admit")

    def name(element: _Der, what: str) -> None:
        """A Name: a SEQUENCE OF non-empty SETs of ``SEQUENCE { OID, one element }``."""
        if element.tag != 0x30 or not all(
            rdn.tag == 0x31
            and rdn.children
            and all(
                attribute.tag == 0x30
                and len(attribute.children) == 2
                and attribute.children[0].tag == 0x06
                for attribute in rdn.children
            )
            for rdn in element.children
        ):
            refuse(f"{what}: not a Name")

    def x509(element: _Der, what: str) -> tuple[bytes, bytes]:
        """RFC 5280 4.1's Certificate template; its issuer's and serial's encodings."""
        parts = element.children if element.tag == 0x30 else ()
        if len(parts) != 3 or parts[0].tag != 0x30 or parts[2].tag != 0x03:
            refuse(
                f"{what}: not SEQUENCE {{ TBSCertificate, AlgorithmIdentifier, BIT STRING }}"
            )
        algorithm(parts[1], f"{what}: signatureAlgorithm")
        fields = list(parts[0].children)
        if fields and fields[0].tag == 0xA0:
            version = fields.pop(0).children
            if (
                len(version) != 1
                or version[0].tag != 0x02
                or value(version[0]) not in (b"\x00", b"\x01", b"\x02")
            ):
                refuse(f"{what}: version")
        if len(fields) < 6 or fields[0].tag != 0x02:
            refuse(f"{what}: TBSCertificate fields")
        serial, signature, issuer, validity, subject, key = fields[:6]
        algorithm(signature, f"{what}: signature")
        name(issuer, f"{what}: issuer")
        if (
            validity.tag != 0x30
            or len(validity.children) != 2
            or any(time.tag not in (0x17, 0x18) for time in validity.children)
        ):
            refuse(f"{what}: validity")
        name(subject, f"{what}: subject")
        key_fields = key.children if key.tag == 0x30 else ()
        if len(key_fields) != 2 or key_fields[1].tag != 0x03:
            refuse(f"{what}: subjectPublicKeyInfo")
        algorithm(key_fields[0], f"{what}: subjectPublicKeyInfo algorithm")
        rest = fields[6:]
        # issuerUniqueID [1] and subjectUniqueID [2]: IMPLICIT BIT STRING, primitive.
        for tag in (0x81, 0x82):
            if rest and rest[0].tag == tag:
                if not _der_bit_string_is_valid(value(rest[0])):
                    refuse(f"{what}: a unique identifier that is not a DER BIT STRING")
                rest = rest[1:]
        if rest and rest[0].tag == 0xA3:
            extensions = rest[0].children
            if (
                len(extensions) != 1
                or extensions[0].tag != 0x30
                or not extensions[0].children
                or not all(
                    extension.tag == 0x30
                    and [field.tag for field in extension.children]
                    in ([0x06, 0x04], [0x06, 0x01, 0x04])
                    for extension in extensions[0].children
                )
            ):
                refuse(f"{what}: extensions")
            rest = rest[1:]
        if rest:
            refuse(f"{what}: a TBSCertificate field outside RFC 5280's template")
        return encoding(issuer), encoding(serial)

    top = _strict_der(certificate, 0, len(certificate))
    if len(top) != 1 or top[0].tag != 0x30:
        refuse("not exactly one DER SEQUENCE")
    fields = top[0].children
    if fields and fields[0].tag == 0x06:
        wrapped = (
            fields[1].children if len(fields) == 2 and fields[1].tag == 0xA0 else ()
        )
        if (
            value(fields[0]) != PKCS7_SIGNED_DATA_OID
            or len(wrapped) != 1
            or wrapped[0].tag != 0x30
        ):
            refuse("a ContentInfo that does not carry one SignedData")
        fields = wrapped[0].children
    if not fields or fields[0].tag != 0x02 or value(fields[0]) != b"\x01":
        refuse("version")
    if len(fields) < 2 or fields[1].tag != 0x31 or len(fields[1].children) != 1:
        refuse("digestAlgorithms: exactly one AlgorithmIdentifier")
    algorithm(fields[1].children[0], "digestAlgorithms", frozenset({ID_SHA256_OID}))
    if (
        len(fields) < 3
        or fields[2].tag != 0x30
        or [(item.tag, value(item)) for item in fields[2].children]
        != [(0x06, PKCS7_DATA_OID)]
    ):
        refuse("contentInfo: exactly SEQUENCE { id-data }")
    if len(fields) < 4 or fields[3].tag != 0xA0 or not fields[3].children:
        refuse("certificates [0]: absent")
    carried = []
    for index, member in enumerate(fields[3].children, 1):
        if member.tag == 0xA0:
            refuse(f"certificates [0]: member {index} is an ExtendedCertificate")
        carried.append(x509(member, f"certificate {index}"))
    rest = fields[4:]
    if rest and rest[0].tag == 0xA1:
        refuse("crls [1]: present")
    if len(rest) != 1 or rest[0].tag != 0x31 or not rest[0].children:
        refuse("signerInfos")
    for index, signer in enumerate(rest[0].children, 1):
        what = f"SignerInfo {index}"
        parts = signer.children if signer.tag == 0x30 else ()
        if len(parts) > 3 and parts[3].tag == 0xA0:
            refuse(f"{what}: authenticatedAttributes")
        if parts and parts[-1].tag == 0xA1:
            refuse(f"{what}: unauthenticatedAttributes")
        if len(parts) != 5:
            refuse(f"{what}: fields")
        version, issuer_serial, digest, signature_algorithm, signature = parts
        if version.tag != 0x02 or value(version) != b"\x01":
            refuse(f"{what}: version")
        pair = issuer_serial.children if issuer_serial.tag == 0x30 else ()
        if (
            len(pair) != 2
            or pair[1].tag != 0x02
            or (encoding(pair[0]), encoding(pair[1])) not in carried
        ):
            refuse(f"{what}: issuerAndSerialNumber names no carried certificate")
        algorithm(digest, f"{what}: digestAlgorithm", frozenset({ID_SHA256_OID}))
        algorithm(
            signature_algorithm,
            f"{what}: digestEncryptionAlgorithm",
            frozenset({RSA_ENCRYPTION_OID, SHA256_WITH_RSA_ENCRYPTION_OID}),
        )
        if signature.tag != 0x04 or signature.end == signature.content:
            refuse(f"{what}: encryptedDigest")


def _efi_time_is_valid(update: bytes) -> bool:
    """Whether the ``EFI_TIME``'s date and time are a real instant in its ranges (year
    1900-9999, a calendar day, hour 0-23, minute and second 0-59)."""
    year, month, day, hour, minute, second = struct.unpack_from("<HBBBBB", update, 0)
    if not 1900 <= year <= 9999 or hour > 23 or minute > 59 or second > 59:
        return False
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False
    return True


def authenticated_update_payload(update: bytes) -> bytes:
    """The signature lists of an ``EFI_VARIABLE_AUTHENTICATION_2`` dbx update (``dbxupdate_x64.bin``):
    what the firmware stores, and every boot then measures, when the update is an image's ``dbx``
    initial state (GCE replaces its default ``dbx`` with it).

    The update must be well formed: a 16-byte ``EFI_TIME`` -- a real date and time whose
    ``Pad1``, ``Nanosecond``, ``TimeZone``, ``Daylight`` and ``Pad2`` are zero (a time-based
    authenticated variable) --, then a ``WIN_CERTIFICATE_UEFI_GUID`` -- ``dwLength``, revision
    2.0, type ``WIN_CERT_TYPE_EFI_GUID``, ``CertType`` the PKCS#7 GUID and ``CertData`` within
    the ``CertData`` bound (strict DER at every depth, ``_strict_der``; one RFC 2315
    ``SignedData`` under the UEFI profile, its certificates in RFC 5280's template,
    ``_pkcs7_signed_data``) --, stripped by its ``dwLength``, then a non-empty
    ``EFI_SIGNATURE_LIST`` sequence. Refused: a bare signature list (the era's default ``dbx``),
    a header-less or truncated file, another certificate type, an
    ``EFI_TIME`` with an impossible date or time or a non-zero pad or zone, a certificate that
    does not fill its ``dwLength`` or is outside that bound, a payload that is not a
    signature-list sequence. Not checked here (the firmware's when it applies the variable): the
    signature, the chain, and what the bound states it does not interpret (SET OF order, an
    encoded DEFAULT value, other string types' and OCTET STRINGs' contents, a certificate's
    validity against any clock).
    """
    if len(update) < 16 + 24:
        raise PredictionError("dbx update: too short for EFI_VARIABLE_AUTHENTICATION_2")
    length, revision, certificate_type = struct.unpack_from("<IHH", update, 16)
    cert_type = uuid.UUID(bytes_le=update[24:40])
    if (
        revision != WIN_CERT_REVISION_2_0
        or certificate_type != WIN_CERT_TYPE_EFI_GUID
        or cert_type != EFI_CERT_TYPE_PKCS7
        or length <= 24
        or 16 + length >= len(update)
    ):
        raise PredictionError(
            "dbx update: not an authenticated EFI variable (EFI_VARIABLE_AUTHENTICATION_2 with "
            "a PKCS#7 WIN_CERTIFICATE_UEFI_GUID)"
        )
    # EFI_TIME: Year, Month, Day, Hour, Minute, Second, Pad1, Nanosecond, TimeZone, Daylight, Pad2.
    *_date, pad1, nanosecond, timezone, daylight, pad2 = struct.unpack_from(
        "<HBBBBBBIhBB", update, 0
    )
    if pad1 or nanosecond or timezone or daylight or pad2:
        raise PredictionError(
            "dbx update: its EFI_TIME carries a non-zero Pad1, Nanosecond, TimeZone, Daylight or "
            "Pad2 (not a time-based authenticated variable)"
        )
    if not _efi_time_is_valid(update):
        raise PredictionError(
            f"dbx update: its EFI_TIME is not a real date and time ({tuple(_date)!r})"
        )
    _pkcs7_signed_data(update[40 : 16 + length])
    payload = update[16 + length :]
    signature_lists(payload, where="dbx update payload")
    return payload


def dbx_after_update(default_dbx: bytes, update: bytes) -> bytes:
    """EDK2's append write of an authenticated dbx update onto ``default_dbx``: signatures already
    present are dropped, the rest is appended as one list per update list (idempotent). This is the
    ``dbx`` ``secureboot-db.service`` leaves after a boot of an image with no ``dbx`` initial state,
    which that image's later boots measure. Chutes' GCP image registers the update itself as its
    initial state and masks that writer, so no prediction uses it (on the update's own payload the
    append adds nothing)."""
    payload = authenticated_update_payload(update)
    existing = {
        (signature_type, signature[16:])
        for signature_type, _header, signatures in signature_lists(
            default_dbx, where="dbx"
        )
        for signature in signatures
    }
    appended = default_dbx
    for signature_type, header, signatures in signature_lists(
        payload, where="dbx update"
    ):
        keep = [
            signature
            for signature in signatures
            if (signature_type, signature[16:]) not in existing
        ]
        if not keep:
            continue
        body = b"".join(keep)
        size = len(signatures[0])
        appended += signature_type + struct.pack(
            "<III", 28 + len(header) + len(body), len(header), size
        )
        appended += header + body
    return appended


# --- PE images, Authenticode, shim ----------------------------------------------------------------


def _pe_offsets(data: bytes) -> tuple[int, int, int, int, int]:
    if data[:2] != b"MZ":
        raise PredictionError("not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise PredictionError("bad PE signature")
    coff = pe + 4
    sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    return (
        coff,
        sections,
        optional_size,
        optional,
        struct.unpack_from("<H", data, optional)[0],
    )


def authenticode_hash(data: bytes, algorithm: str) -> bytes:
    """The PE/COFF Authenticode digest EDK2 extends for ``EV_EFI_BOOT_SERVICES_APPLICATION``."""
    coff, sections, optional_size, optional, magic = _pe_offsets(data)
    if magic == 0x20B:
        directories, count_offset = optional + 112, optional + 108
    elif magic == 0x10B:
        directories, count_offset = optional + 96, optional + 92
    else:
        raise PredictionError("unknown PE optional header magic")
    checksum = optional + 64
    size_of_headers = struct.unpack_from("<I", data, optional + 60)[0]
    count = struct.unpack_from("<I", data, count_offset)[0]
    certificate_directory = directories + 8 * 4
    cert_offset, cert_size = (
        struct.unpack_from("<II", data, certificate_directory) if count > 4 else (0, 0)
    )
    digest = hashlib.new(algorithm)
    digest.update(data[:checksum])
    if count > 4:
        digest.update(data[checksum + 4 : certificate_directory])
        digest.update(data[certificate_directory + 8 : size_of_headers])
    else:
        digest.update(data[checksum + 4 : size_of_headers])
    table = optional + optional_size
    raw = []
    for index in range(sections):
        raw_size, raw_pointer = struct.unpack_from("<II", data, table + 40 * index + 16)
        if raw_size:
            raw.append((raw_pointer, raw_size))
    hashed = size_of_headers
    for pointer, size in sorted(raw):
        digest.update(data[pointer : pointer + size])
        hashed += size
    extra = len(data) - hashed - (cert_size if cert_offset else 0)
    if extra > 0:
        digest.update(data[hashed : hashed + extra])
    return digest.digest()


def pe_sections(data: bytes) -> dict[str, tuple[int, int, int, int]]:
    """Section name -> (virtual address, virtual size, raw pointer, raw size)."""
    coff, sections, optional_size, optional, _magic = _pe_offsets(data)
    symbols, symbol_count = struct.unpack_from("<II", data, coff + 8)
    strings = symbols + 18 * symbol_count
    table = optional + optional_size
    out = {}
    for index in range(sections):
        entry = table + 40 * index
        name = data[entry : entry + 8].rstrip(b"\0").decode("ascii", "replace")
        if name.startswith("/"):
            start = strings + int(name[1:])
            name = data[start : data.index(b"\0", start)].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, entry + 8
        )
        out[name] = (virtual_address, virtual_size, raw_pointer, raw_size)
    return out


def shim_vendor_cert(shim: bytes) -> bytes:
    """The vendor certificate shim trusts (``.vendor_cert``): the ``MokList``/``MokListRT`` cert."""
    sections = pe_sections(shim)
    if ".vendor_cert" not in sections:
        raise PredictionError("shim carries no .vendor_cert section")
    _va, size, pointer, _raw = sections[".vendor_cert"]
    table = shim[pointer : pointer + size]
    authorized_size, _deauthorized_size, authorized_offset, _ = struct.unpack_from(
        "<IIII", table, 0
    )
    cert = table[authorized_offset : authorized_offset + authorized_size]
    if not cert or cert[0] != 0x30:
        raise PredictionError("shim's vendor certificate is not DER")
    return cert


def shim_sbat_levels(shim: bytes) -> dict[str, bytes]:
    """shim's ``SbatLevel`` payloads: ``original`` (Secure Boot off), ``previous`` and ``latest``."""
    sections = pe_sections(shim)
    if ".sbatlevel" not in sections:
        raise PredictionError("shim carries no .sbatlevel section")
    _va, size, pointer, _raw = sections[".sbatlevel"]
    blob = shim[pointer : pointer + size]
    _version, previous, latest = struct.unpack_from("<III", blob, 0)
    return {
        "original": b"sbat,1,2021030218\n",
        "previous": blob[4 + previous :].split(b"\0")[0],
        "latest": blob[4 + latest :].split(b"\0")[0],
    }


# --- a minimal DER walk (the Authenticode signer's issuer, a db certificate's subject) -----------


def _der_element(data: bytes, offset: int) -> tuple[int, int, int]:
    """(tag, content start, end) of the DER element at ``offset``."""
    if offset + 2 > len(data):
        raise PredictionError("truncated DER")
    tag = data[offset]
    length = data[offset + 1]
    cursor = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 4 or cursor + count > len(data):
            raise PredictionError("unsupported DER length")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    if cursor + length > len(data):
        raise PredictionError("DER element overruns its buffer")
    return tag, cursor, cursor + length


def _der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    children = []
    cursor = start
    while cursor < end:
        tag, content, element_end = _der_element(data, cursor)
        children.append((tag, cursor, element_end))
        cursor = element_end
    return children


def certificate_names(der: bytes) -> tuple[bytes, bytes]:
    """The raw DER of a certificate's issuer and subject ``Name`` (TBSCertificate fields)."""
    tag, content, end = _der_element(der, 0)
    if tag != 0x30:
        raise PredictionError("certificate is not a DER SEQUENCE")
    tbs_tag, tbs_content, tbs_end = _der_element(der, content)
    fields = _der_children(der, tbs_content, tbs_end)
    if fields and fields[0][0] == 0xA0:
        fields = fields[1:]
    if len(fields) < 5:
        raise PredictionError("TBSCertificate is truncated")
    issuer, subject = fields[2], fields[4]
    return der[issuer[1] : issuer[2]], der[subject[1] : subject[2]]


def db_authority_entry(db: bytes, issuer_name: bytes) -> bytes:
    """The ``EFI_SIGNATURE_DATA`` (owner + certificate) of the db X.509 entry whose subject issued
    the boot application's signer -- the authority the firmware logs under Secure Boot.
    """
    for signature_type, _header, signatures in signature_lists(db, where="db"):
        if signature_type != EFI_CERT_X509.bytes_le:
            continue
        for signature in signatures:
            if certificate_names(signature[16:])[1] == issuer_name:
                return signature
    raise PredictionError("the era's db holds no certificate that issued shim's signer")


# --- GPT, boot options ---------------------------------------------------------------------------


def gpt_event_data(sectors: bytes) -> bytes:
    """The ``EV_EFI_GPT_EVENT`` data: the primary GPT header and its used entries."""
    if len(sectors) < 34 * 512:
        raise PredictionError("the GPT needs LBA 0-33")
    header = sectors[512 : 512 + 92]
    if header[:8] != b"EFI PART":
        raise PredictionError("no primary GPT header at LBA 1")
    entries_lba, count, size = struct.unpack_from("<QII", header, 72)
    table = sectors[entries_lba * 512 : entries_lba * 512 + count * size]
    if len(table) != count * size:
        raise PredictionError("the GPT entry array lies outside LBA 0-33")
    used = [table[index * size : (index + 1) * size] for index in range(count)]
    used = [entry for entry in used if entry[:16] != bytes(16)]
    return header + struct.pack("<Q", len(used)) + b"".join(used)


def gpt_partitions(sectors: bytes) -> list[dict[str, Any]]:
    header = sectors[512 : 512 + 92]
    if header[:8] != b"EFI PART":
        raise PredictionError("no primary GPT header at LBA 1")
    entries_lba, count, size = struct.unpack_from("<QII", header, 72)
    partitions = []
    for index in range(count):
        entry = sectors[
            entries_lba * 512 + index * size : entries_lba * 512 + (index + 1) * size
        ]
        if entry[:16] == bytes(16):
            continue
        first, last = struct.unpack_from("<QQ", entry, 32)
        partitions.append(
            {
                "number": index + 1,
                "type": str(uuid.UUID(bytes_le=entry[:16])),
                "guid": str(uuid.UUID(bytes_le=entry[16:32])),
                "first_lba": first,
                "size_lba": last - first + 1,
            }
        )
    return partitions


def boot0002_option(
    bootx64_csv: bytes, esp: Mapping[str, Any], device_path_prefix: bytes
) -> bytes:
    """The load option shim's fallback creates from ``EFI/ubuntu/BOOTX64.CSV``: the shape's disk
    device path, the ESP's hard-drive node, the loader's file path."""
    try:
        text = bootx64_csv.decode("utf-16")
    except UnicodeDecodeError as exc:
        raise PredictionError("BOOTX64.CSV is not UTF-16") from exc
    fields = text.strip().split(",", 3)
    if len(fields) != 4:
        raise PredictionError("BOOTX64.CSV is not loader,label,arguments,comment")
    loader, label, arguments, _comment = fields
    hard_drive = (
        struct.pack("<BBH", 4, 1, 42)
        + struct.pack("<IQQ", esp["number"], esp["first_lba"], esp["size_lba"])
        + uuid.UUID(esp["guid"]).bytes_le
        + bytes([2, 2])
    )
    path = ("\\EFI\\ubuntu\\" + loader + "\0").encode("utf-16-le")
    file_node = struct.pack("<BBH", 4, 4, 4 + len(path)) + path
    device_path = (
        device_path_prefix + hard_drive + file_node + bytes([0x7F, 0xFF, 4, 0])
    )
    description = (label + "\0").encode("utf-16-le")
    return (
        struct.pack("<IH", 1, len(device_path))
        + description
        + device_path
        + (arguments.encode("utf-16-le"))
    )


# The boot options a disk topology adds. pd1 (one blank data disk attached at create): the
# firmware enumerates the data disk as Boot0002, the image's fallback option is Boot0003, and
# BootOrder is 0003,0001,0002,0000 (GCE captures of stock images). The rule holds per data disk:
# pd2 (an OS disk plus one data volume) measured BootOrder 0004,0001,0002,0003,0000
# on c3-standard-4 and -8. GCE's firmware keeps a VM's boot options across boots, so a layout is
# also the order the data disks first appeared in: a data disk keeps its first number, a new one
# takes the lowest free number before Boot0000. Two boot-order variants follow with one data volume:
# pd2-attached (created pd1, the volume attached later: BootOrder 0003,0001,0002,0004,0000) and
# pd1-detached (created pd2, the volume detached: BootOrder 0004,0001,0002,0000). Every load option's
# bytes are the create-time layout's; only BootOrder differs. A layout is its image option number and
# its data disks' option numbers (namespaces 2.. in order); BootOrder lists image, 0001, data, 0000.
LAYOUTS = {
    "pd1": {"image": 3, "data": (2,)},
    "pd2": {"image": 4, "data": (2, 3)},
    "pd2-attached": {"image": 3, "data": (2, 4)},
    "pd1-detached": {"image": 4, "data": (2,)},
}
# The topologies a prediction row names (the create-time layouts), and each one's boot-order variants,
# predicted only as that row's RTMR0 alternatives.
TOPOLOGIES = ("pd1", "pd2")
BOOT_ORDER_VARIANTS = {"pd1": ("pd1-detached",), "pd2": ("pd2-attached",)}


def _layout(topology: Optional[str]) -> dict:
    if topology is None:
        return {"image": 2, "data": ()}
    if topology not in LAYOUTS:
        raise PredictionError(f"unknown disk topology {topology!r}")
    return LAYOUTS[topology]


def data_disks(topology: Optional[str]) -> int:
    """The number of data disks a topology (or layout) names (0 for the boot disk alone)."""
    return len(_layout(topology)["data"])


def data_options(topology: Optional[str]) -> list[str]:
    """The firmware's data-disk boot options of a layout, in BootOrder's (and namespace) order."""
    return [f"Boot{number:04X}" for number in _layout(topology)["data"]]


def image_option(topology: Optional[str]) -> str:
    """The image's own boot option of a layout."""
    return f"Boot{_layout(topology)['image']:04X}"


def boot_order(topology: Optional[str] = None) -> bytes:
    """``BootOrder``: the image's option first, then Boot0001, the data disks', Boot0000 (the boot
    disk alone 0002,0001,0000; pd1 0003,0001,0002,0000; pd2 0004,0001,0002,0003,0000; pd2-attached
    0003,0001,0002,0004,0000; pd1-detached 0004,0001,0002,0000)."""
    layout = _layout(topology)
    order = (layout["image"], 1, *layout["data"], 0)
    return struct.pack(f"<{len(order)}H", *order)


# --- GCE PCR0 and the RTMR0 template ---------------------------------------------------------------


def gce_pcr0_events(svn: int, technology: str) -> list[ModelEvent]:
    """The three events the GCE firmware extends into vTPM PCR0."""
    if type(svn) is not int or not 0 <= svn <= 0xFFFFFFFF:
        raise PredictionError(f"gce_pcr0: svn must be a uint32, got {svn!r}")
    if technology not in GCE_PCR0_TECHNOLOGIES:
        raise PredictionError(f"gce_pcr0: unknown technology {technology!r}")
    version = f"GCE Virtual Firmware v{svn}\0".encode("utf-16-le")
    nonhost = (
        b"GCE NonHostInfo\0" + bytes([GCE_PCR0_TECHNOLOGIES[technology]]) + bytes(15)
    )
    return [
        ModelEvent(
            0,
            EV_S_CRTM_VERSION,
            f"S-CRTM version: GCE Virtual Firmware v{svn}",
            version,
        ),
        ModelEvent(0, EV_NONHOST_INFO, f"GCE NonHostInfo: {technology}", nonhost),
        ModelEvent(0, EV_SEPARATOR, "separator", SEPARATOR),
    ]


def gce_pcr0(svn: int, technology: str) -> str:
    """GCE vTPM PCR0 for ``svn`` and ``technology`` (upper-case hex): the same function as Chutes'
    validator computes, equal on every shared vector."""
    return replay_events(gce_pcr0_events(svn, technology), "sha256")


def rtmr0_before_cfv(td_hob_digest: bytes) -> bytes:
    """RTMR0 after the TD HOB event, the template's ``before_cfv``."""
    return hashlib.sha384(bytes(48) + td_hob_digest).digest()


def evaluate_rtmr0_template(template: Mapping[str, Any], cfv_sha384: str) -> str:
    """``RTMR0 = fold(sha384(before_cfv || cfv), after_cfv)`` (upper-case hex); the same fold as
    Chutes' validator computes."""
    register = hashlib.sha384(
        bytes.fromhex(template["before_cfv"]) + bytes.fromhex(cfv_sha384)
    ).digest()
    for digest in template["after_cfv"]:
        register = hashlib.sha384(register + bytes.fromhex(digest)).digest()
    return register.hex().upper()


# --- the static grub.cfg --------------------------------------------------------------------------


def _check_release(kernel_release: str) -> str:
    if not isinstance(kernel_release, str) or not _KERNEL_RELEASE_RE.fullmatch(
        kernel_release
    ):
        raise PredictionError(f"invalid kernel release {kernel_release!r}")
    return kernel_release


def check_cmdline(cmdline: str) -> str:
    tokens = cmdline.split(" ")
    if not tokens or any(not _CMDLINE_TOKEN_RE.fullmatch(token) for token in tokens):
        raise PredictionError(
            "the kernel command line holds a token GRUB would not measure verbatim"
        )
    return cmdline


# The static GCP kernel line: the dm-verity kernel line (with the debug-build console suffix),
# followed by the masks that disable the console (no ``console=ttyS0`` on a non-debug image).
_STATIC_CMDLINE_HEAD = (
    "root=/dev/mapper/verity-root verity.roothash={roothash} fastboot panic=1 "
    "systemd.import_credentials=no systemd.ssh_auto=no ro lockdown=integrity module.sig_enforce=1"
)
DEBUG_CONSOLE_TOKEN = "console=ttyS0,115200n8"
CONSOLE_MASKS = (
    "systemd.mask=getty@tty1.service",
    "systemd.mask=serial-getty@ttyS0.service",
    "systemd.mask=serial-getty@hvc0.service",
    "systemd.mask=emergency.service",
    "systemd.mask=rescue.service",
)


def gcp_static_cmdline(roothash: str, *, debug_build: bool) -> str:
    """The kernel command line of a GCP image's static ``grub.cfg``."""
    if not re.fullmatch(r"[0-9a-f]{64}", roothash or ""):
        raise PredictionError("verity.roothash must be 64 lower-case hex")
    tokens = [_STATIC_CMDLINE_HEAD.format(roothash=roothash)]
    if debug_build:
        tokens.append(DEBUG_CONSOLE_TOKEN)
    return " ".join(tokens + list(CONSOLE_MASKS))


def render_static_grub_cfg(kernel_release: str, cmdline: str) -> bytes:
    """The GCP image's static ``/boot/grub/grub.cfg``: one entry, no environment."""
    release = _check_release(kernel_release)
    check_cmdline(cmdline)
    return (
        "set timeout=0\n"
        "set default=0\n"
        f"menuentry '{STATIC_MENU_TITLE}' {{\n"
        f"\tlinux /vmlinuz-{release} {cmdline}\n"
        f"\tinitrd /initrd.img-{release}\n"
        "}\n"
    ).encode("ascii")


def static_grub_cmdline(grub_cfg: bytes, kernel_release: str) -> str:
    """The command line of a static ``grub.cfg``; refuses any file that is not exactly the
    template's rendering for ``kernel_release`` (fail closed: no GRUB interpreter is modelled).
    """
    _check_release(kernel_release)
    prefix = f"\tlinux /vmlinuz-{kernel_release} ".encode()
    lines = grub_cfg.split(b"\n")
    candidates = [line for line in lines if line.startswith(prefix)]
    if len(candidates) != 1:
        raise PredictionError("grub.cfg is not the static template's rendering")
    try:
        cmdline = candidates[0][len(prefix) :].decode("ascii")
        rendered = render_static_grub_cfg(kernel_release, cmdline)
    except (UnicodeDecodeError, PredictionError) as exc:
        raise PredictionError(
            "grub.cfg is not the static template's rendering"
        ) from exc
    if rendered != grub_cfg:
        raise PredictionError("grub.cfg is not the static template's rendering")
    return cmdline


def esp_stub_boot_uuid(stub: bytes) -> str:
    """The /boot filesystem UUID the ESP's GRUB stub searches for (its exact three-line form)."""
    match = _ESP_STUB_RE.fullmatch(stub)
    if match is None:
        raise PredictionError(
            "the ESP grub.cfg is not Ubuntu's three-line search/configfile stub"
        )
    return match.group(1).decode()


# --- GRUB and Linux EFI stub events (the literal list) ------------------------------------------


def grub_command(text: str) -> ModelEvent:
    """``grub_cmd: <argv joined>`` into PCR8; the digest covers the joined argv only."""
    return ModelEvent(8, EV_IPL, f"grub_cmd: {text}", text.encode())


def grub_file(path: str, digests: Mapping[str, str]) -> ModelEvent:
    """A file GRUB read through its verifier into PCR9: the event names the path, the digest is
    the file's."""
    return ModelEvent(9, EV_IPL, path, digests=dict(digests))


def kernel_cmdline(text: str) -> ModelEvent:
    """``kernel_cmdline: <kernel path and arguments>`` into PCR8."""
    return ModelEvent(8, EV_IPL, f"kernel_cmdline: {text}", text.encode())


def stub_load_options(cmdline_text: str) -> ModelEvent:
    """The Linux EFI stub's ``LoadOptions`` (vTPM PCR9): UTF-16LE ``BOOT_IMAGE=<kernel> <args>``
    **with one terminating UTF-16 NUL** (two zero bytes).

    The stub measures the ``LoadOptions`` buffer over the ``LoadOptionsSize`` GRUB passes, and
    Ubuntu 26.04's GRUB 2.14 (grub-efi-amd64-signed 1.215+2.14-2ubuntu1, Authenticode SHA-256
    ``137a664e...``) counts the terminator: a SEV-SNP capture measured ``CD0075F1...`` for a
    415-character kernel line, this form. Stock 24.04 images boot an earlier GRUB (``4caffb53...``)
    whose ``LoadOptionsSize`` omits it; the model predicts only the newer GRUB.
    """
    return ModelEvent(
        9,
        EV_EVENT_TAG,
        "Linux EFI stub: LoadOptions",
        ("BOOT_IMAGE=" + cmdline_text + "\0").encode("utf-16-le"),
    )


def stub_initrd(digests: Mapping[str, str]) -> ModelEvent:
    return ModelEvent(
        9, EV_EVENT_TAG, "Linux EFI stub: Linux initrd", digests=dict(digests)
    )


def static_grub_events(inputs: Mapping[str, Any], *, vtpm: bool) -> list[ModelEvent]:
    """GRUB's events on Chutes' GCP image, in measurement order: the ESP stub, the four ``*.lst``
    reads, the static ``grub.cfg`` and its one entry; with ``vtpm`` the Linux EFI stub's two events.
    """
    esp, boot = inputs["esp"], inputs["boot"]
    esp_number = inputs["gpt"]["esp_partition"]["number"]
    boot_number = inputs["gpt"]["boot_partition"]
    release = boot["kernel_release"]
    stub = bytes.fromhex(esp["grub_cfg"]["bytes"])
    boot_uuid = esp_stub_boot_uuid(stub)
    cmdline = static_grub_cmdline(bytes.fromhex(boot["grub_cfg"]["bytes"]), release)
    esp_cfg = f"(hd0,gpt{esp_number})/EFI/ubuntu/grub.cfg"
    boot_root = f"(hd0,gpt{boot_number})"
    linux_args = f"/vmlinuz-{release} {cmdline}"
    block = f"{{\n\tlinux {linux_args}\n\tinitrd /initrd.img-{release}\n}}"
    events = [
        # Ubuntu's GRUB opens the ESP stub twice at normal-mode start (every observed log).
        grub_file(esp_cfg, esp["grub_cfg"]["digests"]),
        grub_file(esp_cfg, esp["grub_cfg"]["digests"]),
        grub_command(f"search.fs_uuid {boot_uuid} root"),
        grub_command(f"set prefix={boot_root}/grub"),
        *(
            grub_file(f"{boot_root}/grub/x86_64-efi/{name}.lst", boot["lst"][name])
            for name in LST_FILES
        ),
        grub_command(f"configfile {boot_root}/grub/grub.cfg"),
        grub_file(f"{boot_root}/grub/grub.cfg", boot["grub_cfg"]["digests"]),
        grub_command("set timeout=0"),
        grub_command("set default=0"),
        grub_command(f"menuentry {STATIC_MENU_TITLE} {block}"),
        grub_command(f"setparams {STATIC_MENU_TITLE}"),
        grub_command(f"linux {linux_args}"),
        grub_file(f"/vmlinuz-{release}", boot["kernel"]["file"]),
        kernel_cmdline(linux_args),
        grub_command(f"initrd /initrd.img-{release}"),
        grub_file(f"/initrd.img-{release}", boot["initrd"]["file"]),
    ]
    if vtpm:
        events += [stub_load_options(linux_args), stub_initrd(boot["initrd"]["file"])]
    return events


# --- the boot chain --------------------------------------------------------------------------------


def shim_mok_events(vendor_cert: bytes) -> list[ModelEvent]:
    """shim 15.8's MOK mirror on a VM with no MOK variables (vTPM PCR14; folded into TDX RTMR2)."""
    return [
        ModelEvent(14, EV_IPL, "MokList", esl(EFI_CERT_X509, SHIM_LOCK, [vendor_cert])),
        # Ubuntu's shim mirrors no vendor dbx: its placeholder holds one all-zero SHA-256.
        ModelEvent(
            14, EV_IPL, "MokListX", esl(EFI_CERT_SHA256, SHIM_LOCK, [bytes(32)])
        ),
        ModelEvent(14, EV_IPL, "MokListTrusted", b"\x01"),
    ]


def boot_application(what: str, digests: Mapping[str, str]) -> ModelEvent:
    return ModelEvent(4, EV_EFI_BOOT_SERVICES_APPLICATION, what, digests=dict(digests))


def tdx_rtmr1_events(
    inputs: Mapping[str, Any], *, secure_boot: bool
) -> list[ModelEvent]:
    """TDX RTMR1 (PCR2-6 folded into one CCEL register): seven events, eight with Secure Boot on."""
    events = [
        ModelEvent(
            4, EV_EFI_ACTION, CALLING_EFI_APPLICATION.decode(), CALLING_EFI_APPLICATION
        ),
        ModelEvent(4, EV_SEPARATOR, "separator", SEPARATOR),
        ModelEvent(
            5, EV_EFI_GPT_EVENT, "GPT", bytes.fromhex(inputs["gpt"]["event_data"])
        ),
        boot_application("shimx64.efi", inputs["esp"]["shim"]["authenticode"]),
        boot_application("grubx64.efi", inputs["esp"]["grub"]["authenticode"]),
    ]
    if secure_boot:
        events.append(
            boot_application("kernel", inputs["boot"]["kernel"]["authenticode"])
        )
    events += [
        ModelEvent(
            5,
            EV_EFI_ACTION,
            EXIT_BOOT_SERVICES_INVOCATION.decode(),
            EXIT_BOOT_SERVICES_INVOCATION,
        ),
        ModelEvent(
            5,
            EV_EFI_ACTION,
            EXIT_BOOT_SERVICES_SUCCESS.decode(),
            EXIT_BOOT_SERVICES_SUCCESS,
        ),
    ]
    return events


def vtpm_pcr4_events(
    inputs: Mapping[str, Any], *, secure_boot: bool
) -> list[ModelEvent]:
    """vTPM PCR4: the calling action, its separator, shim, GRUB (+ the kernel with Secure Boot on);
    the GPT and the exit-boot-services actions extend PCR5 (unpinned)."""
    events = [
        ModelEvent(
            4, EV_EFI_ACTION, CALLING_EFI_APPLICATION.decode(), CALLING_EFI_APPLICATION
        ),
        ModelEvent(4, EV_SEPARATOR, "separator", SEPARATOR),
        boot_application("shimx64.efi", inputs["esp"]["shim"]["authenticode"]),
        boot_application("grubx64.efi", inputs["esp"]["grub"]["authenticode"]),
    ]
    if secure_boot:
        events.append(
            boot_application("kernel", inputs["boot"]["kernel"]["authenticode"])
        )
    return events


def secure_boot_events(
    inputs: Mapping[str, Any],
    era: Mapping[str, bytes],
    dbx: bytes,
    *,
    secure_boot: bool,
    pcr: int = 7,
) -> tuple[list[ModelEvent], list[ModelEvent]]:
    """(before the boot options, after them): SecureBoot, PK, KEK, db, ``dbx``, the separator; then
    the db authority (Secure Boot on), shim's ``SbatLevel`` and the ``MokListRT`` authority (Secure
    Boot on).  The ``SbatLevel`` payload is shim's ``original`` with Secure Boot off and its
    ``previous`` level with Secure Boot on (observed)."""
    shim = inputs["esp"]["shim"]
    variables = [
        ("SecureBoot", EFI_GLOBAL_VARIABLE, b"\x01" if secure_boot else b"\x00"),
        ("PK", EFI_GLOBAL_VARIABLE, era["pk"]),
        ("KEK", EFI_GLOBAL_VARIABLE, era["kek"]),
        ("db", EFI_IMAGE_SECURITY_DATABASE, era["db"]),
        ("dbx", EFI_IMAGE_SECURITY_DATABASE, dbx),
    ]
    before = [
        ModelEvent(
            pcr,
            EV_EFI_VARIABLE_DRIVER_CONFIG,
            name,
            uefi_variable_data(guid, name, value),
        )
        for name, guid, value in variables
    ]
    before.append(ModelEvent(pcr, EV_SEPARATOR, "separator", SEPARATOR))
    after = []
    levels = shim["sbat_levels"]
    if secure_boot:
        entry = db_authority_entry(era["db"], bytes.fromhex(shim["signer_issuer"]))
        after.append(
            ModelEvent(
                pcr,
                EV_EFI_VARIABLE_AUTHORITY,
                "db authority (verified shim)",
                uefi_variable_data(EFI_IMAGE_SECURITY_DATABASE, "db", entry),
            )
        )
    sbat = bytes.fromhex(levels["previous" if secure_boot else "original"])
    after.append(
        ModelEvent(
            pcr,
            EV_EFI_VARIABLE_AUTHORITY,
            "SbatLevel",
            uefi_variable_data(SHIM_LOCK, "SbatLevel", sbat),
        )
    )
    if secure_boot:
        vendor = SHIM_LOCK.bytes_le + bytes.fromhex(shim["vendor_cert"])
        after.append(
            ModelEvent(
                pcr,
                EV_EFI_VARIABLE_AUTHORITY,
                "MokListRT authority (verified GRUB)",
                uefi_variable_data(SHIM_LOCK, "MokListRT", vendor),
            )
        )
    return before, after


def vtpm_pcr7_events(
    inputs: Mapping[str, Any],
    era: Mapping[str, bytes],
    dbx: bytes,
    *,
    secure_boot: bool,
) -> list[ModelEvent]:
    before, after = secure_boot_events(inputs, era, dbx, secure_boot=secure_boot)
    return before + after


def rtmr0_template(
    inputs: Mapping[str, Any],
    profile: Mapping[str, Any],
    era: Mapping[str, bytes],
    dbx: bytes,
    *,
    profile_sha256: str,
    secure_boot: bool,
) -> tuple[dict[str, Any], list[ModelEvent]]:
    """The signed RTMR0 template of one machine type: ``before_cfv`` (the profile's TD HOB) and the
    ordered ``after_cfv`` digests -- the Secure Boot variables and separator, the profile's three
    ACPI tables, ``BootOrder``, the image's ``Boot0002`` on the shape's device path, the profile's
    ``Boot0001``/``Boot0000``, then the authorities and ``SbatLevel``. A ``pd1`` profile (one data
    disk attached at create) measures ``BootOrder`` 0003,0001,0002,0000, the image's option as
    ``Boot0003``, ``Boot0001``, the profile's data-disk ``Boot0002``, then ``Boot0000``; a ``pdN``
    profile the image's option as ``Boot(N+2)``, ``Boot0001``, its data-disk options
    ``Boot0002``..``Boot(N+1)`` in that order, then ``Boot0000``.
    """
    before, after = secure_boot_events(inputs, era, dbx, secure_boot=secure_boot, pcr=1)
    acpi = [
        ModelEvent(1, EV_PLATFORM_CONFIG_FLAGS, "ACPI DATA", digests={"sha384": digest})
        for digest in profile["acpi_digests"]
    ]
    option = boot0002_option(
        bytes.fromhex(inputs["esp"]["bootx64_csv"]),
        inputs["gpt"]["esp_partition"],
        bytes.fromhex(profile["boot_device_path_prefix"]),
    )
    topology = profile.get("topology")
    boot_options = [
        ModelEvent(1, EV_EFI_VARIABLE_BOOT, "BootOrder", boot_order(topology)),
        ModelEvent(1, EV_EFI_VARIABLE_BOOT, image_option(topology), option),
        ModelEvent(
            1, EV_EFI_VARIABLE_BOOT, "Boot0001", bytes.fromhex(profile["boot0001"])
        ),
    ]
    for name in data_options(topology):
        boot_options.append(
            ModelEvent(
                1, EV_EFI_VARIABLE_BOOT, name, bytes.fromhex(profile[name.lower()])
            )
        )
    boot_options.append(
        ModelEvent(
            1, EV_EFI_VARIABLE_BOOT, "Boot0000", bytes.fromhex(profile["boot0000"])
        )
    )
    events = before + acpi + boot_options + after
    template = {
        "profile_id": profile["profile_id"],
        "profile_sha256": profile_sha256,
        "before_cfv": rtmr0_before_cfv(bytes.fromhex(profile["td_hob_digest"]))
        .hex()
        .upper(),
        "after_cfv": [event.digest("sha384").hex().upper() for event in events],
    }
    if not 1 <= len(template["after_cfv"]) <= 32:
        raise PredictionError("an RTMR0 template carries 1-32 events after the CFV")
    return template, events


def tdx_rtmr2_events(inputs: Mapping[str, Any]) -> list[ModelEvent]:
    """TDX RTMR2 (PCR8-15 folded): shim's MOK mirror, then GRUB's literal list (no stub events:
    the Linux EFI stub measures through TCG2 only, which on GCE TDX is the vTPM)."""
    return shim_mok_events(
        bytes.fromhex(inputs["esp"]["shim"]["vendor_cert"])
    ) + static_grub_events(inputs, vtpm=False)


def vtpm_grub_events(
    inputs: Mapping[str, Any],
) -> tuple[list[ModelEvent], list[ModelEvent]]:
    """(PCR8, PCR9) of the vTPM: GRUB's commands and kernel line, its file reads and the stub's."""
    events = static_grub_events(inputs, vtpm=True)
    return [event for event in events if event.pcr == 8], [
        event for event in events if event.pcr == 9
    ]
