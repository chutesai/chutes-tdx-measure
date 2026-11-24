from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOCUMENT_TYPE = "chutes.tdx-measurements.v1"
MAX_DOCUMENT_BYTES = 65536
MAX_ENTRIES = 32
PROOF_PREFIX = b"chutes-tdx-measurement-key-proof-v1\x00"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX96 = re.compile(r"[0-9a-f]{96}")
_MACHINE_TYPE = re.compile(r"[a-z][a-z0-9-]{0,62}")
EXACT_KEYS = frozenset({"machine_type", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"})
FOLLOW_KEYS = frozenset({"machine_type", "mrtd", "rtmr0_template", "rtmr1", "rtmr2", "rtmr3"})


class DocumentRefused(ValueError):
    """A refused document with its code: document_too_large, document_signature_invalid,
    document_invalid or document_image_mismatch."""

    def __init__(self, code: str, text: str = ""):
        super().__init__(f"{code}: {text}" if text else code)
        self.code = code


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def strict_b64(text, size: int) -> bytes:
    """``B64``: standard alphabet with padding, no whitespace, canonical, exactly ``size`` bytes."""
    if not isinstance(text, str) or any(c in text for c in " \t\r\n"):
        raise ValueError("not B64")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("not B64") from None
    if len(raw) != size or b64(raw) != text:
        raise ValueError("not B64 of the right size")
    return raw


# --- the measurement key -----------------------------------------------------------------------

def create_key(path: str) -> Ed25519PrivateKey:
    """A new Ed25519 key, written as PKCS#8 PEM with mode 0600 (refused if ``path`` exists)."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(pem)
    return key


def load_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as stream:
        key = serialization.load_pem_private_key(stream.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("the measurement key must be Ed25519")
    return key


def public_raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_b64(key: Ed25519PrivateKey) -> str:
    """The key as registered: ``B64`` of its 32 raw bytes."""
    return b64(public_raw(key))


def fingerprint(public: bytes) -> str:
    """SHA-256 of the 32 raw bytes, lower hex: what the owner confirms out of band."""
    return hashlib.sha256(public).hexdigest()


def load_public(text: str) -> bytes:
    """A registered key (``B64`` of 32 bytes) that loads as an Ed25519 point."""
    raw = strict_b64(text, 32)
    Ed25519PublicKey.from_public_bytes(raw)
    return raw


# --- the registration's proof of possession ------------------------------------------------------

def proof_message(user_id: str, archive_sha256: str) -> bytes:
    """``"chutes-tdx-measurement-key-proof-v1" || 0x00 || user_id || 0x00 || archive_sha256`` (ASCII)."""
    if not isinstance(user_id, str) or not user_id or not user_id.isascii() or "\x00" in user_id:
        raise ValueError("the user id is non-empty ASCII without NUL")
    if not isinstance(archive_sha256, str) or _HEX64.fullmatch(archive_sha256) is None:
        raise ValueError("archive_sha256 is 64 lower-case hex characters")
    return PROOF_PREFIX + user_id.encode("ascii") + b"\x00" + archive_sha256.encode("ascii")


def sign_proof(key: Ed25519PrivateKey, user_id: str, archive_sha256: str) -> str:
    return b64(key.sign(proof_message(user_id, archive_sha256)))


def verify_proof(public: bytes, user_id: str, archive_sha256: str, proof_b64: str) -> bool:
    try:
        signature = strict_b64(proof_b64, 64)
        Ed25519PublicKey.from_public_bytes(public).verify(signature, proof_message(user_id, archive_sha256))
        return True
    except (ValueError, InvalidSignature):
        return False


# --- the document --------------------------------------------------------------------------------

def write_document(image_sha256: str, entries: list) -> bytes:
    """The document as the tool writes it (``json.dumps(indent=2)`` and a newline). Any bytes that
    verify are valid: these are what get signed."""
    raw = (json.dumps({"type": DOCUMENT_TYPE, "image_sha256": image_sha256, "accept": entries}, indent=2) + "\n").encode()
    parse_unsigned(raw)
    return raw


def sign_document(key: Ed25519PrivateKey, raw: bytes) -> str:
    """``B64`` of the 64-byte Ed25519 signature over the exact bytes, no newline."""
    return b64(key.sign(raw))


def _pairs(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise DocumentRefused("document_invalid", "duplicate key")
    return dict(pairs)


def _constant(_name):
    raise DocumentRefused("document_invalid", "NaN or Infinity")


def _hex(value, pattern) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def parse_unsigned(raw: bytes) -> list:
    """Steps 3 and 4 alone (the closed shape), for writing and tests."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raise DocumentRefused("document_invalid", "byte-order mark")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except DocumentRefused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise DocumentRefused("document_invalid", "not strict UTF-8 JSON") from None
    if not isinstance(value, dict) or set(value) != {"type", "image_sha256", "accept"}:
        raise DocumentRefused("document_invalid", "the keys are type, image_sha256 and accept")
    if value["type"] != DOCUMENT_TYPE or not _hex(value["image_sha256"], _HEX64):
        raise DocumentRefused("document_invalid", "type or image_sha256")
    entries = value["accept"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise DocumentRefused("document_invalid", "accept is a list of 1..32 entries")
    for entry in entries:
        if not isinstance(entry, dict) or not _hex(entry.get("machine_type"), _MACHINE_TYPE):
            raise DocumentRefused("document_invalid", "an entry's machine_type")
        if not _hex(entry.get("rtmr1"), _HEX96) or not _hex(entry.get("rtmr2"), _HEX96):
            raise DocumentRefused("document_invalid", "an entry's rtmr1 or rtmr2")
        if "rtmr3" not in entry or (entry["rtmr3"] is not None and not _hex(entry["rtmr3"], _HEX96)):
            raise DocumentRefused("document_invalid", "rtmr3 is always present: null or 96 hex")
        keys = set(entry)
        if keys == EXACT_KEYS:
            if not _hex(entry["mrtd"], _HEX96) or not _hex(entry["rtmr0"], _HEX96):
                raise DocumentRefused("document_invalid", "an exact entry's mrtd or rtmr0")
        elif keys == FOLLOW_KEYS:
            template = entry["rtmr0_template"]
            if (entry["mrtd"] != "gce-endorsed" or not isinstance(template, dict)
                    or set(template) != {"before_cfv", "after_cfv"} or not _hex(template["before_cfv"], _HEX96)
                    or not isinstance(template["after_cfv"], list) or not 1 <= len(template["after_cfv"]) <= 32
                    or not all(_hex(item, _HEX96) for item in template["after_cfv"])):
                raise DocumentRefused("document_invalid", "a firmware-following entry")
        else:
            raise DocumentRefused("document_invalid", "an entry is neither form")
    return entries, value["image_sha256"]


def parse_document(raw: bytes, signature_b64: str, public: bytes, image_sha256: str) -> list:
    """Steps 1-5. Returns the entries or raises :class:`DocumentRefused`."""
    if not isinstance(raw, (bytes, bytearray)) or not 1 <= len(raw) <= MAX_DOCUMENT_BYTES:
        raise DocumentRefused("document_too_large" if isinstance(raw, (bytes, bytearray)) and raw else "document_invalid")
    raw = bytes(raw)
    try:
        signature = strict_b64(signature_b64, 64)
        Ed25519PublicKey.from_public_bytes(public).verify(signature, raw)
    except (ValueError, InvalidSignature):
        raise DocumentRefused("document_signature_invalid") from None
    entries, named = parse_unsigned(raw)
    if named != image_sha256:
        raise DocumentRefused("document_image_mismatch")
    return entries
