"""A test PKI and synthetic Google TDX launch endorsements (``gce_pki``, ``synthetic_tdvf``,
``tdx_endorsement``), so the firmware admission runs end to end without Google's bucket."""

import datetime as dt
import functools
import hashlib
import secrets
import struct
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

PSS32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def field(number: int, wire_type: int, value) -> bytes:
    key = varint((number << 3) | wire_type)
    if wire_type == 0:
        return key + varint(value)
    return key + varint(len(value)) + bytes(value)


@functools.lru_cache(maxsize=1)
def gce_pki():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-cc-tcb-root")])
    ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(ski, critical=False)
            .sign(root_key, hashes.SHA256(), rsa_padding=PSS32))
    signer = (x509.CertificateBuilder()
              .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-uefi-signer")]))
              .issuer_name(root_name).public_key(signer_key.public_key()).serial_number(2)
              .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1825))
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
              .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                           data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                           crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .sign(root_key, hashes.SHA256(), rsa_padding=PSS32))
    return {"root_der": root.public_bytes(serialization.Encoding.DER),
            "signer_der": signer.public_bytes(serialization.Encoding.DER), "signer_key": signer_key}


_TABLE_FOOTER_GUID = uuid.UUID("96b582de-1fb2-45f7-baea-a366c55a082d").bytes_le
_TDX_METADATA_GUID = uuid.UUID("e47a6535-984a-4798-865e-4685a7bf8ec2").bytes_le


def synthetic_tdvf(cfv: bytes, *, size: int = 0x10000) -> bytes:
    """A minimal OVMF image whose TDVF metadata names ``cfv`` (at offset 0) as its CFV section."""
    fw = bytearray(size)
    fw[: len(cfv)] = cfv
    sections = [
        (len(cfv), 0x1000, 0xFFE20000, 0x1000, 0, 1),
        (0, len(cfv), 0xFFE00000, -(-len(cfv) // 0x1000) * 0x1000, 1, 0),
        (0, 0, 0x809000, 0x2000, 2, 0),
        (0, 0, 0x800000, 0x6000, 3, 0),
    ]
    descriptor_offset = size - 0x1000
    descriptor = b"TDVF" + struct.pack("<III", 16 + 32 * len(sections), 1, len(sections))
    for section in sections:
        descriptor += struct.pack("<IIQQII", *section)
    fw[descriptor_offset: descriptor_offset + len(descriptor)] = descriptor
    entry = struct.pack("<I", size - descriptor_offset) + struct.pack("<H", 4 + 18) + _TDX_METADATA_GUID
    footer = struct.pack("<H", len(entry) + 18) + _TABLE_FOOTER_GUID
    table_end = size - 32
    fw[table_end - len(footer) - len(entry): table_end] = entry + footer
    return bytes(fw)


def tdx_endorsement(mrtds, *, endorsed_at, svn=2, cl_spec=957008435, binary=None):
    """``(endorsement, binary, uefi hex)`` listing ``[(ram_gib, early_accept, mrtd hex)]``."""
    pki = gce_pki()
    binary = binary if binary is not None else synthetic_tdvf(secrets.token_bytes(0x2000))
    uefi = hashlib.sha384(binary).digest()
    entries = b"".join(field(2, 2, field(1, 0, gib) + field(2, 0, int(early)) + field(3, 2, bytes.fromhex(value)))
                       for gib, early, value in mrtds)
    golden = (field(1, 2, field(1, 0, int(endorsed_at.timestamp()))) + field(2, 0, cl_spec)
              + field(4, 2, pki["signer_der"]) + field(5, 2, uefi) + field(8, 2, field(1, 0, svn) + entries))
    signature = pki["signer_key"].sign(golden, PSS32, hashes.SHA256())
    return field(1, 2, golden) + field(2, 2, signature), binary, uefi.hex()
