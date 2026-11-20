"""Minimal, dependency-free TDX quote parser (v4).

Extracts MRTD, RTMR0-3 and the 64-byte REPORTDATA from a raw TDX quote using the field
offsets from the Intel TDX quote specification. It reads exactly the fields Chutes' validator's
parser reads, at the same offsets, with no shared trusted code and no dependency on the Chutes
repositories.

The cryptographic verification of the quote (Intel signature chain, TCB status) is done
separately by dcap-qvl in tdx_verify.py; this module only locates the fields.
"""

import struct
from dataclasses import dataclass

# Offsets are relative to the start of the 584-byte TD report, which begins at byte 48
# (after the 48-byte quote header). Values match the Intel TDX 1.0/1.5 quote layout.
_HEADER_LEN = 48
_TD_REPORT_LEN = 584
_REPORT_END = _HEADER_LEN + _TD_REPORT_LEN  # 632
_MIN_QUOTE_LEN = _REPORT_END + 4  # v4 signature-data length

_TEE_TYPE_TDX = 0x81


class QuoteParseError(ValueError):
    """Raised when a blob is not a well-formed TDX quote."""


@dataclass(frozen=True)
class ParsedQuote:
    version: int
    att_key_type: int
    tee_type: int
    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    report_data: str  # 128 hex chars == 64 bytes
    # TD identity (TD10 body offsets, upper hex): XFAM, the three owner-defined
    # registers (all-zero unless a launcher sets them) and MRSEAM (the TDX module measurement,
    # recorded only). Defaults keep directly constructed quotes valid.
    xfam: str = ""
    mr_config_id: str = "0" * 96
    mr_owner: str = "0" * 96
    mr_owner_config: str = "0" * 96
    mr_seam: str = ""

    @property
    def rtmrs(self) -> dict[str, str]:
        return {
            "rtmr0": self.rtmr0,
            "rtmr1": self.rtmr1,
            "rtmr2": self.rtmr2,
            "rtmr3": self.rtmr3,
        }

    @property
    def td_identity(self) -> dict[str, str]:
        return {
            "xfam": self.xfam,
            "mr_config_id": self.mr_config_id,
            "mr_owner": self.mr_owner,
            "mr_owner_config": self.mr_owner_config,
        }

    @property
    def nonce(self) -> str:
        """report_data[0:32] as hex: the tagged slot the producer bound for the caller's nonce.

        Network-reachable quote routes bind sha256(public-quote tag || nonce) here; the
        statement quote binds its own slot. REPORTDATA = slot(32B) || sha256(server cert pubkey).
        """
        return self.report_data[:64].lower()

    @property
    def cert_hash(self) -> str:
        """sha256 of the bound TLS server-cert public key (DER SubjectPublicKeyInfo)."""
        return self.report_data[64:128].lower()


def parse_quote(quote_bytes: bytes) -> ParsedQuote:
    """Parse a raw TDX quote. Raises QuoteParseError on any structural problem."""
    if len(quote_bytes) < _HEADER_LEN:
        raise QuoteParseError(
            f"Quote too short: {len(quote_bytes)} bytes (need >= {_HEADER_LEN})"
        )

    # Header: uint16 version, uint16 att_key_type, uint32 tee_type, 16s QE vendor id, 20s user data.
    try:
        version, att_key_type, tee_type, _qe_vendor_id, _hdr_user_data = (
            struct.unpack_from("<HHI16s20s", quote_bytes, 0)
        )
    except struct.error as exc:  # pragma: no cover - guarded by length check above
        raise QuoteParseError(f"Failed to parse quote header: {exc}") from exc

    if version != 4:
        raise QuoteParseError(
            f"Unsupported quote version {version} (only TDX quote v4 is parsed)"
        )
    if tee_type != _TEE_TYPE_TDX:
        raise QuoteParseError(
            f"Not a TDX quote: tee_type=0x{tee_type:08x} (expected 0x{_TEE_TYPE_TDX:02x})"
        )
    if att_key_type not in (2, 3):  # ECDSA-256 / ECDSA-384
        raise QuoteParseError(f"Unexpected attestation key type {att_key_type}")
    if len(quote_bytes) < _MIN_QUOTE_LEN:
        raise QuoteParseError(
            f"TDX quote v4 body is truncated: {len(quote_bytes)} bytes "
            f"(need >= {_MIN_QUOTE_LEN})"
        )
    signature_data_len = struct.unpack_from("<I", quote_bytes, _REPORT_END)[0]
    available = len(quote_bytes) - _MIN_QUOTE_LEN
    if signature_data_len <= 0 or signature_data_len > available:
        raise QuoteParseError(
            "TDX quote v4 signature body is malformed or truncated "
            f"(declared={signature_data_len}, available={available})"
        )

    td = quote_bytes[_HEADER_LEN : _HEADER_LEN + _TD_REPORT_LEN]
    return ParsedQuote(
        version=version,
        att_key_type=att_key_type,
        tee_type=tee_type,
        mrtd=td[136:184].hex().upper(),
        rtmr0=td[328:376].hex().upper(),
        rtmr1=td[376:424].hex().upper(),
        rtmr2=td[424:472].hex().upper(),
        rtmr3=td[472:520].hex().upper(),
        report_data=td[520:584].hex().upper(),
        xfam=td[128:136].hex().upper(),
        mr_config_id=td[184:232].hex().upper(),
        mr_owner=td[232:280].hex().upper(),
        mr_owner_config=td[280:328].hex().upper(),
        mr_seam=td[16:64].hex().upper(),
    )
