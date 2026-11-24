"""Intel TDX quote verification: dcap-qvl 0.5.3 plus the shared TDX policy module.

``verify_tdx_quote_bytes`` is chutes-attest's one TDX verification step. It applies the
validator's policy through the shared policy module ``tdx_policy``:

1. the installed ``dcap_qvl`` must be exactly ``DCAP_QVL_AUDITED_VERSION`` (the audited fallback
   and the validator's identical verdict hold only for it); anything else is ``VerifierUnavailable``;
2. collateral comes from ONE seam, ``_fetch_collateral(raw, source)``: ``intel-pcs`` (default,
   Intel's PCS), ``phala-pccs`` or an explicit ``https://`` PCCS, chosen by the caller or by
   ``TDX_COLLATERAL_SOURCE``;
3. ``check_collateral_freshness`` runs before ``verify_with_root_ca``; stale collateral is
   ``VerifierUnavailable`` (no verdict), never a verdict against the TD;
4. ``verify_with_root_ca`` checks the quote against the pinned Intel SGX Root CA; its exact
   audited step-8 error is resolved by the module-identity fallback, any other refusal is a
   decided ``TdxQuoteRejected``;
5. ``evaluate_tdx_verdict`` returns the named checks ``tcb_status``, ``advisories``,
   ``td_attributes`` and ``not_debug``.

Every verdict also names the collateral it was reached under (``TdxVerdict.collateral_sha256``,
``collateral_sha256``), so a recorded verdict can be re-checked offline under it.

The library is imported lazily, so the package imports cleanly before it is installed.
"""

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional
from urllib.parse import urlsplit

from .intel_root import INTEL_SGX_ROOT_CA_DER
from .tdx_policy import (
    DCAP_QVL_AUDITED_VERSION,
    PolicyCheck,
    TdxPolicyError,
    all_passed,
    check_collateral_freshness,
    evaluate_tdx_verdict,
    failed,
    is_audited_platform_tcb_error,
    resolve_tcb_via_module_identity,
)

COLLATERAL_SOURCE_ENV = "TDX_COLLATERAL_SOURCE"
DEFAULT_COLLATERAL_SOURCE = "intel-pcs"
NAMED_COLLATERAL_SOURCES = ("intel-pcs", "phala-pccs")


class VerifierUnavailable(RuntimeError):
    """No verdict: the verifier's own inputs (library, collateral, NVIDIA verifier) cannot decide.

    Never a verdict against the TD: callers report "no verdict" and ask for a retry.
    """


class TdxQuoteRejected(ValueError):
    """Intel DCAP verification refused the quote: a decided negative, not an outage."""


@dataclass(frozen=True)
class TdxVerdict:
    """A dcap-qvl verified report (JSON form) and the shared policy's checks on it."""

    verified: dict
    checks: List[PolicyCheck]
    freshness: List[PolicyCheck] = field(default_factory=list)
    fallback: bool = False
    # The SHA-256 of the canonical JSON of the collateral the verdict was reached under
    # (``collateral_sha256``); ``None`` only when the library's collateral has no JSON form.
    collateral_sha256: Optional[str] = None
    # That collateral as canonical JSON text, kept with the evidence so the verdict can be
    # re-checked offline (``verify_tdx_quote_with_collateral``).
    collateral_json: Optional[str] = None

    @property
    def status(self) -> str:
        return str(self.verified.get("status", "Unknown"))

    @property
    def advisory_ids(self) -> List[str]:
        value = self.verified.get("advisory_ids") or []
        return list(value) if isinstance(value, list) else []

    @property
    def td10(self) -> dict:
        report = self.verified.get("report")
        td10 = report.get("TD10") if isinstance(report, dict) else None
        return td10 if isinstance(td10, dict) else {}

    @property
    def passed(self) -> bool:
        return all_passed(self.checks)


def resolve_collateral_source(source: Optional[str] = None) -> str:
    """The collateral source: the explicit value, else ``TDX_COLLATERAL_SOURCE``, else Intel PCS."""
    value = source if source is not None else os.environ.get(COLLATERAL_SOURCE_ENV)
    value = (value or DEFAULT_COLLATERAL_SOURCE).strip()
    if value in NAMED_COLLATERAL_SOURCES:
        return value
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "TDX collateral source must be intel-pcs, phala-pccs or an https:// PCCS URL "
            "without credentials, query or fragment"
        )
    return value


def _library():
    try:
        import dcap_qvl  # type: ignore[import-untyped]
    except ImportError as exc:
        raise VerifierUnavailable(
            f"dcap-qvl {DCAP_QVL_AUDITED_VERSION} is required to verify Intel TDX quotes"
        ) from exc
    version = getattr(dcap_qvl, "__version__", None)
    if version != DCAP_QVL_AUDITED_VERSION:
        raise VerifierUnavailable(
            f"installed dcap-qvl {version!r} is not the audited {DCAP_QVL_AUDITED_VERSION}; "
            "install the pinned version (the validator's audited fallback is valid only for it)"
        )
    return dcap_qvl


async def _fetch_collateral(raw: bytes, source: str):
    """The one collateral seam: Intel PCS, Phala's PCCS or an explicit https:// PCCS."""
    dcap_qvl = _library()
    if source == "intel-pcs":
        return await dcap_qvl.get_collateral_from_pcs(raw)
    if source == "phala-pccs":
        return await dcap_qvl.get_collateral(dcap_qvl.PHALA_PCCS_URL, raw)
    return await dcap_qvl.get_collateral(source, raw)


def canonical_collateral_json(collateral) -> Optional[str]:
    """dcap-qvl's ``QuoteCollateralV3.to_json()`` (the TCB info, QE identity, CRLs, issuer chains
    and signatures one verdict used) as canonical JSON text: sorted, compact ASCII. ``None``
    when the object has no JSON form."""
    to_json = getattr(collateral, "to_json", None)
    if not callable(to_json):
        return None
    try:
        return json.dumps(
            json.loads(to_json()),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return None


def collateral_json_sha256(text: str) -> str:
    """The SHA-256 of the canonical collateral JSON text plus one trailing newline: the digest a
    recorded verdict names as its collateral."""
    return hashlib.sha256(text.encode("ascii") + b"\n").hexdigest()


def collateral_sha256(collateral) -> Optional[str]:
    """``collateral_json_sha256`` of ``collateral``; ``None`` when it has no JSON form."""
    text = canonical_collateral_json(collateral)
    return None if text is None else collateral_json_sha256(text)


def _hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, str):
        return value.lower()
    raise TdxQuoteRejected(
        f"cannot interpret {type(value).__name__} as TD report bytes"
    )


def _fallback_report(dcap_qvl, raw: bytes, collateral, original: ValueError) -> dict:
    """The audited module-identity fallback: the verified report with Intel's TCB verdict."""
    try:
        parsed = dcap_qvl.Quote.parse(raw)
    except ValueError as exc:
        raise TdxQuoteRejected(f"unable to parse the verified quote: {exc}") from exc
    if not parsed.is_tdx():
        raise TdxQuoteRejected(f"Intel DCAP verification failed: {original}")
    report = parsed.report
    pck = parsed.pck_extension()
    if pck is None:
        raise TdxQuoteRejected("unable to parse the verified quote's PCK extension")
    try:
        status, advisory_ids = resolve_tcb_via_module_identity(
            tcb_info_json=collateral.tcb_info,
            qe_identity_json=collateral.qe_identity,
            tee_tcb_svn=list(report.tee_tcb_svn),
            cpu_svn=list(pck.cpu_svn),
            pce_svn=pck.pce_svn,
            mr_signer_seam=report.mr_signer_seam,
            seam_attributes=report.seam_attributes,
            raw_quote=raw,
        )
    except TdxPolicyError as exc:
        raise TdxQuoteRejected(f"TDX TCB resolution failed: {exc}") from exc
    return {
        "status": status,
        "advisory_ids": advisory_ids,
        "report": {
            "TD10": {
                "mr_td": _hex(report.mr_td),
                "rt_mr0": _hex(report.rt_mr0),
                "rt_mr1": _hex(report.rt_mr1),
                "rt_mr2": _hex(report.rt_mr2),
                "rt_mr3": _hex(report.rt_mr3),
                "report_data": _hex(report.report_data),
                "td_attributes": _hex(report.td_attributes),
            }
        },
    }


async def verify_tdx_quote_bytes(
    raw: bytes,
    *,
    allow_advisories: bool = False,
    accepted_advisory_ids: Iterable[str] = (),
    now: Optional[int] = None,
    collateral_source: Optional[str] = None,
) -> TdxVerdict:
    """Verify a raw TDX quote under the validator's policy; see the module docstring.

    ``now`` is Unix seconds (default: the wall clock); the same instant feeds collateral freshness
    and dcap-qvl.  Raises ``VerifierUnavailable`` (no verdict) or ``TdxQuoteRejected`` (decided).
    """
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise TdxQuoteRejected("TDX quote bytes are required")
    raw = bytes(raw)
    if isinstance(now, bool) or (now is not None and not isinstance(now, int)):
        raise ValueError("now must be integer Unix seconds")
    now_secs = int(time.time()) if now is None else now
    source = resolve_collateral_source(collateral_source)
    dcap_qvl = _library()
    try:
        collateral = await _fetch_collateral(raw, source)
    except VerifierUnavailable:
        raise
    except ValueError as exc:
        raise TdxQuoteRejected(
            f"TDX quote/collateral request is invalid: {exc}"
        ) from exc
    except Exception as exc:
        raise VerifierUnavailable(
            f"TDX collateral from {source} is unavailable: {type(exc).__name__}: {exc}"
        ) from exc
    try:
        freshness = check_collateral_freshness(
            collateral.tcb_info, collateral.qe_identity, now=now_secs
        )
    except (AttributeError, TdxPolicyError) as exc:
        raise VerifierUnavailable(f"TDX collateral from {source} is malformed") from exc
    if not all_passed(freshness):
        raise VerifierUnavailable(
            f"stale TDX collateral from {source}: "
            + "; ".join(f"{check.name}: {check.detail}" for check in failed(freshness))
        )
    # CPU-bound signature and collateral checks run off the event loop, so concurrent verifications
    # do not block it.
    return await asyncio.to_thread(
        _decide,
        dcap_qvl,
        raw,
        collateral,
        now_secs,
        freshness,
        allow_advisories,
        accepted_advisory_ids,
    )


def _decide(
    dcap_qvl,
    raw: bytes,
    collateral,
    now_secs: int,
    freshness,
    allow_advisories: bool,
    accepted_advisory_ids: Iterable[str],
) -> TdxVerdict:
    """The verdict under ``collateral`` at ``now_secs``: the quote against the pinned Intel
    root, the audited fallback, then the shared policy."""
    fallback = False
    try:
        verified = dcap_qvl.verify_with_root_ca(
            raw,
            collateral,
            INTEL_SGX_ROOT_CA_DER,
            now_secs,
        )
    except ValueError as exc:
        # Only the audited step-8 error of the audited version may be resolved; every other
        # refusal (signature, chain, policy) is Intel's decided negative.
        if not is_audited_platform_tcb_error(str(exc), dcap_qvl.__version__):
            raise TdxQuoteRejected(f"Intel DCAP verification failed: {exc}") from exc
        document = _fallback_report(dcap_qvl, raw, collateral, exc)
        fallback = True
    except Exception as exc:
        raise VerifierUnavailable(
            f"Intel DCAP verifier failed before a verdict: {type(exc).__name__}: {exc}"
        ) from exc
    else:
        try:
            document = json.loads(verified.to_json())
        except Exception as exc:
            raise VerifierUnavailable(
                "Intel DCAP verifier returned an unreadable report"
            ) from exc
    if not isinstance(document, dict):
        raise VerifierUnavailable("Intel DCAP verifier returned a malformed report")
    checks = evaluate_tdx_verdict(
        document,
        allow_advisories=allow_advisories,
        accepted_advisory_ids=accepted_advisory_ids,
    )
    return TdxVerdict(
        verified=document,
        checks=checks,
        freshness=freshness,
        fallback=fallback,
        collateral_sha256=collateral_sha256(collateral),
        collateral_json=canonical_collateral_json(collateral),
    )


def verify_tdx_quote_with_collateral(
    raw: bytes,
    collateral_json: str,
    *,
    now: int,
    allow_advisories: bool = False,
    accepted_advisory_ids: Iterable[str] = (),
) -> TdxVerdict:
    """Re-check a captured quote offline under its kept collateral (the capture-time verdict's
    ``collateral_json``) as at ``now``, its capture time in Unix seconds: the same freshness,
    signature, fallback and policy steps, with no fetch."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise TdxQuoteRejected("TDX quote bytes are required")
    dcap_qvl = _library()
    try:
        collateral = dcap_qvl.QuoteCollateralV3.from_json(collateral_json)
    except Exception as exc:
        raise TdxQuoteRejected(
            f"the kept TDX collateral does not parse: {exc}"
        ) from exc
    try:
        freshness = check_collateral_freshness(
            collateral.tcb_info, collateral.qe_identity, now=now
        )
    except (AttributeError, TdxPolicyError) as exc:
        raise TdxQuoteRejected("the kept TDX collateral is malformed") from exc
    if not all_passed(freshness):
        raise TdxQuoteRejected(
            "the kept TDX collateral was not fresh at the capture time: "
            + "; ".join(f"{check.name}: {check.detail}" for check in failed(freshness))
        )
    return _decide(
        dcap_qvl,
        bytes(raw),
        collateral,
        now,
        freshness,
        allow_advisories,
        accepted_advisory_ids,
    )
