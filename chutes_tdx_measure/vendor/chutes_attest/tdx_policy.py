"""Intel TDX verification policy applied to the output of Intel's DCAP library ``dcap-qvl``.

The module imports only the standard library and never imports dcap-qvl: callers pass plain JSON,
bytes and integers and turn the returned ``PolicyCheck`` results into their own diagnostics.

Verdict (``evaluate_tdx_verdict``), four checks evaluated without short-circuiting:

    tcb_status     status == "UpToDate"; with ``allow_advisories`` also one of the three Intel
                   "Needed" statuses in ``ADVISORY_TOLERANT_STATUSES`` (Intel's spelling only)
    advisories     ``advisory_ids`` is empty, or every id is named in ``accepted_advisory_ids``
    td_attributes  TDATTRIBUTES (8 bytes, little-endian) set SEPT_VE_DISABLE (bit 28) and no bit
                   outside DEBUG (0), SEPT_VE_DISABLE (28), PKS (30) and KL (31)
    not_debug      the DEBUG bit (0) is clear; a missing or unparseable value counts as debug

Module-identity TCB resolution (``resolve_tcb_via_module_identity``). dcap-qvl 0.5.3 compares the
two module-governed TEE_TCB_SVN bytes while it selects the platform TCB level, so a host whose TDX
module SVN restarts low fails with "No matching TCB level found" although Intel reports it
UpToDate. Only that error, raised by exactly ``DCAP_QVL_AUDITED_VERSION``
(``is_audited_platform_tcb_error``), is resolved with Intel's algorithm over the Intel-signed TCB
Info: the platform level excluding the module bytes (``match_platform_tcb_level``), the TDX module
identity (``verify_tdx_module``) and the authenticated QE verdict
(``resolve_authenticated_qe_tcb_status``), merged by severity. Any other library version or error
fails closed. dcap-qvl raises that error only after it has verified the quote, PCK chain, QE report
and collateral signatures against the caller's pinned root, so the fallback never replaces a
signature check.

Collateral freshness (``check_collateral_freshness``). TCB Info and QE Identity must each carry
``tcbEvaluationDataNumber`` >= ``TDX_TCB_EVALUATION_DATA_NUMBER_MIN`` and an ``issueDate`` at most
``TDX_COLLATERAL_MAX_AGE_DAYS`` old (and not in the future) at the caller's ``now`` (Unix seconds).
Stale collateral is a verifier input problem, so callers report "no verdict", never a failure of the
TD. A caller may raise the evaluation floor, never lower it.
"""

import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

TDX_POLICY_MODULE_VERSION = 1

# The only dcap-qvl release whose "No matching TCB level found" error is known to come after every
# signature check (see the module docstring); the fallback applies to it alone.
DCAP_QVL_AUDITED_VERSION = "0.5.3"

# Intel's TCB status spellings (the strings dcap-qvl emits) and their severity order.
TCB_STATUS_SEVERITY: Dict[str, int] = {
    "UpToDate": 0,
    "SWHardeningNeeded": 1,
    "ConfigurationNeeded": 2,
    "ConfigurationAndSWHardeningNeeded": 3,
    "OutOfDate": 4,
    "OutOfDateConfigurationNeeded": 5,
    "Revoked": 6,
}
KNOWN_TCB_STATUSES: FrozenSet[str] = frozenset(TCB_STATUS_SEVERITY)
ADVISORY_TOLERANT_STATUSES: Tuple[str, ...] = (
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
)

# TDATTRIBUTES (TDREPORT10, 8 bytes little-endian): DEBUG (0), SEPT_VE_DISABLE (28),
# PKS (30) and KL (31) are the only bits a production TD may set; SEPT_VE_DISABLE is required.
TD_ATTRIBUTE_DEBUG_BIT = 0
TD_ATTRIBUTES_REQUIRED = 1 << 28
TD_ATTRIBUTES_ALLOWED = (1 << 0) | (1 << 28) | (1 << 30) | (1 << 31)

# dcap-qvl 0.5.3's exact error text, bare and as its verifier wraps it.
PLATFORM_TCB_ERROR = "No matching TCB level found"
_AUDITED_PLATFORM_TCB_MESSAGES: FrozenSet[str] = frozenset(
    {PLATFORM_TCB_ERROR, f"Verification failed: {PLATFORM_TCB_ERROR}"}
)

# Collateral freshness: minimum tcbEvaluationDataNumber and maximum issueDate age.
TDX_TCB_EVALUATION_DATA_NUMBER_MIN = 19
TDX_COLLATERAL_MAX_AGE_DAYS = 30

# TDX quote v4 authentication data layout (the QE report certification data).
_TDX_V4_AUTH_LENGTH_OFFSET = 632
_TDX_V4_AUTH_DATA_OFFSET = 636
_ECDSA_SIGNATURE_AND_KEY_LENGTH = 128
_CERTIFICATION_DATA_HEADER_LENGTH = 6
_QE_REPORT_CERTIFICATION_DATA_TYPE = 6
_QE_REPORT_LENGTH = 384
_QE_REPORT_ISV_SVN_OFFSET = 258


class TdxPolicyError(ValueError):
    """The TCB collateral or quote cannot be resolved under the policy (fail closed)."""


@dataclass(frozen=True)
class PolicyCheck:
    name: str
    passed: bool
    detail: str


def all_passed(checks: Iterable[PolicyCheck]) -> bool:
    return all(check.passed for check in checks)


def failed(checks: Iterable[PolicyCheck]) -> List[PolicyCheck]:
    return [check for check in checks if not check.passed]


def debug_enabled(td_attributes: Any) -> bool:
    """True when the DEBUG bit (0) is set; a missing or unparseable value counts as debug."""
    if not td_attributes:
        return True
    try:
        # dcap-qvl serializes td_attributes in little-endian memory order (byte[0] first).
        value = int.from_bytes(bytes.fromhex(td_attributes), "little")
    except (ValueError, TypeError):
        return True
    return bool(value & (1 << TD_ATTRIBUTE_DEBUG_BIT))


def td_attributes_valid(td_attributes: Any) -> bool:
    """dcap-qvl's production TD10 attribute policy: SEPT_VE_DISABLE set, only 0/28/30/31."""
    try:
        raw = bytes.fromhex(td_attributes)
    except (ValueError, TypeError):
        return False
    if len(raw) != 8:
        return False
    value = int.from_bytes(raw, "little")
    return bool(value & TD_ATTRIBUTES_REQUIRED) and not bool(
        value & ~TD_ATTRIBUTES_ALLOWED
    )


def _td10(verified_json: Mapping[str, Any]) -> Mapping[str, Any]:
    report = verified_json.get("report")
    if not isinstance(report, Mapping):
        return {}
    td10 = report.get("TD10")
    return td10 if isinstance(td10, Mapping) else {}


def evaluate_tdx_verdict(
    verified_json: Mapping[str, Any],
    *,
    allow_advisories: bool = False,
    accepted_advisory_ids: Iterable[str] = frozenset(),
) -> List[PolicyCheck]:
    """Evaluate a dcap-qvl verified report (its JSON form); never short-circuits.

    ``allow_advisories`` admits exactly the three Intel "Needed" statuses; a non-empty
    ``advisory_ids`` list is admitted only when every id is in ``accepted_advisory_ids``.
    """
    if not isinstance(verified_json, Mapping):
        raise TdxPolicyError("verified report must be a JSON object")
    if not isinstance(allow_advisories, bool):
        raise TdxPolicyError("allow_advisories must be a boolean")
    if isinstance(accepted_advisory_ids, (str, bytes)):
        raise TdxPolicyError("accepted_advisory_ids must be a collection of ids")
    accepted = frozenset(accepted_advisory_ids)
    checks: List[PolicyCheck] = []

    status = verified_json.get("status", "Unknown")
    acceptable = {"UpToDate"}
    if allow_advisories:
        acceptable |= set(ADVISORY_TOLERANT_STATUSES)
    if isinstance(status, str) and status in acceptable:
        checks.append(PolicyCheck("tcb_status", True, f"TCB status={status}"))
    else:
        required = "UpToDate" + (
            " or an Intel 'Needed' status" if allow_advisories else ""
        )
        checks.append(
            PolicyCheck(
                "tcb_status",
                False,
                f"TCB status={status!r} is not accepted ({required} required)",
            )
        )

    advisory_ids = verified_json.get("advisory_ids") or []
    if not isinstance(advisory_ids, list) or any(
        not isinstance(item, str) for item in advisory_ids
    ):
        checks.append(
            PolicyCheck("advisories", False, "advisory_ids is not a list of ids")
        )
    elif not advisory_ids:
        checks.append(
            PolicyCheck("advisories", True, "no Intel security advisories apply")
        )
    else:
        unaccepted = [item for item in advisory_ids if item not in accepted]
        if unaccepted:
            checks.append(
                PolicyCheck(
                    "advisories",
                    False,
                    "unaccepted Intel security advisories: " + ", ".join(unaccepted),
                )
            )
        else:
            checks.append(
                PolicyCheck(
                    "advisories",
                    True,
                    "every advisory is explicitly accepted: " + ", ".join(advisory_ids),
                )
            )

    td_attributes = _td10(verified_json).get("td_attributes", "")
    if td_attributes_valid(td_attributes):
        checks.append(
            PolicyCheck("td_attributes", True, f"td_attributes=0x{td_attributes}")
        )
    else:
        checks.append(
            PolicyCheck(
                "td_attributes",
                False,
                f"td_attributes={td_attributes!r} is not a production TD "
                "(SEPT_VE_DISABLE required; only DEBUG/SEPT_VE_DISABLE/PKS/KL allowed)",
            )
        )
    debug = debug_enabled(td_attributes)
    checks.append(
        PolicyCheck(
            "not_debug",
            not debug,
            (
                "DEBUG bit clear"
                if not debug
                else "the TD is a debug TD (or TDATTRIBUTES is missing)"
            ),
        )
    )
    return checks


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise TdxPolicyError("Invalid hex value in TDX module field") from exc
    raise TdxPolicyError(f"Cannot interpret {type(value).__name__} as bytes")


def merge_tcb_status(
    platform: Tuple[str, List[str]], module: Optional[Tuple[str, List[str]]]
) -> Tuple[str, List[str]]:
    """The worse of two (status, advisories) verdicts by Intel severity; advisories union."""
    if module is None:
        return platform
    platform_status, platform_advisories = platform
    module_status, module_advisories = module
    unknown = max(TCB_STATUS_SEVERITY.values()) + 1
    status = (
        module_status
        if TCB_STATUS_SEVERITY.get(module_status, unknown)
        > TCB_STATUS_SEVERITY.get(platform_status, unknown)
        else platform_status
    )
    advisories = list(platform_advisories)
    advisories.extend(item for item in module_advisories if item not in advisories)
    return status, advisories


def match_platform_tcb_level(
    tcb_info: Mapping[str, Any],
    tee_tcb_svn: Sequence[int],
    sgx_tcb_components: Sequence[int],
    pce_svn: int,
) -> Tuple[str, List[str]]:
    """Apply Intel's platform-level matching, excluding module-governed SVN bytes."""
    tdx_start = 2 if tee_tcb_svn[1] > 0 else 0
    for level in tcb_info.get("tcbLevels", []):
        tcb = level["tcb"]
        if pce_svn < tcb["pcesvn"]:
            continue
        sgx_components = [
            component["svn"] for component in tcb.get("sgxtcbcomponents", [])
        ]
        if len(sgx_components) != len(sgx_tcb_components):
            raise TdxPolicyError("SGX TCB component count mismatch in TCB Info")
        if any(
            actual < required
            for actual, required in zip(sgx_tcb_components, sgx_components)
        ):
            continue
        tdx_components = [
            component["svn"] for component in tcb.get("tdxtcbcomponents", [])
        ]
        if len(tdx_components) != len(tee_tcb_svn):
            raise TdxPolicyError("TDX TCB component count mismatch in TCB Info")
        if any(
            actual < required
            for actual, required in zip(
                tee_tcb_svn[tdx_start:], tdx_components[tdx_start:]
            )
        ):
            continue
        return level["tcbStatus"], level.get("advisoryIDs", []) or []
    raise TdxPolicyError("No matching platform TCB level found")


def verify_tdx_module(
    tcb_info: Mapping[str, Any],
    tee_tcb_svn: Sequence[int],
    mr_signer_seam: Any,
    seam_attributes: Any,
) -> Optional[Tuple[str, List[str]]]:
    """Verify the exact Intel-signed TDX module identity and select its TCB level."""
    module_minor_svn, module_major_svn = tee_tcb_svn[0], tee_tcb_svn[1]
    if tcb_info.get("id") != "TDX" or tcb_info.get("version", 0) < 3:
        if module_major_svn > 0:
            raise TdxPolicyError(
                "TDX TCB Info cannot authenticate a non-base module identity"
            )
        return None
    base = tcb_info.get("tdxModule")
    if base is None:
        raise TdxPolicyError("TDX TCB Info is missing tdxModule field")

    expected_mrsigner = base["mrsigner"]
    expected_attributes = base["attributes"]
    attributes_mask = base["attributesMask"]
    identity_levels: Optional[List[Mapping[str, Any]]] = None

    # Intel PCS evaluates tdxModule only when the major SVN at index 1 is zero.
    # A non-zero major SVN must resolve through the matching TDX_XX module identity.
    identities = tcb_info.get("tdxModuleIdentities")
    if module_major_svn > 0:
        if not isinstance(identities, list) or not identities:
            raise TdxPolicyError(
                "TDX TCB Info is missing tdxModuleIdentities for a non-base module"
            )
        wanted_id = f"TDX_{module_major_svn:02X}"
        identity = next(
            (
                item
                for item in identities
                if item.get("id", "").upper() == wanted_id.upper()
            ),
            None,
        )
        if identity is None:
            raise TdxPolicyError(
                f"Unsupported TDX module major SVN: no identity '{wanted_id}' in TCB Info"
            )
        expected_mrsigner = identity["mrsigner"]
        expected_attributes = identity["attributes"]
        attributes_mask = identity["attributesMask"]
        identity_levels = identity.get("tcbLevels", [])

    if _as_bytes(expected_mrsigner) != _as_bytes(mr_signer_seam):
        raise TdxPolicyError("TDX module MRSIGNER mismatch")

    expected = _as_bytes(expected_attributes)
    mask = _as_bytes(attributes_mask)
    actual = _as_bytes(seam_attributes)
    if not (len(expected) == len(mask) == len(actual)):
        raise TdxPolicyError("TDX module SEAMATTRIBUTES length mismatch")
    for expected_byte, mask_byte, actual_byte in zip(expected, mask, actual):
        if (
            expected_byte & mask_byte != actual_byte & mask_byte
            or actual_byte & (~mask_byte & 0xFF) != 0
        ):
            raise TdxPolicyError("TDX module SEAMATTRIBUTES mismatch")

    if identity_levels is not None:
        for level in identity_levels:
            if module_minor_svn >= level["tcb"]["isvsvn"]:
                return level["tcbStatus"], level.get("advisoryIDs", []) or []
        raise TdxPolicyError(
            f"TDX module minor SVN {module_minor_svn} below minimum in TDX module "
            "TCB levels"
        )
    return None


def resolve_tdx_tcb_status(
    tcb_info: Mapping[str, Any],
    tee_tcb_svn: Sequence[int],
    sgx_tcb_components: Sequence[int],
    pce_svn: int,
    mr_signer_seam: Any,
    seam_attributes: Any,
) -> Tuple[str, List[str]]:
    """Resolve platform and module TCB status using Intel's module-identity algorithm."""
    if len(tee_tcb_svn) < 2:
        raise TdxPolicyError("TEE_TCB_SVN too short to resolve TDX TCB status")
    platform = match_platform_tcb_level(
        tcb_info, tee_tcb_svn, sgx_tcb_components, pce_svn
    )
    module = verify_tdx_module(tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes)
    return merge_tcb_status(platform, module)


def is_audited_platform_tcb_error(message: Any, library_version: Any) -> bool:
    """Accept only the known dcap-qvl error, raised by the pinned library version.

    ``library_version`` is the caller's installed ``dcap_qvl.__version__``.
    """
    if library_version != DCAP_QVL_AUDITED_VERSION:
        return False
    return isinstance(message, str) and message in _AUDITED_PLATFORM_TCB_MESSAGES


def extract_tdx_v4_qe_isv_svn(raw_quote: bytes) -> int:
    """Extract QE ISVSVN from the authenticated QE report of a TDX quote v4."""
    try:
        auth_data_length = struct.unpack_from(
            "<I", raw_quote, _TDX_V4_AUTH_LENGTH_OFFSET
        )[0]
    except struct.error as exc:
        raise TdxPolicyError(
            "TDX quote is too short for its authentication-data length"
        ) from exc

    auth_data_end = _TDX_V4_AUTH_DATA_OFFSET + auth_data_length
    if auth_data_end > len(raw_quote):
        raise TdxPolicyError("TDX quote authentication data is truncated")

    outer_cert_offset = _TDX_V4_AUTH_DATA_OFFSET + _ECDSA_SIGNATURE_AND_KEY_LENGTH
    try:
        cert_type, cert_body_length = struct.unpack_from(
            "<HI", raw_quote, outer_cert_offset
        )
    except struct.error as exc:
        raise TdxPolicyError(
            "TDX quote is missing QE report certification data"
        ) from exc
    if cert_type != _QE_REPORT_CERTIFICATION_DATA_TYPE:
        raise TdxPolicyError(
            f"TDX quote has unexpected outer certification data type {cert_type}"
        )

    qe_report_offset = outer_cert_offset + _CERTIFICATION_DATA_HEADER_LENGTH
    cert_body_end = qe_report_offset + cert_body_length
    if cert_body_end > auth_data_end or cert_body_length < _QE_REPORT_LENGTH:
        raise TdxPolicyError("TDX quote QE report certification data is truncated")

    try:
        return struct.unpack_from(
            "<H", raw_quote, qe_report_offset + _QE_REPORT_ISV_SVN_OFFSET
        )[0]
    except struct.error as exc:
        raise TdxPolicyError("TDX quote QE report is truncated") from exc


def resolve_authenticated_qe_tcb_status(
    raw_quote: bytes, qe_identity_json: Any
) -> Tuple[str, List[str]]:
    """Recover the QE verdict dcap-qvl computed before its platform-level error.

    dcap-qvl 0.5.3 raises that error only after the QE identity signature, the PCK, QE and quote
    signatures, the QE identity policy and the QE TCB match have succeeded; the fallback carries
    the matched QE status and its advisories into the final verdict.
    """
    try:
        qe_identity = json.loads(qe_identity_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise TdxPolicyError(
            "Unable to parse authenticated QE Identity collateral"
        ) from exc
    if (
        not isinstance(qe_identity, dict)
        or qe_identity.get("id") != "TD_QE"
        or qe_identity.get("version") not in (2, 3)
    ):
        raise TdxPolicyError(
            "Authenticated QE Identity has an unsupported id or version"
        )

    qe_isv_svn = extract_tdx_v4_qe_isv_svn(raw_quote)
    levels = qe_identity.get("tcbLevels")
    if not isinstance(levels, list) or not levels:
        raise TdxPolicyError("Authenticated QE Identity has no TCB levels")

    for level in levels:
        try:
            required_isv_svn = level["tcb"]["isvsvn"]
            status_value = level["tcbStatus"]
            advisory_ids = level.get("advisoryIDs", []) or []
        except (KeyError, TypeError, AttributeError) as exc:
            raise TdxPolicyError(
                "Authenticated QE Identity TCB level is malformed"
            ) from exc
        if (
            isinstance(required_isv_svn, bool)
            or not isinstance(required_isv_svn, int)
            or not isinstance(status_value, str)
            or status_value not in KNOWN_TCB_STATUSES
            or not isinstance(advisory_ids, list)
            or any(not isinstance(item, str) for item in advisory_ids)
        ):
            raise TdxPolicyError("Authenticated QE Identity TCB level is malformed")
        if qe_isv_svn >= required_isv_svn:
            return status_value, advisory_ids

    raise TdxPolicyError(
        f"QE ISVSVN {qe_isv_svn} is below every authenticated QE Identity TCB level"
    )


def _json_object(value: Any, what: str) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        document = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise TdxPolicyError(f"Unable to parse {what}") from exc
    if not isinstance(document, dict):
        raise TdxPolicyError(f"{what} is not a JSON object")
    return document


def resolve_tcb_via_module_identity(
    *,
    tcb_info_json: Any,
    qe_identity_json: Any,
    tee_tcb_svn: Any,
    cpu_svn: Any,
    pce_svn: Any,
    mr_signer_seam: Any,
    seam_attributes: Any,
    raw_quote: bytes,
) -> Tuple[str, List[str]]:
    """The module-identity fallback: platform and module TCB level, merged with the QE verdict.

    ``tee_tcb_svn`` and ``cpu_svn`` accept dcap-qvl's ``bytes`` or integer lists;
    ``mr_signer_seam`` and ``seam_attributes`` accept ``bytes`` or hex. Call only after
    ``is_audited_platform_tcb_error`` admitted the library's error.
    """
    if isinstance(pce_svn, bool) or not isinstance(pce_svn, int):
        raise TdxPolicyError("PCESVN must be an integer")
    tcb_info = _json_object(tcb_info_json, "authenticated TCB Info collateral")
    status, advisory_ids = resolve_tdx_tcb_status(
        tcb_info=tcb_info,
        tee_tcb_svn=list(tee_tcb_svn),
        sgx_tcb_components=list(cpu_svn),
        pce_svn=pce_svn,
        mr_signer_seam=mr_signer_seam,
        seam_attributes=seam_attributes,
    )
    qe_json = (
        json.dumps(qe_identity_json)
        if isinstance(qe_identity_json, Mapping)
        else qe_identity_json
    )
    qe_status = resolve_authenticated_qe_tcb_status(raw_quote, qe_json)
    return merge_tcb_status((status, advisory_ids), qe_status)


def _issue_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def check_collateral_freshness(
    tcb_info_json: Any,
    qe_identity_json: Any,
    *,
    now: int,
    minimum_evaluation_number: int = TDX_TCB_EVALUATION_DATA_NUMBER_MIN,
) -> List[PolicyCheck]:
    """The TDX collateral freshness rule; a failure is stale input, never a verdict.

    ``now`` is Unix seconds (dcap-qvl's ``now_secs``). ``minimum_evaluation_number`` may raise
    the floor, never lower it. Returns the checks ``collateral_evaluation_number`` and
    ``collateral_age``.
    """
    if isinstance(now, bool) or not isinstance(now, int):
        raise TdxPolicyError(
            "collateral freshness requires now as integer Unix seconds"
        )
    if isinstance(minimum_evaluation_number, bool) or not isinstance(
        minimum_evaluation_number, int
    ):
        raise TdxPolicyError("the evaluation data number floor must be an integer")
    floor = max(TDX_TCB_EVALUATION_DATA_NUMBER_MIN, minimum_evaluation_number)
    current = datetime.fromtimestamp(now, timezone.utc)
    evaluation_problems: List[str] = []
    age_problems: List[str] = []
    evaluation_numbers: List[str] = []
    ages: List[str] = []
    for label, value in (
        ("TCB Info", tcb_info_json),
        ("QE Identity", qe_identity_json),
    ):
        try:
            document = _json_object(value, label)
        except TdxPolicyError:
            evaluation_problems.append(f"{label} is not a JSON object")
            age_problems.append(f"{label} is not a JSON object")
            continue
        number = document.get("tcbEvaluationDataNumber")
        if isinstance(number, bool) or not isinstance(number, int):
            evaluation_problems.append(f"{label} carries no tcbEvaluationDataNumber")
        elif number < floor:
            evaluation_problems.append(
                f"{label} tcbEvaluationDataNumber {number} < {floor}"
            )
        else:
            evaluation_numbers.append(f"{label} {number}")
        issued = _issue_time(document.get("issueDate"))
        if issued is None:
            age_problems.append(f"{label} carries no timezone-aware issueDate")
            continue
        age = (current - issued).total_seconds()
        if age < 0:
            age_problems.append(
                f"{label} issueDate {document['issueDate']} is after now"
            )
        elif age > TDX_COLLATERAL_MAX_AGE_DAYS * 86400:
            age_problems.append(
                f"{label} issued {document['issueDate']} is older than "
                f"{TDX_COLLATERAL_MAX_AGE_DAYS} days"
            )
        else:
            ages.append(f"{label} issued {document['issueDate']}")
    return [
        PolicyCheck(
            "collateral_evaluation_number",
            not evaluation_problems,
            (
                "; ".join(evaluation_problems)
                if evaluation_problems
                else f"evaluation data numbers meet floor {floor}: "
                + ", ".join(evaluation_numbers)
            ),
        ),
        PolicyCheck(
            "collateral_age",
            not age_problems,
            (
                "; ".join(age_problems)
                if age_problems
                else f"issued within {TDX_COLLATERAL_MAX_AGE_DAYS} days: "
                + ", ".join(ages)
            ),
        ),
    ]
