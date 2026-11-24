from __future__ import annotations

import hashlib
from typing import Optional, Sequence, Union


def fold(template: dict, cfv_sha384: str) -> str:
    """RTMR0 = SHA-384(before_cfv || cfv), then SHA-384(r || d) for each d in after_cfv (lower hex)."""
    register = hashlib.sha384(bytes.fromhex(template["before_cfv"]) + bytes.fromhex(cfv_sha384)).digest()
    for digest in template["after_cfv"]:
        register = hashlib.sha384(register + bytes.fromhex(digest)).digest()
    return register.hex()


def match(documents: Sequence[Optional[list]], machine_type: str, observed: dict,
          admitted_cfvs: Sequence[str], mrtd_admitted: Optional[bool] = None) -> Union[tuple, str]:
    """``(document index, entry index)`` of the first matching entry, or the refusal code.

    ``documents``: each document's entries, None for one that did not verify. ``observed``:
    lower-case ``mrtd``, ``rtmr0``..``rtmr3``. ``admitted_cfvs``: the CFVs of the admitted builds
    whose binary is indexed (what a firmware-following entry folds with). ``mrtd_admitted``: the
    MRTD is admitted (endorsed, RAM-independent, floor, not denied); an exact entry needs no binary.
    None: admitted exactly when ``admitted_cfvs`` is non-empty (the vectors' form)."""
    if mrtd_admitted is None:
        mrtd_admitted = bool(admitted_cfvs)
    if all(entries is None for entries in documents):
        return "measurements_unsigned"
    if not mrtd_admitted:
        return "firmware_refused"
    for doc_index, entries in enumerate(documents):
        if entries is None:
            continue
        for index, entry in enumerate(entries):
            if entry["machine_type"] != machine_type:
                continue
            if entry["rtmr1"] != observed["rtmr1"] or entry["rtmr2"] != observed["rtmr2"]:
                continue
            if entry["rtmr3"] is not None and entry["rtmr3"] != observed["rtmr3"]:
                continue
            if "rtmr0" in entry:
                if entry["mrtd"] == observed["mrtd"] and entry["rtmr0"] == observed["rtmr0"]:
                    return (doc_index, index)
                continue
            if any(fold(entry["rtmr0_template"], cfv) == observed["rtmr0"] for cfv in admitted_cfvs):
                return (doc_index, index)
    return "measurements_unmatched"
