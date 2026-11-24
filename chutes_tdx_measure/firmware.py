from __future__ import annotations

import datetime as dt
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from chutes_tdx_measure.vendor import owner_vm_firmware as fw

CL_SPEC_CODE_FLOOR = 919307640
SVN_CODE_FLOOR = 2
ENDORSED_AT_CODE_FLOOR = dt.datetime(2026, 5, 21, tzinfo=dt.timezone.utc)
_HEX96 = re.compile(r"[0-9a-f]{96}")


class FirmwareUnavailable(RuntimeError):
    """No verdict on the MRTD: Google's bucket did not answer or the index cannot be read."""


@dataclass(frozen=True)
class Floor:
    """The firmware floor: a ``--floor`` document or the platform's ``firmware_floor``."""

    min_cl_spec: int = CL_SPEC_CODE_FLOOR
    min_svn: int = SVN_CODE_FLOOR
    denied_builds: frozenset = frozenset()

    @classmethod
    def from_document(cls, doc: Optional[dict]) -> "Floor":
        """``{"min_cl_spec", "min_svn", "denied_builds"}`` (closed), or the code floor for None."""
        if doc is None:
            return cls()
        if not isinstance(doc, dict) or set(doc) != {"min_cl_spec", "min_svn", "denied_builds"}:
            raise ValueError("a floor is exactly {min_cl_spec, min_svn, denied_builds}")
        cl, svn, denied = doc["min_cl_spec"], doc["min_svn"], doc["denied_builds"]
        if type(cl) is not int or cl < 1 or type(svn) is not int or svn < 2:
            raise ValueError("min_cl_spec >= 1 and min_svn >= 2")
        if (not isinstance(denied, list) or len(denied) > 256 or len(set(denied)) != len(denied)
                or not all(isinstance(d, str) and _HEX96.fullmatch(d) for d in denied)):
            raise ValueError("denied_builds: at most 256 distinct lower-case HEX96")
        return cls(cl, svn, frozenset(denied))

    @classmethod
    def combine(cls, floors) -> "Floor":
        """Every floor at once (``--floor`` and the platform's): each minimum's maximum and every
        denied build; the code floor when there is none."""
        floors = list(floors)
        if not floors:
            return cls()
        return cls(max(f.min_cl_spec for f in floors), max(f.min_svn for f in floors),
                   frozenset().union(*(f.denied_builds for f in floors)))

    def admits(self, build) -> bool:
        cl_spec = getattr(build, "cl_spec", 0)
        return (
            build.uefi_sha384 not in self.denied_builds
            and type(cl_spec) is int and cl_spec > 0
            and cl_spec >= max(CL_SPEC_CODE_FLOOR, self.min_cl_spec)
            and build.svn >= max(SVN_CODE_FLOOR, self.min_svn)
            and build.endorsed_at >= ENDORSED_AT_CODE_FLOOR
        )


def default_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "chutes-tdx-measure" / "firmware"


def _private_dir(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.stat().st_mode & 0o077:
        os.chmod(directory, 0o700)


def _write(directory: Path, name: str, blob: bytes) -> None:
    target = directory / name
    tmp = directory / f".{name}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(blob)
    os.replace(tmp, target)


def fetch_mrtd(mrtd: str, directory: Path, *, now: dt.datetime, fetch: Optional[Callable] = None,
               trusted_root_der=None) -> None:
    """Fetch Google's endorsement of ``mrtd`` and its build's binary into the index (verified
    first: nothing is written for a refused or unreachable object)."""
    fetch = fetch or fw._download
    url = fw.GCE_TCB_INTEGRITY_BASE_URL + fw.gce_endorsement_object_name("tdx", mrtd)
    try:
        blob = fetch(url, fw.MAX_ENDORSEMENT_BYTES)
        verified = fw.verify_launch_endorsement(blob, now=now, trusted_root_der=trusted_root_der)
    except fw.GceEndorsementError:
        return  # Google does not endorse it: nothing to index (the MRTD stays unadmitted)
    except Exception as exc:  # noqa: BLE001 - transport: no verdict
        raise FirmwareUnavailable(f"{url}: {type(exc).__name__}: {exc}") from None
    build = fw._tdx_build(verified, None)
    if build is None or not any(value == mrtd for _, value in build.mrtds):
        return
    url = fw.GCE_TCB_INTEGRITY_BASE_URL + fw.gce_firmware_binary_object_name(verified.uefi_sha384)
    _private_dir(directory)
    _write(directory, f"{verified.uefi_sha384}.binarypb", bytes(blob))
    fetch_binary(verified.uefi_sha384, directory, fetch=fetch)


def fetch_binary(uefi_sha384: str, directory: Path, *, fetch: Optional[Callable] = None) -> None:
    """Google's binary of an indexed build (it must hash to the endorsed digest)."""
    fetch = fetch or fw._download
    url = fw.GCE_TCB_INTEGRITY_BASE_URL + fw.gce_firmware_binary_object_name(uefi_sha384)
    try:
        binary = bytes(fetch(url, fw.MAX_BINARY_BYTES))
    except Exception as exc:  # noqa: BLE001
        raise FirmwareUnavailable(f"{url}: {type(exc).__name__}: {exc}") from None
    try:
        fw.binary_cfv(binary, uefi_sha384)  # a binary that is not the endorsed build
    except fw.FirmwareRefusal as exc:
        raise FirmwareUnavailable(f"{url}: {exc.text}") from None
    _write(directory, f"{uefi_sha384}.fd", binary)


@dataclass(frozen=True)
class Admission:
    """``admitted``: some build admits the MRTD (exact entries). ``cfvs``: the CFVs of the admitted
    builds whose binary is indexed, newest first (firmware-following entries)."""

    admitted: bool
    cfvs: tuple


def admit(mrtd: str, floor: Floor, *, now: Optional[dt.datetime] = None, directory: Optional[Path] = None,
          fetch: Optional[Callable] = None, trusted_root_der=None, need_cfv: bool = True) -> Admission:
    """The MRTD's admission. An unknown MRTD is fetched once from Google's bucket; an admitted build
    without its binary gets the binary fetched when ``need_cfv`` (a firmware-following entry)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    directory = Path(directory) if directory else default_dir()
    mrtd = mrtd.lower()
    if _HEX96.fullmatch(mrtd) is None:
        return Admission(False, ())

    def index_builds():
        try:
            index = fw.load_index(directory, now=now, trusted_root_der=trusted_root_der)
        except fw.FirmwareRefusal as exc:
            raise FirmwareUnavailable(f"the firmware index: {exc.text}") from None
        return [a.build for a in index.tdx_admissions(mrtd, 0) if (0, mrtd) in a.build.mrtds]

    def only_inadmissible() -> bool:
        """Every stored endorsement that lists the MRTD lists it only RAM-specific or early-accept
        (and one does): Google has spoken, so a refetch would decide nothing new."""
        forms = []
        for path in sorted(directory.glob("*.binarypb")) if directory.is_dir() else []:
            verified = fw.verify_launch_endorsement(path.read_bytes(), now=now, trusted_root_der=trusted_root_der)
            if verified.tdx is not None:
                forms += [(m.ram_gib, m.early_accept) for m in verified.tdx.measurements if m.mrtd == mrtd]
        return bool(forms) and (0, False) not in forms

    builds = index_builds()
    if not builds and not only_inadmissible():
        fetch_mrtd(mrtd, directory, now=now, fetch=fetch, trusted_root_der=trusted_root_der)
        builds = index_builds()
    admitted = sorted((b for b in builds if floor.admits(b)), key=lambda b: b.endorsed_at, reverse=True)
    if need_cfv and admitted and all(b.cfv_sha384 is None for b in admitted):
        for build in admitted:
            fetch_binary(build.uefi_sha384, directory, fetch=fetch)
        admitted = sorted((b for b in index_builds() if floor.admits(b)), key=lambda b: b.endorsed_at, reverse=True)
    return Admission(bool(admitted), tuple(b.cfv_sha384 for b in admitted if b.cfv_sha384 is not None))


def admitted_cfvs(mrtd: str, floor: Floor, **kwargs) -> list:
    """The CFVs of the admitted builds with their binary (the vectors' ``admitted_build_cfvs``)."""
    return list(admit(mrtd, floor, **kwargs).cfvs)
