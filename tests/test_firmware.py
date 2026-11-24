"""The MRTD admission end to end with a test PKI: endorsement verified, RAM-independent entries
only, the binary's CFV, the floor (cl_spec, SVN, golden timestamp, denied builds), the fetch."""

import datetime as dt
import hashlib
import os

import pytest

from chutes_tdx_measure import firmware
from chutes_tdx_measure.vendor import owner_vm_firmware as fw
from gce_testkit import gce_pki, synthetic_tdvf, tdx_endorsement

NOW = dt.datetime(2026, 11, 16, tzinfo=dt.timezone.utc)
JUNE = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
MRTD = "ab" * 48


def install(directory, blob, binary, uefi, with_binary=True):
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / f"{uefi}.binarypb").write_bytes(blob)
    os.chmod(directory / f"{uefi}.binarypb", 0o600)
    if with_binary:
        (directory / f"{uefi}.fd").write_bytes(binary)
        os.chmod(directory / f"{uefi}.fd", 0o600)


def cfvs(directory, floor=firmware.Floor(), fetch=None, mrtd=MRTD):
    return firmware.admitted_cfvs(mrtd, floor, now=NOW, directory=directory, trusted_root_der=gce_pki()["root_der"],
                                  fetch=fetch or (lambda url, limit: (_ for _ in ()).throw(OSError("offline"))))


def test_admitted_build_and_its_cfv(tmp_path):
    cfv = os.urandom(0x2000)
    blob, binary, uefi = tdx_endorsement([(0, False, MRTD)], endorsed_at=JUNE, binary=synthetic_tdvf(cfv))
    install(tmp_path / "fw", blob, binary, uefi)
    assert cfvs(tmp_path / "fw") == [hashlib.sha384(cfv).hexdigest()]


@pytest.mark.parametrize("why,kwargs,floor", [
    ("below the changelist floor", {"cl_spec": 900000000}, firmware.Floor()),
    ("below the code changelist floor, whatever the signed floor", {"cl_spec": 900000000}, firmware.Floor(min_cl_spec=1)),
    ("below the code SVN floor, whatever the signed floor", {"svn": 1}, firmware.Floor(min_svn=0)),
    ("below the signed changelist floor", {"cl_spec": 957008434}, firmware.Floor(min_cl_spec=957008435)),
    ("below the SVN floor", {"svn": 1}, firmware.Floor()),
    ("below the signed SVN floor", {"svn": 2}, firmware.Floor(min_svn=3)),
    ("endorsed before 2026-05-21", {"endorsed_at": dt.datetime(2026, 5, 20, tzinfo=dt.timezone.utc)}, firmware.Floor()),
])
def test_floor_refusals(tmp_path, why, kwargs, floor):
    kw = {"endorsed_at": JUNE, **kwargs}
    blob, binary, uefi = tdx_endorsement([(0, False, MRTD)], **kw)
    install(tmp_path / "fw", blob, binary, uefi)
    assert cfvs(tmp_path / "fw", floor) == [], why


def test_denied_build(tmp_path):
    blob, binary, uefi = tdx_endorsement([(0, False, MRTD)], endorsed_at=JUNE)
    install(tmp_path / "fw", blob, binary, uefi)
    assert cfvs(tmp_path / "fw", firmware.Floor(denied_builds=frozenset({uefi}))) == []


def test_ram_specific_and_early_accept_entries_are_not_admitted(tmp_path):
    blob, binary, uefi = tdx_endorsement([(16, False, MRTD), (0, True, MRTD)], endorsed_at=JUNE)
    install(tmp_path / "fw", blob, binary, uefi)
    assert cfvs(tmp_path / "fw") == []


def test_build_without_its_binary(tmp_path):
    """An exact entry's MRTD is admitted on the endorsement alone; a firmware-following entry
    needs the binary's CFV, fetched (here Google's bucket is unreachable: no verdict)."""
    blob, binary, uefi = tdx_endorsement([(0, False, MRTD)], endorsed_at=JUNE)
    install(tmp_path / "fw", blob, binary, uefi, with_binary=False)
    root = gce_pki()["root_der"]
    offline = lambda url, limit: (_ for _ in ()).throw(OSError("offline"))  # noqa: E731
    exact = firmware.admit(MRTD, firmware.Floor(), now=NOW, directory=tmp_path / "fw", trusted_root_der=root,
                           fetch=offline, need_cfv=False)
    assert exact.admitted and exact.cfvs == ()
    with pytest.raises(firmware.FirmwareUnavailable):
        firmware.admit(MRTD, firmware.Floor(), now=NOW, directory=tmp_path / "fw", trusted_root_der=root,
                       fetch=offline, need_cfv=True)
    served = {fw.GCE_TCB_INTEGRITY_BASE_URL + fw.gce_firmware_binary_object_name(uefi): binary}
    follow = firmware.admit(MRTD, firmware.Floor(), now=NOW, directory=tmp_path / "fw", trusted_root_der=root,
                            fetch=lambda url, limit: served[url], need_cfv=True)
    assert follow.admitted and len(follow.cfvs) == 1


def test_fetch_from_googles_bucket(tmp_path):
    blob, binary, uefi = tdx_endorsement([(0, False, MRTD)], endorsed_at=JUNE)
    served = {fw.GCE_TCB_INTEGRITY_BASE_URL + fw.gce_endorsement_object_name("tdx", MRTD): blob,
              fw.GCE_TCB_INTEGRITY_BASE_URL + fw.gce_firmware_binary_object_name(uefi): binary}
    asked = []

    def fetch(url, limit):
        asked.append(url)
        return served[url]
    assert len(cfvs(tmp_path / "fw", fetch=fetch)) == 1 and len(asked) == 2
    assert (tmp_path / "fw").stat().st_mode & 0o077 == 0
    asked.clear()
    assert len(cfvs(tmp_path / "fw", fetch=fetch)) == 1 and asked == []  # indexed now


def test_fetch_refuses_a_binary_that_is_not_the_endorsed_build(tmp_path):
    blob, binary, uefi = tdx_endorsement([(0, False, MRTD)], endorsed_at=JUNE)
    served = {fw.GCE_TCB_INTEGRITY_BASE_URL + fw.gce_endorsement_object_name("tdx", MRTD): blob,
              fw.GCE_TCB_INTEGRITY_BASE_URL + fw.gce_firmware_binary_object_name(uefi): synthetic_tdvf(b"\x01" * 0x2000)}
    with pytest.raises(firmware.FirmwareUnavailable):
        cfvs(tmp_path / "fw", fetch=lambda url, limit: served[url])
    assert not list((tmp_path / "fw").glob("*.fd"))  # the endorsement verified; the wrong binary is never kept


def test_an_endorsement_under_another_root_is_not_admitted(tmp_path):
    blob, binary, uefi = tdx_endorsement([(0, False, MRTD)], endorsed_at=JUNE)
    install(tmp_path / "fw", blob, binary, uefi)
    with pytest.raises(firmware.FirmwareUnavailable):
        firmware.admitted_cfvs(MRTD, firmware.Floor(), now=NOW, directory=tmp_path / "fw")  # Google's real root


def test_floor_document():
    assert firmware.Floor.from_document({"min_cl_spec": 957008435, "min_svn": 2, "denied_builds": []}).min_cl_spec == 957008435
    for bad in ({"min_cl_spec": 1, "min_svn": 1, "denied_builds": []}, {"min_cl_spec": 1, "min_svn": 2},
                {"min_cl_spec": 1, "min_svn": 2, "denied_builds": ["AB" * 48]}):
        with pytest.raises(ValueError):
            firmware.Floor.from_document(bad)


def test_floors_combine():
    a = firmware.Floor(957008435, 3, frozenset({"aa" * 48}))
    b = firmware.Floor(957008436, 2, frozenset({"bb" * 48}))
    c = firmware.Floor.combine([a, b])
    assert (c.min_cl_spec, c.min_svn, c.denied_builds) == (957008436, 3, frozenset({"aa" * 48, "bb" * 48}))
    assert firmware.Floor.combine([]) == firmware.Floor()
