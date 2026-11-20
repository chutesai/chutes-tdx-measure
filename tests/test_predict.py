"""predict on a synthetic disk: a GPT, a FAT16 ESP holding EFI/BOOT/BOOTX64.EFI (a PE with a .linux PE,
.cmdline and .sdmagic), in raw form and in GCE's archive form (GNU tar --format=oldgnu -S)."""

import hashlib
import shutil
import struct
import subprocess
import uuid
import zlib

import pytest

from chutes_tdx_measure import predict
from chutes_tdx_measure.vendor import gcp_prediction as gp

ESP = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")


def make_pe(sections: dict, vsizes: dict = None) -> bytes:
    """A minimal PE32+ image with the given sections (raw data 0x200-aligned; VirtualSize the data's
    size unless ``vsizes`` names another)."""
    n = len(sections)
    headers = 0x400
    out = bytearray(headers)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x40)
    out[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", out, 0x44, 0x8664, n, 0, 0, 0, 240, 0x22)
    opt = 0x58
    struct.pack_into("<H", out, opt, 0x20B)
    struct.pack_into("<I", out, opt + 60, headers)       # SizeOfHeaders
    struct.pack_into("<I", out, opt + 64, 0x12345678)    # CheckSum (excluded from Authenticode)
    struct.pack_into("<I", out, opt + 108, 16)           # NumberOfRvaAndSizes
    table = opt + 240
    raw = headers
    for i, (name, data) in enumerate(sections.items()):
        entry = table + 40 * i
        out[entry:entry + 8] = name.encode().ljust(8, b"\0")
        size = len(data)
        padded = -(-size // 0x200) * 0x200
        struct.pack_into("<IIII", out, entry + 8, (vsizes or {}).get(name, size), 0x1000 * (i + 1), padded, raw)
        raw += padded
    out = bytearray(out[:headers]) + b"".join(d.ljust(-(-len(d) // 0x200) * 0x200, b"\0") for d in sections.values())
    return bytes(out)


def make_fat16(files: dict, total_sectors=32768) -> bytes:
    """A FAT16 image (512-byte sectors, 4 per cluster) holding ``{"EFI/BOOT/BOOTX64.EFI": bytes}``."""
    spc, reserved, fats, root_entries = 4, 1, 2, 512
    fat_sectors = 32
    root_sectors = root_entries * 32 // 512
    img = bytearray(total_sectors * 512)
    struct.pack_into("<HBHBHHBH", img, 11, 512, spc, reserved, fats, root_entries, total_sectors, 0xF8, fat_sectors)
    img[510:512] = b"\x55\xaa"
    fat = [0xFFF8, 0xFFFF]
    data_start = (reserved + fats * fat_sectors + root_sectors) * 512
    cluster_size = spc * 512

    def alloc(data: bytes) -> int:
        count = max(1, -(-len(data) // cluster_size))
        first = len(fat)
        for i in range(count):
            fat.append(first + i + 1 if i < count - 1 else 0xFFFF)
            start = data_start + (first + i - 2) * cluster_size
            chunk = data[i * cluster_size:(i + 1) * cluster_size]
            img[start:start + len(chunk)] = chunk
        return first

    def entry(name83: bytes, attr: int, cluster: int, size: int) -> bytes:
        e = bytearray(32)
        e[0:11] = name83
        e[11] = attr
        struct.pack_into("<H", e, 26, cluster & 0xFFFF)
        struct.pack_into("<H", e, 20, cluster >> 16)
        struct.pack_into("<I", e, 28, size)
        return bytes(e)

    path, data = next(iter(files.items()))
    efi, boot, name = path.split("/")
    base, ext = name.split(".")
    file_cluster = alloc(data)
    boot_dir = entry(base.ljust(8).encode() + ext.ljust(3).encode(), 0x20, file_cluster, len(data))
    boot_cluster = alloc(boot_dir)
    efi_dir = entry(b"BOOT       ", 0x10, boot_cluster, 0)
    efi_cluster = alloc(efi_dir)
    root = (reserved + fats * fat_sectors) * 512
    img[root:root + 32] = entry(b"EFI        ", 0x10, efi_cluster, 0)
    fat_bytes = b"".join(struct.pack("<H", v) for v in fat)
    for i in range(fats):
        off = (reserved + i * fat_sectors) * 512
        img[off:off + len(fat_bytes)] = fat_bytes
    return bytes(img)


def make_disk(esp: bytes, total=64 * 1024 * 1024) -> bytes:
    disk = bytearray(total)
    disk[510:512] = b"\x55\xaa"
    first = 2048
    last = first + len(esp) // 512 - 1
    entry = bytearray(128)
    entry[0:16] = ESP.bytes_le
    entry[16:32] = uuid.UUID("11111111-2222-4333-8444-555555555555").bytes_le
    struct.pack_into("<QQ", entry, 32, first, last)
    entries = bytes(entry) + bytes(127 * 128)
    header = bytearray(92)
    header[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", header, 8, 0x10000, 92, 0, 0, 1, total // 512 - 1, 34, total // 512 - 34)
    header[56:72] = uuid.UUID("99999999-2222-4333-8444-555555555555").bytes_le
    struct.pack_into("<QIII", header, 72, 2, 128, 128, zlib.crc32(entries))
    struct.pack_into("<I", header, 16, zlib.crc32(bytes(header)))
    disk[512:512 + 92] = header
    disk[1024:1024 + len(entries)] = entries
    disk[first * 512:first * 512 + len(esp)] = esp
    return bytes(disk)


KERNEL = make_pe({".text": b"\x90" * 3000, ".data": b"kernel data"})
UKI = make_pe({".text": b"stub" * 100, ".sdmagic": b"#### LoaderInfo: systemd-stub 255.4-1ubuntu8 ####\0",
               ".osrel": b"ID=ubuntu\n", ".cmdline": b"roothash=" + b"ab" * 32 + b" console=ttyS0\0",
               ".linux": KERNEL, ".initrd": b"initrd" * 50})


def expected_rtmr1(disk: bytes, with_kernel=True) -> str:
    digests = [hashlib.sha384(gp.CALLING_EFI_APPLICATION).digest(), hashlib.sha384(bytes(4)).digest(),
               hashlib.sha384(gp.gpt_event_data(disk[:34 * 512])).digest(), gp.authenticode_hash(UKI, "sha384")]
    if with_kernel:
        digests.append(gp.authenticode_hash(KERNEL, "sha384"))
    digests += [hashlib.sha384(gp.EXIT_BOOT_SERVICES_INVOCATION).digest(), hashlib.sha384(gp.EXIT_BOOT_SERVICES_SUCCESS).digest()]
    register = bytes(48)
    for d in digests:
        register = hashlib.sha384(register + d).digest()
    return register.hex()


PLATFORM = {"schema": "chutes.cvm-platform-data.v1", "captured_at": "2026-11-16T00:00:00Z", "source": "test",
            "settings": {"secure_boot": False, "vtpm": True, "integrity_monitoring": True, "disks": 1},
            "machine_types": {"c3-standard-4": {"rtmr0_template": {"before_cfv": "aa" * 48, "after_cfv": ["bb" * 48]},
                                                "captures": [{"uefi_sha384": "cc" * 48, "mrtd": "dd" * 48,
                                                              "cfv_sha384": "ee" * 48, "rtmr0": "ff" * 48}]}}}


@pytest.fixture
def disk(tmp_path):
    raw = make_disk(make_fat16({"EFI/BOOT/BOOTX64.EFI": UKI}))
    path = tmp_path / "disk.raw"
    path.write_bytes(raw)
    return path, raw


def test_predict_raw_disk(disk):
    path, raw = disk
    out = predict.predict_uki(str(path), "c3-standard-4", PLATFORM)
    assert out["rtmr1"]["value"] == expected_rtmr1(raw)
    assert out["rtmr1_alternatives"][0]["value"] == expected_rtmr1(raw, with_kernel=False)
    assert out["rtmr2"]["value"] == "0" * 96
    assert out["uki"]["systemd_stub"] == "255.4-1ubuntu8"
    assert out["uki"]["cmdline"].startswith("roothash=abab")
    assert [e["mrtd"] for e in out["entries"]] == ["dd" * 48, "gce-endorsed"]
    assert out["entries"][0]["rtmr0"] == "ff" * 48 and out["entries"][1]["rtmr0_template"]["before_cfv"] == "aa" * 48
    assert all(e["rtmr1"] == out["rtmr1"]["value"] and e["rtmr3"] is None for e in out["entries"])


# A prediction is what gets signed; a capture only confirms it.
def test_predict_does_not_call_a_capture_authoritative(disk):
    path, *_ = disk
    confirm = predict.predict_uki(str(path), "c3-standard-4", PLATFORM)["confirm"]
    assert "authoritative" not in confirm
    assert "sign only values this prediction gives, never a capture's that it does not" in confirm


@pytest.mark.skipif(shutil.which("tar") is None, reason="GNU tar is needed to make an oldgnu sparse archive")
def test_predict_gce_archive(disk, tmp_path):
    path, raw = disk
    archive = tmp_path / "disk.tar.gz"
    subprocess.run(["tar", "--format=oldgnu", "-Sczf", str(archive), "-C", str(path.parent), "disk.raw"], check=True)
    out = predict.predict_uki(str(archive), "c3-standard-4", None)
    assert out["rtmr1"]["value"] == expected_rtmr1(raw)
    assert out["image_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert out["entries"] == []


def test_predict_refuses_a_disk_without_the_uki(tmp_path):
    raw = make_disk(make_fat16({"EFI/BOOT/OTHERX64.EFI": UKI}))
    (tmp_path / "d.raw").write_bytes(raw)
    with pytest.raises(predict.PredictionError, match="BOOTX64"):
        predict.predict_uki(str(tmp_path / "d.raw"), "c3-standard-4")


def uki_257(vsizes=None):
    return make_pe({".text": b"stub" * 100, ".sdmagic": b"#### LoaderInfo: systemd-stub 257.13-1~deb13u1 ####\0",
                    ".osrel": b"ID=ubuntu\n", ".cmdline": b"roothash=" + b"ab" * 32 + b" console=ttyS0\0",
                    ".linux": KERNEL, ".initrd": b"initrd" * 50, ".sbat": b"sbat,1\n", ".pcrsig": b"{}"}, vsizes)


def fold(pairs) -> str:
    """RTMR2 from (name, content as loaded) pairs, written out here: SHA-384 of the name with its
    NUL, then of the content, each extended into a zero register."""
    register = bytes(48)
    for name, content in pairs:
        for digest in (hashlib.sha384(name + b"\0").digest(), hashlib.sha384(content).digest()):
            register = hashlib.sha384(register + digest).digest()
    return register.hex()


# systemd-stub 257 measures the UKI's sections into RTMR2, in its own order (.linux .osrel .cmdline
# .initrd ... .uname .sbat, never .pcrsig), each as loaded: its VirtualSize, zero-padded.
def test_predict_stub_257(tmp_path):
    uki = uki_257(vsizes={".osrel": 0x400})
    path = tmp_path / "d.raw"
    path.write_bytes(make_disk(make_fat16({"EFI/BOOT/BOOTX64.EFI": uki})))
    out = predict.predict_uki(str(path), "c3-standard-4", PLATFORM)
    want = fold([(b".linux", KERNEL), (b".osrel", b"ID=ubuntu\n".ljust(0x400, b"\0")),
                 (b".cmdline", b"roothash=" + b"ab" * 32 + b" console=ttyS0\0"), (b".initrd", b"initrd" * 50),
                 (b".sbat", b"sbat,1\n")])
    assert out["uki"]["systemd_stub"] == "257.13-1~deb13u1"
    assert out["rtmr2"]["value"] == want and "257" in out["rtmr2"]["model"]
    # The all-zero alternative is marked not signable.
    assert out["rtmr2_alternatives"] == [{"model": predict.NOT_SIGNABLE_ZERO, "signable": False, "value": "0" * 96}]
    assert predict.NOT_SIGNABLE_ZERO.startswith("not safe to sign with this template")
    assert all(e["rtmr2"] == want for e in out["entries"])
    registers = {m["register"] for m in out["measured_inputs"]}
    assert registers == {"MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"}
    unmeasured = " ".join(m["input"] + " " + m["handling"] for m in out["not_measured"])
    for word in ("SMBIOS", "efi=noruntime", "systemd.import_credentials=no", "random.trust_bootloader=off", "sysext"):
        assert word in unmeasured


# A stub version with no model (256) is refused rather than guessed.
def test_predict_refuses_an_unmodelled_stub(tmp_path):
    uki = make_pe({".sdmagic": b"#### LoaderInfo: systemd-stub 256.7 ####\0", ".cmdline": b"x\0", ".linux": KERNEL})
    path = tmp_path / "d.raw"
    path.write_bytes(make_disk(make_fat16({"EFI/BOOT/BOOTX64.EFI": uki})))
    with pytest.raises(predict.PredictionError, match="256"):
        predict.predict_uki(str(path), "c3-standard-4")
