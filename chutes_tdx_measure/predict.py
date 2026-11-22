"""``predict``: an image's TDX measurements on a GCE c3 machine, from its archive.

For the image template's layout (a unified kernel image booted directly as \\EFI\\BOOT\\BOOTX64.EFI,
no shim or GRUB, Secure Boot off), using the GCP TDX model of sek8s (vendored ``gcp_prediction``,
validated against GCP captures) and systemd-stub's source:

- **RTMR1**: the calling action, a separator, the GPT event (the disk's primary GPT header and its
  used entries), the UKI's Authenticode digest, then the two exit-boot-services actions. Whether the
  embedded kernel's Authenticode digest sits between them depends on the stub (its ``.sdmagic``):
  systemd-stub 257 and earlier hand the kernel to the firmware's LoadImage, which measures every PE
  it loads; 258 and later, with Secure Boot off (the template's setting), map the kernel themselves,
  so the firmware measures no kernel event (systemd ``src/boot/linux.c``, ``linux_exec``; the kernel
  is still in the UKI's Authenticode and in the stub's ``.linux`` event in RTMR2). The other form is
  listed as the alternative.
- **RTMR2** depends on the UKI's stub (its ``.sdmagic``):
  - systemd-stub 257 or later measures every section it uses (``.linux .osrel .cmdline .initrd
    .ucode .splash .dtb .uname .sbat .pcrpkey .profile .dtbauto .hwids`` in that order, when
    present; never ``.pcrsig``) into the CC registers as well as the vTPM: per section, SHA-384 of
    its name with the NUL, then of its content as loaded (its VirtualSize, zero-padded). PCR 11 is
    RTMR2: GCE's TDVF offers the CC measurement protocol, and the stub measures through it. That is
    the primary model. The all-zero register is listed as an alternative marked not signable, so a
    VM whose RTMR2 lacks the stub's events is refused. Anything the stub adds beyond the UKI (a
    command line from the boot entry or an addon, credential, sysext or confext files from the
    ESP) adds events.
  - systemd-stub 255 (Ubuntu 24.04's) measures into the vTPM only: RTMR2 is all zero.
  - The Linux EFI stub measures the initrd and its command line through TCG2 when a TPM is
    present (GCE's vTPM), so never into RTMR2 there.
  Other stub versions have no model and are refused.
- **MRTD and RTMR0** come from Chutes' platform data for the machine type: the exact form uses the
  newest capture, the firmware-following form the RTMR0 template.

Other layouts (shim and GRUB): ``predict --inputs`` with a ``chutes.gcp-prediction-inputs.v1``
manifest, through the vendored model's own TDX events.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import tarfile

from chutes_tdx_measure.vendor import gcp_prediction as gp

ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
ZERO = "0" * 96
# systemd-stub's section measurement order (its UnifiedSection enum, src/fundamental/uki.h of 257;
# .pcrsig is never measured).
STUB_SECTIONS = (".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat",
                 ".pcrpkey", ".profile", ".dtbauto", ".hwids")
# The first systemd-stub release whose source measures into the CC registers too (measure.c:
# tpm_log_ipl_event calls cc_log_event first); 255 measures into the TPM only.
STUB_CC_MEASURED = 257
# The first systemd-stub release that, with Secure Boot off, maps the UKI's kernel itself instead of
# handing it to the firmware's LoadImage (src/boot/linux.c, linux_exec): RTMR1 has no kernel event.
STUB_MAPS_KERNEL = 258

# The label of the all-zero RTMR2 alternative under a 257 stub. A VM that shows it booted where the
# firmware offered the stub no CC measurement protocol, so nothing the stub adds (a boot entry's or
# an addon's command line, sidecars) reached any TDX register: never sign it for this template.
NOT_SIGNABLE_ZERO = ("not safe to sign with this template: the stub's own measurements are missing "
                     "(no CC measurement protocol offered to the stub)")

# What each register covers, for the template's layout (a UKI, systemd-stub 257 or later).
MEASURED_INPUTS = [
    {"register": "MRTD", "covers": "the TD's firmware (GCE's TDVF build)"},
    {"register": "RTMR0", "covers": "the firmware's configuration and data: the TD HOB, the ACPI tables, the Secure "
     "Boot variables, BootOrder and the Boot#### it lists (such an entry with options changes it; an entry "
     "outside BootOrder, selected by BootNext, is not here)"},
    {"register": "RTMR1", "covers": "the GPT header and entries; the UKI's Authenticode (so the stub, the kernel, "
     "the initrd, the command line, os-release, uname and sbat); the kernel's Authenticode when the stub hands the "
     "kernel to the firmware's LoadImage (systemd-stub 257 and earlier; 258 and later map it themselves with Secure "
     "Boot off); and every other PE loaded through the firmware's LoadImage, which measures each one: an ESP addon "
     "of any kind, including one carrying only an initrd or microcode (whose payloads the stub measures into the "
     "vTPM only)"},
    {"register": "RTMR2", "covers": "each UKI section the stub uses, name and content; any command line the stub "
     "takes from the boot entry (BootNext included: the only TDX evidence of such an entry) or an addon; any "
     "credential, sysext or confext file it packs from the ESP, through the CC measurement protocol of GCE's "
     "TDVF. An all-zero RTMR2 is never signable for this layout"},
    {"register": "RTMR3", "covers": "nothing (no event)"},
]

# Every boot input no register covers, and what the template does about it.
NOT_MEASURED = [
    {"input": "SMBIOS type 11 strings (io.systemd.stub.kernel-cmdline-extra, io.systemd.credential:*)",
     "handling": "ignored in a confidential VM by systemd-stub 257 (stub.c, cmdline_append_and_measure_smbios) "
                 "and by PID 1 (import-creds.c); credential import is off (systemd.import_credentials=no)"},
    {"input": "EFI variables (SystemdOptions, LoaderDevicePartUUID and the rest; host-writable with Secure Boot off)",
     "handling": "efi=noruntime: Linux reads no EFI variable; systemd.gpt_auto=no and root=/dev/mapper/root: no "
                 "partition is found from them"},
    {"input": "fw_cfg and command-line credentials", "handling": "systemd.import_credentials=no"},
    {"input": "the ESP's random seed (\\loader\\random-seed) and LoaderSystemToken",
     "handling": "mixed into the kernel's pool, never credited (random.trust_bootloader=off); the CPU's RDRAND is "
                 "mixed in as well"},
    {"input": "system and configuration extensions (sysext, confext) from /.extra or the root",
     "handling": "the units are masked in the initrd and the root (and the ESP files are measured into RTMR2 first)"},
    {"input": "the root and app partitions' content", "handling": "dm-verity; both root hashes are on the measured "
                 "command line (roothash=, chutes.app_roothash=)"},
    {"input": "other attached disks", "handling": "nothing mounts them: no partition discovery, fstab has tmpfs only"},
    {"input": "the kernel's own measurements (initrd, command line into PCR 9)",
     "handling": "vTPM only on GCE (TCG2 present); what they cover is already in RTMR1 and RTMR2"},
]


class PredictionError(ValueError):
    pass


# --- the archive and the disk --------------------------------------------------------------------

class Disk:
    """Random reads of disk.raw, from a raw file or from GCE's archive (gzip'd oldgnu sparse tar
    with one member disk.raw). An archive is read forward only: ``read`` regions in order."""

    def __init__(self, path: str):
        self.sha256 = None
        if path.endswith((".tar.gz", ".tgz")):
            with open(path, "rb") as stream:
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            self.sha256 = digest.hexdigest()
            self._tar = tarfile.open(path, "r:gz")
            members = self._tar.getmembers()
            if len(members) != 1 or members[0].name != "disk.raw":
                raise PredictionError("the archive must hold exactly one member, disk.raw")
            self.size = members[0].size
            self._file = self._tar.extractfile(members[0])
        else:
            self._tar = None
            self._file = open(path, "rb")
            self.size = self._file.seek(0, io.SEEK_END)
        self._pos = 0

    def read(self, offset: int, length: int) -> bytes:
        if offset < self._pos and self._tar is not None:
            raise PredictionError("archive regions must be read in order")
        self._file.seek(offset)
        data = self._file.read(length)
        self._pos = offset + len(data)
        if len(data) != length:
            raise PredictionError("the disk is shorter than its partition table says")
        return data


# --- FAT (the ESP) -------------------------------------------------------------------------------

class Fat:
    """A minimal reader of the ESP's FAT12/16/32 file system, enough to read one file by its 8.3
    path. ``image`` holds the whole partition."""

    def __init__(self, image: bytes):
        self.image = image
        bps, spc, reserved, fats, root_entries, total16, _media, fat16 = struct.unpack_from("<HBHBHHBH", image, 11)
        total32, fat32 = struct.unpack_from("<I", image, 32)[0], struct.unpack_from("<I", image, 36)[0]
        if bps not in (512, 1024, 2048, 4096) or spc == 0 or fats == 0:
            raise PredictionError("the ESP is not a FAT file system")
        self.bps, self.spc = bps, spc
        fat_size = fat16 or fat32
        total = total16 or total32
        root_sectors = (root_entries * 32 + bps - 1) // bps
        self.fat_offset = reserved * bps
        self.root_offset = (reserved + fats * fat_size) * bps
        self.data_offset = self.root_offset + root_sectors * bps
        clusters = (total - (reserved + fats * fat_size + root_sectors)) // spc
        # FAT32 when the 16-bit FAT size is zero (as Linux decides: mkfs.fat makes FAT32 ESPs with
        # fewer clusters than the specification's threshold), else FAT12/16 by cluster count.
        self.kind = 32 if fat16 == 0 else 12 if clusters < 4085 else 16
        self.root_entries = root_entries
        self.root_cluster = struct.unpack_from("<I", image, 44)[0] if self.kind == 32 else None

    def _next(self, cluster: int) -> int:
        if self.kind == 32:
            return struct.unpack_from("<I", self.image, self.fat_offset + 4 * cluster)[0] & 0x0FFFFFFF
        if self.kind == 16:
            return struct.unpack_from("<H", self.image, self.fat_offset + 2 * cluster)[0]
        raw = struct.unpack_from("<H", self.image, self.fat_offset + cluster * 3 // 2)[0]
        return raw >> 4 if cluster & 1 else raw & 0xFFF

    def _end(self, cluster: int) -> bool:
        return cluster >= {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.kind] or cluster < 2

    def _chain(self, cluster: int) -> bytes:
        size = self.bps * self.spc
        out, seen = [], set()
        while not self._end(cluster):
            if cluster in seen:
                raise PredictionError("a FAT cluster chain loops")
            seen.add(cluster)
            start = self.data_offset + (cluster - 2) * size
            out.append(self.image[start:start + size])
            cluster = self._next(cluster)
        return b"".join(out)

    def _entries(self, data: bytes):
        for offset in range(0, len(data), 32):
            entry = data[offset:offset + 32]
            if entry[0] == 0:
                return
            if entry[0] == 0xE5 or entry[11] == 0x0F or entry[11] & 0x08:
                continue
            name = entry[:11].decode("ascii", "replace")
            cluster = struct.unpack_from("<H", entry, 26)[0] | (struct.unpack_from("<H", entry, 20)[0] << 16)
            yield name, entry[11], cluster, struct.unpack_from("<I", entry, 28)[0]

    def read(self, path: str) -> bytes:
        """``path`` like ``EFI/BOOT/BOOTX64.EFI`` (8.3 names, matched case-insensitively)."""
        if self.kind == 32:
            data = self._chain(self.root_cluster)
        else:
            data = self.image[self.root_offset:self.root_offset + 32 * self.root_entries]
        parts = path.upper().split("/")
        for depth, part in enumerate(parts):
            base, _, ext = part.partition(".")
            want = base.ljust(8) + ext.ljust(3)
            for name, attrs, cluster, size in self._entries(data):
                if name == want:
                    if depth == len(parts) - 1:
                        return self._chain(cluster)[:size]
                    if not attrs & 0x10:
                        raise PredictionError(f"{part} is not a directory")
                    data = self._chain(cluster)
                    break
            else:
                raise PredictionError(f"{path}: {part} not found in the ESP")
        raise PredictionError(f"{path} not found")


# --- the UKI -------------------------------------------------------------------------------------

def section(pe: bytes, name: str) -> bytes:
    """A section's content as loaded: VirtualSize bytes, zero-padded past its raw data."""
    sections = gp.pe_sections(pe)
    if name not in sections:
        raise PredictionError(f"the UKI has no {name} section")
    _va, vsize, raw_pointer, raw_size = sections[name]
    data = pe[raw_pointer:raw_pointer + min(vsize, raw_size)]
    return data + bytes(vsize - len(data))


def stub_version(uki: bytes) -> str:
    try:
        text = section(uki, ".sdmagic").decode("ascii", "replace")
    except PredictionError:
        return "unknown"
    m = re.search(r"systemd-stub ([^ #]+)", text)
    return m.group(1) if m else text.strip("# \0")


def stub_major(version: str) -> int:
    m = re.match(r"(\d+)", version)
    if not m:
        raise PredictionError(f"the UKI's systemd-stub version is unknown ({version!r})")
    return int(m.group(1))


def stub_events(uki: bytes) -> list:
    """systemd-stub's RTMR2 digests for the UKI's sections (257 and later): name, then content."""
    if ".profile" in gp.pe_sections(uki):
        raise PredictionError("a UKI with profiles has no model here")
    events = []
    for name in STUB_SECTIONS:
        try:
            content = section(uki, name)
        except PredictionError:
            continue
        events += [hashlib.sha384(name.encode() + b"\0").digest(), hashlib.sha384(content).digest()]
    return events


def _replay(digests) -> str:
    register = bytes(48)
    for digest in digests:
        register = hashlib.sha384(register + digest).digest()
    return register.hex()


def rtmr1_events(gpt_event: bytes, uki_authenticode: bytes, kernel_authenticode) -> list:
    events = [
        gp.ModelEvent(4, gp.EV_EFI_ACTION, gp.CALLING_EFI_APPLICATION.decode(), gp.CALLING_EFI_APPLICATION),
        gp.ModelEvent(4, gp.EV_SEPARATOR, "separator", gp.SEPARATOR),
        gp.ModelEvent(5, gp.EV_EFI_GPT_EVENT, "GPT", gpt_event),
        gp.boot_application("EFI/BOOT/BOOTX64.EFI (the UKI)", {"sha384": uki_authenticode.hex()}),
    ]
    if kernel_authenticode is not None:
        events.append(gp.boot_application("the UKI's .linux (LoadImage by systemd-stub)", {"sha384": kernel_authenticode.hex()}))
    events += [
        gp.ModelEvent(5, gp.EV_EFI_ACTION, gp.EXIT_BOOT_SERVICES_INVOCATION.decode(), gp.EXIT_BOOT_SERVICES_INVOCATION),
        gp.ModelEvent(5, gp.EV_EFI_ACTION, gp.EXIT_BOOT_SERVICES_SUCCESS.decode(), gp.EXIT_BOOT_SERVICES_SUCCESS),
    ]
    return events


def _event_records(events) -> list:
    return [{"type": e.event_type, "what": e.what, "sha384": e.digest("sha384").hex()} for e in events]


def predict_uki(disk_path: str, machine_type: str, platform_data: dict = None) -> dict:
    disk = Disk(disk_path)
    sectors = disk.read(0, 34 * 512)
    gpt_event = gp.gpt_event_data(sectors)
    esp = [p for p in gp.gpt_partitions(sectors) if p["type"] == ESP_TYPE]
    if len(esp) != 1:
        raise PredictionError("the disk needs exactly one ESP")
    image = disk.read(esp[0]["first_lba"] * 512, esp[0]["size_lba"] * 512)
    uki = Fat(image).read("EFI/BOOT/BOOTX64.EFI")
    del image
    uki_authenticode = gp.authenticode_hash(uki, "sha384")
    kernel = section(uki, ".linux")
    kernel_authenticode = gp.authenticode_hash(kernel, "sha384")
    cmdline = section(uki, ".cmdline").rstrip(b"\0").decode("utf-8", "replace")

    with_kernel = rtmr1_events(gpt_event, uki_authenticode, kernel_authenticode)
    without_kernel = rtmr1_events(gpt_event, uki_authenticode, None)
    version = stub_version(uki)
    major = stub_major(version)
    if major >= STUB_MAPS_KERNEL:
        primary, alternative = without_kernel, with_kernel
        rtmr1_model = (f"the UKI; systemd-stub {version} maps its kernel itself with Secure Boot off (no kernel "
                       "LoadImage event), GCE TDX")
        alternative_model = "the UKI and its kernel (LoadImage: the stub with Secure Boot on and shim)"
    else:
        primary, alternative = with_kernel, without_kernel
        rtmr1_model = "UKI and its kernel (LoadImage), GCE TDX"
        alternative_model = "the UKI only (a stub that does not LoadImage the kernel)"
    sections_value = _replay(stub_events(uki))
    if major >= STUB_CC_MEASURED:
        rtmr2 = sections_value
        rtmr2_model = f"systemd-stub {version} measures the UKI's sections into RTMR2"
        rtmr2_alternatives = [{"model": NOT_SIGNABLE_ZERO, "signable": False, "value": ZERO}]
    elif major == 255:
        rtmr2 = ZERO
        rtmr2_model = f"systemd-stub {version} measures into the vTPM only: nothing extends RTMR2"
        rtmr2_alternatives = [{"model": "the stub also measures its sections into RTMR2 (not 255's source)",
                               "value": sections_value}]
    else:
        raise PredictionError(f"systemd-stub {version}: no RTMR2 model (255, or 257 and later)")

    rtmr1 = gp.replay_events(primary, "sha384").lower()
    out = {
        "schema": "chutes.tdx-measure-prediction.v1",
        "layout": "uki",
        "machine_type": machine_type,
        "image_sha256": disk.sha256,
        "uki": {"authenticode_sha384": uki_authenticode.hex(), "kernel_authenticode_sha384": kernel_authenticode.hex(),
                "cmdline": cmdline, "systemd_stub": version},
        "gpt_event_sha384": hashlib.sha384(gpt_event).hexdigest(),
        "rtmr1": {"value": rtmr1, "model": rtmr1_model, "events": _event_records(primary)},
        "rtmr1_alternatives": [{"model": alternative_model, "value": gp.replay_events(alternative, "sha384").lower()}],
        "rtmr2": {"value": rtmr2, "model": rtmr2_model},
        "rtmr2_alternatives": rtmr2_alternatives,
        "rtmr3": None,
        "measured_inputs": MEASURED_INPUTS,
        "not_measured": NOT_MEASURED,
        "confirm": "this is a model: confirm it with a capture of a test boot you launch yourself (capture --nonce), "
                   "and sign only values this prediction gives, never a capture's that it does not",
    }
    out.update(_platform_entries(machine_type, platform_data, rtmr1, rtmr2))
    return out


def _platform_entries(machine_type: str, platform_data, rtmr1: str, rtmr2: str) -> dict:
    """MRTD and RTMR0 from the platform data, and the two entries ready for ``write``."""
    if platform_data is None:
        return {"exact": None, "firmware_following": None, "entries": []}
    machine = platform_data["machine_types"].get(machine_type)
    if machine is None:
        raise PredictionError(f"the platform data has no {machine_type}")
    entries = []
    exact = None
    if machine["captures"]:
        newest = machine["captures"][-1]
        exact = {"mrtd": newest["mrtd"], "rtmr0": newest["rtmr0"], "uefi_sha384": newest["uefi_sha384"]}
        entries.append({"machine_type": machine_type, "mrtd": newest["mrtd"], "rtmr0": newest["rtmr0"],
                        "rtmr1": rtmr1, "rtmr2": rtmr2, "rtmr3": None})
    entries.append({"machine_type": machine_type, "mrtd": "gce-endorsed", "rtmr0_template": machine["rtmr0_template"],
                    "rtmr1": rtmr1, "rtmr2": rtmr2, "rtmr3": None})
    return {"exact": exact, "firmware_following": {"rtmr0_template": machine["rtmr0_template"]}, "entries": entries}


def predict_inputs(inputs: dict, machine_type: str, platform_data: dict = None, *, secure_boot: bool = False) -> dict:
    """Other layouts (shim and GRUB): RTMR1 and RTMR2 from a chutes.gcp-prediction-inputs.v1
    manifest through the vendored model's TDX events."""
    rtmr1 = gp.replay_events(gp.tdx_rtmr1_events(inputs, secure_boot=secure_boot), "sha384").lower()
    rtmr2 = gp.replay_events(gp.tdx_rtmr2_events(inputs), "sha384").lower()
    out = {"schema": "chutes.tdx-measure-prediction.v1", "layout": "shim-grub", "machine_type": machine_type,
           "image_sha256": None, "rtmr1": {"value": rtmr1, "model": "sek8s gcp_prediction TDX RTMR1"},
           "rtmr2": {"value": rtmr2, "model": "sek8s gcp_prediction TDX RTMR2"}, "rtmr3": None}
    out.update(_platform_entries(machine_type, platform_data, rtmr1, rtmr2))
    return out
