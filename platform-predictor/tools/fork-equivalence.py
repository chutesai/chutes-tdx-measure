#!/usr/bin/env python3
# Copyright (c) 2026 Chutes Global Corp
# SPDX-License-Identifier: Apache-2.0
"""Run host profiles through the chutesai/tdx-measure fork and through this predictor; compare.

Every JSON file in PROFILES is one host profile as the API stores it, one API record
(``{"fingerprint", "measured", "profile"}``), a list of such records, or a ready tdx-measure
metadata document (it has ``boot_config``). chutes-cvm renders each profile into the metadata it
hands the fork today (``QemuCommand.build`` with ``MeasurementContext``, then ``ImageConfig``), so
it must be importable: installed, or its source directory given with ``--chutes-cvm``.

Each profile is measured three times, each run in a directory of its own:

- the fork, exactly as chutes-cvm runs it (``--platform-only --create-acpi-tables DIST``);
- this predictor on the same document (the fork form, accepted unchanged);
- this predictor on the document in the versioned form (``metadata_version`` 1 with
  ``firmware_profile`` ``edk2-stable202605`` and ``smbios_tables``), what chutes-cvm sends once it
  moves to that form.

RTMR1 and RTMR2 depend only on the kernel, initrd and command line, so they are measured once per
binary (``--runtime-only``) from ``--image`` (its staged ``.vmlinuz``, ``.initrd`` and
``.cmdline``, as chutes-cvm reads them) or ``--kernel``/``--initrd``/``--cmdline``, and reported on
every row. The report gives MRTD, RTMR0 (both forms), RTMR1, RTMR2 and, for diagnosis, the dumped
ACPI and SMBIOS tables of every profile as match or MISMATCH. It exits 0 only when everything
matches.

The runs are sequential: the fork builds its dump image under one fixed tag and runs it by that
tag. Both binaries need Docker; chutes-cvm's dump shapes run under KVM (``/dev/kvm``).
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
import subprocess  # nosec B404 - fixed argv for the two operator-named binaries.
import sys
import tempfile
from pathlib import Path

FIRMWARE_PROFILE = "edk2-stable202605"
REGISTERS = ("mrtd", "rtmr0", "rtmr0_v1", "rtmr1", "rtmr2", "acpi_tables", "smbios_tables")


def sha256_file(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def load_inputs(directory: Path) -> list[tuple[str, dict]]:
    """``(name, document)`` for every profile or metadata document under ``directory``."""
    out: list[tuple[str, dict]] = []
    for path in sorted(directory.glob("*.json")):
        loaded = json.loads(path.read_text())
        records = loaded if isinstance(loaded, list) else [loaded]
        for index, record in enumerate(records):
            name = path.stem if len(records) == 1 else f"{path.stem}[{index}]"
            if isinstance(record, dict) and "profile" in record and "boot_config" not in record:
                fingerprint = record.get("fingerprint") or ""
                name = f"{name}:{fingerprint[:12]}" if fingerprint else name
                record = record["profile"]
            out.append((name, record))
    return out


def render_metadata(profile: dict, firmware_dir: Path) -> tuple[dict, str]:
    """The metadata chutes-cvm hands the fork for ``profile``, and the profile's TEE name."""
    from chutes_cvm.guest.context import MeasurementContext
    from chutes_cvm.guest.host_profile import HostProfile
    from chutes_cvm.guest.qemu import QemuCommand
    from chutes_cvm.measurement.image_config import ImageConfig

    host = HostProfile.from_api_profile(profile)
    firmware = str(firmware_dir / host.tee_provider.default_firmware)
    # QemuCommand.build prints its topology decisions; keep stdout for the report.
    with contextlib.redirect_stdout(sys.stderr):
        command = QemuCommand.build(host, MeasurementContext.from_host(host, firmware=firmware))
    metadata = ImageConfig(command, host, acpi_tables="acpi.bin").to_dict()
    return metadata, host.tee_provider.name


def versioned(metadata: dict) -> dict:
    """``metadata`` in the versioned form."""
    document = copy.deepcopy(metadata)
    document["metadata_version"] = 1
    boot_config = document["boot_config"]
    boot_config["firmware_profile"] = FIRMWARE_PROFILE
    boot_config["smbios_tables"] = "smbios-tables"
    qemu = boot_config.get("qemu") or {}
    if "processor_id" in qemu and qemu["processor_id"] is None:
        del qemu["processor_id"]
    return document


def run(argv: list[str], log: Path) -> subprocess.CompletedProcess:
    with log.open("w") as handle:
        return subprocess.run(  # nosec B603 - fixed argv
            argv, stdout=handle, stderr=subprocess.STDOUT, check=False, text=True
        )


def platform_run(binary: str, metadata: dict, run_dir: Path, create: list[str]) -> dict:
    """One ``--platform-only --create-acpi-tables`` run in ``run_dir``: its registers and the
    sha256 of the tables it dumped, or ``{"error": ...}``."""
    run_dir.mkdir(parents=True)
    document = copy.deepcopy(metadata)
    boot_config = document["boot_config"]
    boot_config["acpi_tables"] = str(run_dir / "acpi.bin")
    if "smbios_tables" in boot_config:
        boot_config["smbios_tables"] = str(run_dir / "smbios-tables")
    meta_path = run_dir / "metadata.json"
    meta_path.write_text(json.dumps(document, indent=2))
    result_path = run_dir / "result.json"
    log = run_dir / "run.log"
    argv = [binary, str(meta_path), "--platform-only", "--json-file", str(result_path)]
    argv += ["--create-acpi-tables", *create]
    process = run(argv, log)
    if process.returncode != 0 or not result_path.is_file():
        tail = log.read_text().strip().splitlines()[-3:]
        return {"error": f"exit {process.returncode}: " + " | ".join(tail)}
    values = json.loads(result_path.read_text())
    return {
        "mrtd": str(values.get("mrtd", "")).lower(),
        "rtmr0": str(values.get("rtmr0", "")).lower(),
        "acpi_tables": sha256_file(run_dir / "acpi.bin"),
        "smbios_tables": sha256_file(run_dir / "smbios-tables"),
    }


def runtime_run(binary: str, boot: tuple[str, str, str], run_dir: Path) -> dict:
    run_dir.mkdir(parents=True)
    kernel, initrd, cmdline = boot
    meta_path = run_dir / "metadata.json"
    meta_path.write_text(
        json.dumps({"direct": {"kernel": kernel, "initrd": initrd, "cmdline": cmdline}})
    )
    result_path = run_dir / "result.json"
    process = run(
        [binary, "--runtime-only", "--json-file", str(result_path), str(meta_path)],
        run_dir / "run.log",
    )
    if process.returncode != 0 or not result_path.is_file():
        return {"error": f"--runtime-only exit {process.returncode}"}
    values = json.loads(result_path.read_text())
    return {key: str(values.get(key, "")).lower() for key in ("rtmr1", "rtmr2")}


def compare(fork: dict, ours: dict, ours_v1: dict | None, runtime: dict) -> dict:
    """One verdict per register: match, MISMATCH, or an error text."""
    verdicts: dict[str, str] = {}
    pairs = {
        "mrtd": (fork, ours, "mrtd"),
        "rtmr0": (fork, ours, "rtmr0"),
        "rtmr0_v1": (fork, ours_v1, "rtmr0"),
        "acpi_tables": (fork, ours, "acpi_tables"),
        "smbios_tables": (fork, ours, "smbios_tables"),
    }
    for name, (left, right, key) in pairs.items():
        if right is None:
            verdicts[name] = "not run"
        elif "error" in left or "error" in right:
            verdicts[name] = "error: " + (left.get("error") or right.get("error"))
        elif not left.get(key) or left.get(key) != right.get(key):
            verdicts[name] = f"MISMATCH ({left.get(key)} != {right.get(key)})"
        else:
            verdicts[name] = "match"
    for name in ("rtmr1", "rtmr2"):
        fork_rt, ours_rt = runtime.get("fork"), runtime.get("ours")
        if fork_rt is None:
            verdicts[name] = "not run"
        elif "error" in fork_rt or "error" in ours_rt:
            verdicts[name] = "error: " + (fork_rt.get("error") or ours_rt.get("error"))
        elif fork_rt[name] and fork_rt[name] == ours_rt[name]:
            verdicts[name] = "match"
        else:
            verdicts[name] = f"MISMATCH ({fork_rt[name]} != {ours_rt[name]})"
    return verdicts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("profiles", type=Path, help="directory of host-profile JSON files")
    parser.add_argument("--fork", required=True, help="the chutesai/tdx-measure binary")
    parser.add_argument("--ours", required=True, help="this predictor's tdx-measure binary")
    parser.add_argument(
        "--firmware-dir",
        type=Path,
        required=True,
        help="the guest firmware directory chutes-cvm measures with (--bios-dir): "
        "OVMF.inteltdx.fd and OVMF.amdsev.fd",
    )
    parser.add_argument("--chutes-cvm", type=Path, help="chutes-cvm source (src/chutes-cvm)")
    parser.add_argument("--distribution", default="ubuntu:26.04")
    parser.add_argument(
        "--fork-qemu-version",
        help="QEMU package version for the fork (default: the fork's pinned one, as chutes-cvm "
        "runs it)",
    )
    parser.add_argument(
        "--qemu-version",
        default="1:10.2.1+ds-1ubuntu3.1",
        help="QEMU package version for this predictor: the fork's ubuntu:26.04 pin by default",
    )
    parser.add_argument(
        "--qemu-dsc-sha256",
        default="8499c312190488c1126fe61a9e340928eb78da0eff68e7b168ee30627d4a0ad7",
        help="sha256 of that version's .dsc (default: qemu_10.2.1+ds-1ubuntu3.1.dsc's); empty "
        "for a version this predictor pins",
    )
    boot = parser.add_argument_group("RTMR1 and RTMR2 (optional)")
    boot.add_argument("--image", help="a qcow2 with its staged .vmlinuz, .initrd and .cmdline")
    boot.add_argument("--kernel")
    boot.add_argument("--initrd")
    boot.add_argument("--cmdline", help="the kernel command line text")
    parser.add_argument("--work", type=Path, help="keep every run's files here")
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    parser.add_argument("--no-v1", action="store_true", help="skip the versioned-form runs")
    args = parser.parse_args()

    if args.chutes_cvm:
        sys.path.insert(0, str(args.chutes_cvm.resolve()))
    firmware_dir = args.firmware_dir.resolve()
    fork_create = [args.distribution] + ([args.fork_qemu_version] if args.fork_qemu_version else [])
    ours_create = [args.distribution, args.qemu_version]
    if args.qemu_dsc_sha256:
        ours_create += ["--qemu-dsc-sha256", args.qemu_dsc_sha256]

    work_ctx = (
        contextlib.nullcontext(str(args.work))
        if args.work
        else tempfile.TemporaryDirectory(prefix="fork-equivalence-")
    )
    fork_binary = str(Path(args.fork).resolve())
    ours_binary = str(Path(args.ours).resolve())
    with work_ctx as work_name:
        work = Path(work_name).resolve()
        work.mkdir(parents=True, exist_ok=True)

        runtime: dict = {}
        boot_files: tuple[str, str, str] | None = None
        if args.image:
            from chutes_cvm.guest.direct_boot import direct_boot_artifacts

            boot_files = direct_boot_artifacts(os.path.abspath(args.image))
        elif args.kernel and args.initrd and args.cmdline is not None:
            boot_files = (
                os.path.abspath(args.kernel),
                os.path.abspath(args.initrd),
                args.cmdline,
            )
        if boot_files:
            runtime["fork"] = runtime_run(fork_binary, boot_files, work / "runtime-fork")
            runtime["ours"] = runtime_run(ours_binary, boot_files, work / "runtime-ours")

        rows = []
        for index, (name, document) in enumerate(load_inputs(args.profiles)):
            row: dict = {"profile": name}
            try:
                if "boot_config" in document:
                    metadata, tee = document, "metadata"
                else:
                    metadata, tee = render_metadata(document, firmware_dir)
            except Exception as exc:  # noqa: BLE001 - reported per profile
                row.update(tee="?", render_error=f"{type(exc).__name__}: {exc}")
                rows.append(row)
                print(f"{name}: chutes-cvm cannot render it: {exc}", file=sys.stderr)
                continue
            row["tee"] = tee
            base = work / f"{index:03d}"
            print(f"{name}: fork", file=sys.stderr)
            fork = platform_run(fork_binary, metadata, base / "fork", fork_create)
            print(f"{name}: ours", file=sys.stderr)
            ours = platform_run(ours_binary, metadata, base / "ours", ours_create)
            ours_v1 = None
            if not args.no_v1:
                print(f"{name}: ours, metadata_version 1", file=sys.stderr)
                ours_v1 = platform_run(ours_binary, versioned(metadata), base / "ours-v1", ours_create)
            row["values"] = {"fork": fork, "ours": ours, "ours_v1": ours_v1, "runtime": runtime}
            row["verdicts"] = compare(fork, ours, ours_v1, runtime)
            rows.append(row)

    width = max([len(row["profile"]) for row in rows] + [7])
    header = f"{'profile':<{width}}  {'tee':<8}  " + "  ".join(f"{r:<13}" for r in REGISTERS)
    print(header)
    ok = bool(rows)
    for row in rows:
        if "render_error" in row:
            ok = False
            print(f"{row['profile']:<{width}}  {row['tee']:<8}  render error: {row['render_error']}")
            continue
        verdicts = row["verdicts"]
        cells = []
        for register in REGISTERS:
            verdict = verdicts[register]
            short = verdict if verdict in ("match", "not run") else verdict.split(" ")[0]
            if verdict not in ("match", "not run"):
                ok = False
            cells.append(f"{short:<13}")
        print(f"{row['profile']:<{width}}  {row['tee']:<8}  " + "  ".join(cells))
        for register in REGISTERS:
            if verdicts[register] not in ("match", "not run"):
                print(f"    {register}: {verdicts[register]}")
    if args.report:
        args.report.write_text(json.dumps(rows, indent=2) + "\n")
    print("ALL MATCH" if ok else "NOT ALL MATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
