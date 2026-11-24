#!/usr/bin/env python3
"""Parse and replay the TDX TCG2 event log referenced by the CCEL table."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

DEFAULT_EVENT_LOG = Path("/sys/firmware/acpi/tables/data/CCEL")
MAX_EVENT_LOG_BYTES = 16 * 1024 * 1024
MAX_QUOTE_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 4 * 1024 * 1024
MAX_DIGESTS = 16
TPM_ALG_SHA384 = 0x000C
EV_NO_ACTION = 0x00000003


@dataclass(frozen=True)
class Event:
    offset: int
    mr_index: int
    event_type: int
    digests: dict[int, bytes]
    data: bytes


def read_artifact(path: Path, *, wrapper_key: str, max_bytes: int) -> bytes:
    """Read raw evidence or the JSON/base64 representation returned by the service."""
    raw = path.read_bytes()
    stripped = raw.lstrip()
    if stripped.startswith((b"{", b'"')):
        try:
            document = json.loads(raw)
            encoded = (
                document.get(wrapper_key) if isinstance(document, dict) else document
            )
            if not isinstance(encoded, str):
                raise ValueError(
                    f"JSON evidence does not contain a base64 {wrapper_key!r} value"
                )
            raw = base64.b64decode(encoded, validate=True)
        except (json.JSONDecodeError, UnicodeDecodeError, binascii.Error) as exc:
            raise ValueError(f"invalid JSON/base64 evidence: {exc}") from exc
    if not raw or len(raw) > max_bytes:
        raise ValueError(
            f"{wrapper_key} is empty or exceeds the {max_bytes}-byte size limit"
        )
    return raw


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _parse_spec_event(data: bytes) -> tuple[Event, dict[int, int], int]:
    minimum = 4 + 4 + 20 + 4
    if len(data) < minimum:
        raise ValueError("CCEL event log is truncated before the Spec ID event")
    mr_index, event_type = struct.unpack_from("<II", data, 0)
    event_size = _u32(data, 28)
    end = minimum + event_size
    if event_size > MAX_EVENT_BYTES or end > len(data):
        raise ValueError("CCEL Spec ID event has an invalid size")
    event_data = data[32:end]
    if event_type != EV_NO_ACTION or not event_data.startswith(b"Spec ID Event03"):
        raise ValueError("CCEL event log does not start with a TCG Spec ID Event03")
    if len(event_data) < 29:
        raise ValueError("CCEL Spec ID payload is truncated")
    algorithm_count = _u32(event_data, 24)
    if not 1 <= algorithm_count <= MAX_DIGESTS:
        raise ValueError("CCEL Spec ID algorithm count is invalid")
    cursor = 28
    algorithms: dict[int, int] = {}
    for _ in range(algorithm_count):
        if cursor + 4 > len(event_data):
            raise ValueError("CCEL Spec ID algorithm table is truncated")
        algorithm = _u16(event_data, cursor)
        digest_size = _u16(event_data, cursor + 2)
        cursor += 4
        if algorithm in algorithms or not 1 <= digest_size <= 128:
            raise ValueError("CCEL Spec ID algorithm table is invalid")
        algorithms[algorithm] = digest_size
    if TPM_ALG_SHA384 not in algorithms or algorithms[TPM_ALG_SHA384] != 48:
        raise ValueError("CCEL event log does not declare SHA-384")
    return (
        Event(
            offset=0,
            mr_index=mr_index,
            event_type=event_type,
            digests={},
            data=event_data,
        ),
        algorithms,
        end,
    )


def parse_event_log(data: bytes) -> list[Event]:
    if not data or len(data) > MAX_EVENT_LOG_BYTES:
        raise ValueError("CCEL event log is empty or exceeds the size limit")
    spec_event, algorithms, cursor = _parse_spec_event(data)
    events = [spec_event]
    while cursor < len(data):
        remainder = data[cursor:]
        if all(byte in (0x00, 0xFF) for byte in remainder):
            break
        start = cursor
        if cursor + 12 > len(data):
            raise ValueError("CCEL event header is truncated")
        mr_index, event_type, digest_count = struct.unpack_from("<III", data, cursor)
        cursor += 12
        if not 1 <= digest_count <= MAX_DIGESTS:
            raise ValueError(f"CCEL event at {start:#x} has an invalid digest count")
        digests: dict[int, bytes] = {}
        for _ in range(digest_count):
            if cursor + 2 > len(data):
                raise ValueError("CCEL event digest header is truncated")
            algorithm = _u16(data, cursor)
            cursor += 2
            digest_size = algorithms.get(algorithm)
            if digest_size is None:
                raise ValueError(f"CCEL event uses undeclared algorithm {algorithm:#x}")
            if algorithm in digests or cursor + digest_size > len(data):
                raise ValueError("CCEL event digest list is malformed")
            digests[algorithm] = data[cursor : cursor + digest_size]
            cursor += digest_size
        if cursor + 4 > len(data):
            raise ValueError("CCEL event size is truncated")
        event_size = _u32(data, cursor)
        cursor += 4
        if event_size > MAX_EVENT_BYTES or cursor + event_size > len(data):
            raise ValueError("CCEL event payload has an invalid size")
        event_data = data[cursor : cursor + event_size]
        cursor += event_size
        events.append(
            Event(
                offset=start,
                mr_index=mr_index,
                event_type=event_type,
                digests=digests,
                data=event_data,
            )
        )
    return events


def replay_sha384(events: list[Event]) -> dict[str, str]:
    registers = {index: bytes(48) for index in range(4)}
    for event in events:
        if event.event_type == EV_NO_ACTION:
            continue
        digest = event.digests.get(TPM_ALG_SHA384)
        if digest is None:
            continue
        register_index = event.mr_index - 1
        if register_index not in registers:
            raise ValueError(
                f"CCEL event at {event.offset:#x} targets invalid MR index {event.mr_index}"
            )
        registers[register_index] = hashlib.sha384(
            registers[register_index] + digest
        ).digest()
    return {f"RTMR{index}": value.hex().upper() for index, value in registers.items()}


def verify_replay(data, quote_measurements, receipt_measurements):
    """Replay the event log and require RTMR0-2 to equal both the quote's values and the predicted
    values (``receipt_measurements``).

    This proves the log is consistent with the measurements; it says nothing about how the
    measured artefacts were built.
    """
    replayed = replay_sha384(parse_event_log(data))
    for index in range(3):
        key = f"rtmr{index}"
        if replayed[key.upper()] != quote_measurements[key].upper():
            raise ValueError(f"CCEL {key} does not match the hardware quote")
        if replayed[key.upper()] != receipt_measurements[key].upper():
            raise ValueError(f"CCEL {key} does not match the receipt prediction")
    return replayed
