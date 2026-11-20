"""The vendored copies are the pinned bytes."""

import hashlib
import json
import os

import chutes_tdx_measure.vendor as vendor

BASE = os.path.dirname(vendor.__file__)


def test_pins():
    with open(os.path.join(BASE, "PINS.json")) as stream:
        pins = json.load(stream)["files"]
    assert len(pins) == 8
    for rel, pin in pins.items():
        with open(os.path.join(BASE, rel), "rb") as stream:
            assert hashlib.sha256(stream.read()).hexdigest() == pin["sha256"], rel
