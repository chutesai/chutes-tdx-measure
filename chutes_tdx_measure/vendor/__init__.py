"""Copies of Chutes modules this package reuses. PINS.json names the source of each and pins its
sha256 (tests/test_vendor.py checks them):

- ``chutes_attest/``: modules of chutesai/chutes-attest v0.8.5: quote parsing, Intel DCAP
  verification through dcap-qvl, Google's TDX provenance, CCEL replay. Each is unchanged except
  ``tdx_verify.py``, which leaves the collateral fetch and its signer check to ``collateral.py``;
- ``gcp_prediction.py``: Chutes' model of what a GCP confidential VM measures (Authenticode, the
  GPT event, the TDX RTMR1 events);
- ``owner_vm_firmware.py``: the verifier of Google's GCE launch endorsements (the TDVF CFV, the
  RTMR0 template fold), from the Chutes client.

A code change here is a new copy and a new pin."""
