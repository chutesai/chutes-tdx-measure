"""Copies of reused code, with their comments edited, pinned by sha256 in PINS.json
(tests/test_vendor.py checks them): chutes-attest 0.9.0 (quote parsing, Intel DCAP verification
through dcap-qvl, Google's TDX provenance, CCEL replay), sek8s's GCP measurement model
(Authenticode, the GPT event, the TDX RTMR1 events), and the Chutes SDK's GCE firmware endorsement
verifier (Google's launch endorsements, the TDVF CFV, the RTMR0 template fold). Their code is the
upstream code unchanged: a code change is a new copy and a new pin."""
