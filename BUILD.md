# Building and testing chutes-tdx-measure

Python 3.10 to 3.12 (dcap-qvl 0.5.3's wheels).

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.lock   # cryptography, dcap-qvl 0.5.3, httpx and their dependencies, pinned
pip install --no-deps .
chutes-tdx-measure version
```

Tests (no network: Intel's collateral, Google's bucket and registry are injected; Google's
endorsements and the collateral's signer chains are made by test PKIs):

```sh
pip install --require-hashes -r requirements-test.lock   # pytest, pinned
make test             # every vector of spec/vectors (16 document cases, 17 match cases, 4 key proofs,
                      # 3 templates, 4 quotes, the REPORTDATA rule), verify-quote's rows, the firmware
                      # admission and floor, the collateral signer rule, capture, predict on a
                      # synthetic disk, the CLI
make vectors          # spec/vectors/SHA256SUMS
make mutants          # every mutant of mutants/mutants.json must be killed
```

`spec/vectors/` holds the test vectors this tool consumes (`measurements.json`, `quote.json`,
`reportdata.json`, `rtmr0_template.json`), with their sha256 in `SHA256SUMS`. Chutes' own verifier
is tested against the same cases; `reportdata.json` is the same file as in `chutesai/chutes-tdx-gate`.

`make lock` regenerates `requirements.lock` and `requirements-test.lock` (uv, Python 3.12, no
annotations).
