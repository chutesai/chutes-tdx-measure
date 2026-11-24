# Building and testing chutes-tdx-measure

## Install

Python 3.10 to 3.12 (the interpreters dcap-qvl 0.5.3 ships wheels for):

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.lock   # cryptography, dcap-qvl 0.5.3, httpx, pinned with hashes
pip install --no-deps .
chutes-tdx-measure version
```

## Test

The tests use no network: Intel's collateral service and Google's bucket and registry are injected,
and Google's endorsements and the collateral's signer chains come from test PKIs.

```sh
pip install --require-hashes -r requirements-test.lock   # pytest, pinned with hashes
make test       # the vectors, verify-quote's rows, firmware admission and floor, the collateral
                # signer rule, capture, predict on a synthetic disk, the command line
make vectors    # spec/vectors against SHA256SUMS
make mutants    # every mutant in mutants/mutants.json must fail the tests
```

`spec/vectors/` holds the cases this tool is tested against: `measurements.json` (16 document cases,
17 match cases, 4 key proofs), `rtmr0_template.json`, `quote.json` and `reportdata.json`.
`reportdata.json` has the same cases as `spec/vectors/reportdata.json` in
[chutesai/chutes-tdx-gate](https://github.com/chutesai/chutes-tdx-gate), and the Chutes gateway's
checks are tested against the cases of `measurements.json`, `rtmr0_template.json` and
`reportdata.json`.

`make lock` regenerates `requirements.lock` and `requirements-test.lock` with uv (Python 3.12, no
annotations).

## Platform predictor

`tdx-measure` builds and tests on its own, in a digest-pinned Rust image:

```sh
make -C platform-predictor test
make -C platform-predictor repro   # two builds, the same sha256
make -C platform-predictor build
```

[platform-predictor/BUILD.md](platform-predictor/BUILD.md) has the details.
