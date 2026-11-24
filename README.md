# chutes-tdx-measure

Tools to predict, capture, sign and verify the Intel TDX measurements of a VM image for Chutes'
**bring-your-own Intel TDX VM endpoints**. Chutes boots a VM image you build on Google Cloud as an
Intel TDX confidential VM, and requests reach it through the **Chutes gateway**: the Chutes service
that routes callers' requests to your VMs, together with the Chutes client each caller runs. Both
check a VM's TDX quote against the measurement documents you signed for the image before any request
reaches the VM. The repository holds two tools:

- **`chutes-tdx-measure`** (Python, `chutes_tdx_measure/`), for such an image. It predicts the image's
  measurements, writes and signs the measurement document the gateway checks, and runs the gateway's
  checks against a quote. This README describes it.
- **`tdx-measure`** (Rust, `platform-predictor/`), which predicts MRTD and RTMR0 to RTMR2 for a guest
  that QEMU boots directly with a TDVF firmware, as Chutes' bare-metal TDX hosts launch guests. See
  [platform-predictor/README.md](platform-predictor/README.md).

## Guarantees

- `verify-quote` runs the gateway's checks, in the gateway's order (see [verify-quote](#verify-quote)).
  A key service can run it before it releases a key.
- `verify-document` is steps 1 to 5 of the document verification in
  [chutes-tdx-gate `spec/SPEC.md`](https://github.com/chutesai/chutes-tdx-gate/blob/main/spec/SPEC.md),
  section 4.2.
- `capture` reports registers only from a quote that Intel DCAP verifies, whose REPORTDATA carries
  your nonce and whose event log (CCEL) replays to RTMR0 to RTMR3.

Limits:

- A capture shows what one genuine TD measured, not that the TD booted your image. Sign only the
  values `predict` gives for your own archive; use a capture to confirm them.
- `predict --archive` models one layout: a unified kernel image (UKI) booted directly as
  `\EFI\BOOT\BOOTX64.EFI`, Secure Boot off, systemd-stub 255 or 257 and later. Other stub versions
  are refused. `predict --inputs` models shim and GRUB from a manifest.
- MRTD and RTMR0 come from the platform data for the machine type (see [Usage](#usage)), not from
  your archive.

## Install

Python 3.10 to 3.12 (the interpreters dcap-qvl 0.5.3 ships wheels for):

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.lock
pip install --no-deps .
chutes-tdx-measure version
```

## Usage

Make a measurement key, then predict, write and sign the document for an archive (for example one
built from [chutesai/chutes-tdx-image](https://github.com/chutesai/chutes-tdx-image)):

```sh
chutes-tdx-measure key create --out key.pem    # prints the public key and its fingerprint
sha=$(sha256sum disk.tar.gz | cut -d' ' -f1)
chutes-tdx-measure predict --archive disk.tar.gz --platform-data platform-data.json \
    --machine-type c3-standard-4 -o prediction.json
chutes-tdx-measure write --image-sha256 "$sha" --entries prediction.json -o m.json
chutes-tdx-measure sign --key key.pem m.json -o m.json.sig
chutes-tdx-measure verify-document --public-key "$PUBLIC_KEY" --image-sha256 "$sha" m.json m.json.sig
```

`$PUBLIC_KEY` is the public key `key create` printed. Give its fingerprint to your callers yourself:
their Chutes client asks for it when they save the endpoint's trust file.

You register the key with Chutes when you upload the archive with the Chutes client
(`chutes endpoint vm image upload ./disk.tar.gz --name NAME --version-label VERSION
--measurement-key-file key.pem`). The `chutes endpoint vm` commands are in the client that
vms.chutes.ai gives its users (install steps under Docs, CLI), not in the `chutes` package on PyPI.
The upload includes a proof that you hold the key: an Ed25519 signature over your Chutes user id and
the archive's sha256 (`key proof` below). The client signs it from the key file; for a key held
elsewhere, such as an HSM, `key proof --print-message --user-id USER_ID --archive-sha256 "$sha"`
prints the bytes to sign. Then register the signed document for the image with
`chutes endpoint vm measurements add IMAGE_ID m.json m.json.sig`.

`platform-data.json` (`chutes.cvm-platform-data.v1`) holds Chutes' measurements of its platform: for
each machine type Chutes offers, the MRTD and RTMR0 Chutes recorded from a test boot of
chutes-tdx-image's `capture` variant, launched as Chutes launches endpoint VMs (Secure Boot off, vTPM
and integrity monitoring on, one disk), and the RTMR0 template its event log gives. The file is not
published; endpoint owners get the current one from Chutes. You can take the same values from a test
boot of your own: launch the capture variant that way on the machine type, in your own Google Cloud
project, and run `capture`. Its `rtmr0_template` is the template for a firmware-following entry, and
its MRTD and RTMR0 are the exact values for the firmware build that VM ran. Without
`--platform-data`, `predict` gives RTMR1 and RTMR2 only.

Exit status: 0 success, 1 refused, 2 no verdict (Intel's collateral service, Google's bucket or
Google's registry did not answer) or a usage error.

## Commands

| Command | Does |
|---|---|
| `key create --out key.pem` | Creates an Ed25519 key (PKCS#8 PEM, mode 0600; never overwrites). Prints the public key to register (`B64` of its 32 bytes) and its fingerprint (SHA-256 of those bytes) to confirm out of band. |
| `key proof --key key.pem --user-id U --archive-sha256 H` | The registration's proof of possession: `B64` of the Ed25519 signature of `"chutes-tdx-measurement-key-proof-v1" ‖ 0x00 ‖ U ‖ 0x00 ‖ H`. `--print-message` prints the message instead, for an HSM to sign. |
| `predict --archive disk.tar.gz --platform-data PD --machine-type T` | RTMR1 and RTMR2 from the archive, MRTD and RTMR0 from the platform data, and both entry forms ready for `write`. `measured_inputs` lists what each register covers; `not_measured` lists every boot input no register covers and how the image template handles it. |
| `predict --inputs MANIFEST --platform-data PD --machine-type T` | The same for shim and GRUB layouts, from a `chutes.gcp-prediction-inputs.v1` manifest. |
| `capture --quote Q --ccel C --nonce N`, or `capture --serial-line FILE --nonce N` | A test boot's registers and the RTMR0 template its event log implies. The quote is verified with Intel DCAP against Intel's own collateral service, its REPORTDATA must carry the nonce, and the CCEL must replay to RTMR0 to RTMR3. `--unverified` skips the quote verification and the nonce (no network) and says so in its output. |
| `write --image-sha256 H --entries E -o m.json` | The document, written as `json.dumps(indent=2)` and a newline. `E` is a JSON list of entries or a `predict` output. Any bytes that verify are valid; these are the bytes you sign. |
| `sign --key key.pem m.json -o m.json.sig` | `B64` of the 64-byte Ed25519 signature over the exact bytes, no newline. |
| `verify-document --public-key K --image-sha256 H m.json m.json.sig` | Steps 1 to 5 of the document verification. |
| `verify-quote …` | The gateway's checks against a quote (below); `--json` prints the rows. |

`B64` is standard base64 with padding, no whitespace.

## The measurement document

UTF-8 JSON of at most 64 KiB, with no byte-order mark, duplicate key, NaN or Infinity:
`{"type": "chutes.tdx-measurements.v1", "image_sha256": "<sha256 of disk.tar.gz>", "accept": [...]}`,
with 1 to 32 entries. Each entry names one machine type and has one of two forms:

- **Exact**: `{"machine_type", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"}`, lower-case hex, `rtmr3`
  `null` to leave it unchecked. When Google updates its TDX firmware, MRTD and RTMR0 change, and new
  VMs are refused until you sign a new document.
- **Firmware-following**: `{"machine_type", "mrtd": "gce-endorsed", "rtmr0_template": {"before_cfv",
  "after_cfv": [...]}, "rtmr1", "rtmr2", "rtmr3"}`. It accepts any TDX firmware Google endorses at or
  above Chutes' floor, with RTMR0 folded from the template and that build's configuration firmware
  volume (CFV).

Chutes' firmware floor and its list of refused builds apply to both forms.

## verify-quote

The rows run in this order. `measurements` runs only when `quote` and `binding` passed, and
`provider_root` only when every other row passed.

| Row | Check | Refusal code |
|---|---|---|
| `quote` | Intel DCAP (dcap-qvl 0.5.3): collateral signed by Intel's TCB signing certificate, TCB status, advisories, TD attributes, debug off | `endpoint_vm_quote_refused` |
| `binding` | A v4 TDX quote whose REPORTDATA is `SHA-512("chutes-tdx-endpoint-attest-v1" ‖ 0x00 ‖ nonce ‖ public key)` (`--nonce`, `--public-key-file`), or the value a key service gives (`--report-data`) | `endpoint_vm_binding_mismatch` |
| `platform` | The project the VM names (`--gce-project`) is in the pin: `--allowed-project` (repeatable), `--platform`'s list, or both when both are given. One of them is required, since the VM's own claim is never its pin. The zone's region and the machine type must be allowed. | `endpoint_vm_platform_mismatch` |
| `measurements` | Every document under your key for this image; the MRTD admitted (a Google-endorsed, RAM-independent build at or above the floor, not denied, its CFV taken from Google's binary); a matching entry | `endpoint_vm_measurements_unsigned`, `endpoint_vm_firmware_refused`, `endpoint_vm_measurements_unmatched` |
| `provider_root` | MRCONFIGID and MROWNERCONFIG are zero; MR_OWNER is the PZID of the instance you name; Google's registry lists the quote's host in that zone's region | `endpoint_vm_provider_refused` |

A row that reaches no verdict is `incomplete`, with `endpoint_check_incomplete`. A verdict without
the TD's attributes is refused, since it cannot show that debug is off. With both `--floor` and
`--platform`, both floors apply: the higher of each minimum, and every denied build.

The firmware index (Google's endorsements and binaries, verified under the pinned GCE root) is kept
in `~/.cache/chutes-tdx-measure/firmware` (`--firmware-dir` to change it). An MRTD the index does
not know is fetched once.

`verify-quote` fetches Intel's DCAP collateral from `--collateral-source`, else from
`TDX_COLLATERAL_SOURCE`, else from Intel's own service: `intel-pcs`, `phala-pccs` or an `https://`
PCCS URL. `capture` always uses Intel's own service. Whichever service answers, the quote is refused
unless Intel's TCB signing certificate, under the pinned Intel SGX root, signed the TCB Info and the
QE Identity.

## Build and test

```sh
pip install --require-hashes -r requirements-test.lock
make test       # the test suite; no network
make vectors    # spec/vectors against SHA256SUMS
make mutants    # every mutant in mutants/mutants.json must fail the tests
```

[BUILD.md](BUILD.md) has the details, including the platform predictor's reproducible build.

## Layout

| Path | Contents |
|---|---|
| `chutes_tdx_measure/` | The Python package; `cli.py` is the command line |
| `chutes_tdx_measure/vendor/` | Copies of chutes-attest v0.8.5 modules and two other Chutes modules; `PINS.json` names the source of each and pins its sha256 |
| `spec/vectors/` | Test vectors for documents, templates, quotes and REPORTDATA |
| `tests/` | The test suite |
| `mutants/` | The mutation check |
| `platform-predictor/` | `tdx-measure`, the Rust predictor |

## Licence

[PolyForm Shield 1.0.0](https://polyformproject.org/licenses/shield/1.0.0) (`LICENSE`): any use,
including commercial, except providing a product that competes with Chutes. `platform-predictor/` is
Apache-2.0 (`platform-predictor/LICENSE`, attribution in `platform-predictor/NOTICE`), and its
`pci-bar-stub.c`, which the dump images build into QEMU, is also available under GPL-2.0-or-later.
The Intel and Google root certificates the verifier pins are theirs. `NOTICE` lists these parts.
