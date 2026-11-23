# chutes-tdx-measure

Chutes' Intel TDX measurement tool. Source only. It has two parts:

- **`chutes-tdx-measure`** (Python, `chutes_tdx_measure/`) for a VM image you build and run on
  Google Cloud as a **bring-your-own Intel TDX VM endpoint**: predict the image's TDX measurements,
  capture them from a test boot, write and sign the measurement document Chutes' gateway checks,
  prove you hold the signing key, and verify a quote exactly as the gateway does (your key service
  can use the same check). The Chutes client ships the same code as `chutes tdx …`, with the same
  version string. The rest of this README describes it.
- **The platform predictor** (Rust, `platform-predictor/`, the `tdx-measure` command) for the guests
  Chutes' bare-metal TDX hosts launch, by QEMU direct kernel boot with Chutes' TDVF, Chutes' site
  images among them: MRTD and RTMR0 to RTMR2 from the firmware, the QEMU launch shape, the kernel,
  initrd and kernel command line, without TDX hardware. `platform-predictor/README.md` describes it
  and `platform-predictor/BUILD.md` its reproducible build.

## Licence

MIT (`LICENSE`), except `platform-predictor/`: Apache-2.0 (`platform-predictor/LICENSE`), derived
from fortanix/tdx-measure and dstack-mr (`platform-predictor/NOTICE`).

## Commands

| Command | Does |
|---|---|
| `key create --out key.pem` | a new Ed25519 key (PKCS#8 PEM, mode 0600, never overwrites); prints the public key to register (`B64` of its 32 bytes) and its fingerprint (SHA-256 of those bytes) to confirm out of band |
| `key proof --key key.pem --user-id U --archive-sha256 H` | the registration's proof of possession: `B64` of the Ed25519 signature of `"chutes-tdx-measurement-key-proof-v1" ‖ 0x00 ‖ U ‖ 0x00 ‖ H`; `--print-message` prints the bytes for an HSM to sign instead |
| `predict --archive disk.tar.gz --platform-data PD --machine-type T` | RTMR1 and RTMR2 from the archive (the image template's UKI layout), MRTD and RTMR0 from Chutes' platform data; both entry forms ready for `write`; what each register covers (`measured_inputs`) and every boot input none covers with the template's handling (`not_measured`) |
| `predict --inputs MANIFEST --platform-data PD --machine-type T` | other layouts (shim and GRUB) from a `chutes.gcp-prediction-inputs.v1` manifest |
| `capture --quote Q --ccel C --nonce N` or `capture --serial-line FILE --nonce N` | a test boot's registers; the quote verified with Intel DCAP (Intel's own collateral service) and its REPORTDATA required to carry your nonce; refused unless the CCEL replays to RTMR0-3; with the RTMR0 template the log implies. `--unverified` skips the quote's verification and the nonce (no network) and says so: registers nothing authenticates. A capture confirms a prediction; sign only values `predict` gives |
| `write --image-sha256 H --entries E -o m.json` | the document (`json.dumps(indent=2)` and a newline). `E` is a JSON list of entries or a `predict` output. Any bytes that verify are valid: these are what get signed |
| `sign --key key.pem m.json -o m.json.sig` | `B64` of the 64-byte signature over the exact bytes, no newline |
| `verify-document --public-key K --image-sha256 H m.json m.json.sig` | the document's verification, steps 1-5 of `chutesai/chutes-tdx-gate` spec/SPEC.md §4.2 |
| `verify-quote …` | the gateway's rows against a quote (below); `--json` for the rows |

Exit status: 0 success, 1 a decided refusal, 2 no verdict (Intel's collateral, Google's bucket or
registry did not answer) or a usage error.

## The document (`chutes.tdx-measurements.v1`)

UTF-8 JSON of at most 64 KiB, no byte-order mark, no duplicate key, no NaN or Infinity, exactly
`{"type": "chutes.tdx-measurements.v1", "image_sha256": "<sha256 of your disk.tar.gz>", "accept": [...]}`
with 1 to 32 entries, each for one machine type and of one form:

- **exact**: `{"machine_type", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"}` (lower-case hex, `rtmr3`
  `null` to leave it unchecked). When Google updates its TDX firmware, MRTD and RTMR0 change and new
  VMs are refused until you sign a new document;
- **firmware-following**: `{"machine_type", "mrtd": "gce-endorsed", "rtmr0_template": {"before_cfv",
  "after_cfv": [...]}, "rtmr1", "rtmr2", "rtmr3"}`: any TDX firmware Google endorses, at or above
  Chutes' floor, with RTMR0 folded from the template and that build's CFV.

Chutes' firmware floor and its list of refused builds apply to **both** forms.

## verify-quote

In this order; `provider_root` runs last and only when every other row passed:

| Row | Check | Code |
|---|---|---|
| `quote` | Intel DCAP (dcap-qvl 0.5.3 through chutes-attest 0.9.0): collateral signed by Intel's TCB signing certificate (below), TCB status, advisories, TD attributes, debug off | `endpoint_vm_quote_refused` |
| `binding` | a v4 TDX quote whose REPORTDATA is `SHA-512("chutes-tdx-endpoint-attest-v1" ‖ 0x00 ‖ nonce ‖ public key)` (`--nonce`, `--public-key-file`), or the value a key service gives (`--report-data`) | `endpoint_vm_binding_mismatch` |
| `platform` | the project the VM names (`--gce-project`) is pinned: in `--allowed-project` (repeatable) or `--platform`'s list, in both when both are given (one is required: the VM's own claim is never its pin); the zone's region and the machine type allowed | `endpoint_vm_platform_mismatch` |
| `measurements` | every document under your key for this image; the MRTD admitted (a Google-endorsed, RAM-independent build at or above the floor, not denied; its CFV from Google's binary); a matching entry. Not run (`endpoint_check_incomplete`) unless `quote` and `binding` passed | `endpoint_vm_measurements_unsigned`, `endpoint_vm_firmware_refused`, `endpoint_vm_measurements_unmatched` |
| `provider_root` | MRCONFIGID and MROWNERCONFIG zero; MR_OWNER is the PZID of the instance you name; the quote's host is in Google's registry in that zone's region | `endpoint_vm_provider_refused` |

A row that could not reach a verdict is `incomplete` with `endpoint_check_incomplete`. A verdict
without the TD's attributes is refused (it cannot show debug is off). When both `--floor` and
`--platform` are given, both floors apply: each minimum's maximum, and every denied build.

The firmware index (Google's endorsements and binaries, verified under the pinned GCE root) lives in
`~/.cache/chutes-tdx-measure/firmware` (`--firmware-dir`); an unknown MRTD is fetched once.

`verify-quote` fetches Intel's DCAP collateral from `--collateral-source`, else from
`TDX_COLLATERAL_SOURCE`, else from Intel's own service: `intel-pcs`, `phala-pccs` or an `https://`
PCCS URL. `capture` always asks Intel's own service. Whichever service answers, the quote is refused
unless Intel's TCB signing certificate, under the pinned Intel SGX root, signed the TCB Info and the
QE Identity.
