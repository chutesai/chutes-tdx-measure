"""The collateral's signers: the TCB Info's and the QE Identity's issuer chain must each be Intel's
TCB signing certificate and the pinned root, judged before the vendored verifier reads the
collateral, whichever service answered. The chains come from a test PKI (a synthetic SGX
root CA, pinned for the test); Intel's collateral service and Intel's verifier are injected."""

import asyncio
import json

import pytest

from chutes_tdx_measure import collateral
from chutes_tdx_measure.vendor.chutes_attest import intel_root, tdx_verify
from intel_testkit import NOW, Verdict, collateral_document, intel_pki, other_chains, pin, serve

QUOTE = b"a quote: the injected verifier does not read it"
MEMBERS = [("tcb_info_issuer_chain", "TCB Info"), ("qe_identity_issuer_chain", "QE Identity")]


def verify(**kwargs):
    kwargs.setdefault("now", NOW)
    return asyncio.run(collateral.verify_quote(QUOTE, **kwargs))


# ---- the rule

@pytest.mark.parametrize("chain,needle", [
    ("pck-chain", "issuer chain is not exactly two PEM certificates"),
    ("platform-ca", "is signed by 'Intel SGX PCK Platform CA', not by 'Intel SGX TCB Signing'"),
    ("a-pck-certificate", "is signed by 'Intel SGX PCK Certificate', not by 'Intel SGX TCB Signing'"),
    ("named-as-the-signer-under-the-platform-ca", "signer was not issued by the pinned Intel SGX root CA"),
    ("named-as-the-signer-under-another-root", "signer was not issued by the pinned Intel SGX root CA"),
    ("another-root-of-the-same-name", "does not end at the pinned Intel SGX root CA"),
    ("the-signer-alone", "issuer chain is not exactly two PEM certificates"),
    ("the-root-first", "does not end at the pinned Intel SGX root CA"),
    ("the-signer-twice", "does not end at the pinned Intel SGX root CA"),
    ("a-third-certificate", "issuer chain is not exactly two PEM certificates"),
    ("a-block-of-another-label-first", "issuer chain is not exactly two PEM certificates"),
    ("text-before-the-chain", "issuer chain is not exactly two PEM certificates"),
    ("text-after-the-chain", "issuer chain is not exactly two PEM certificates"),
    ("respelled-base64", "holds a certificate that does not parse"),
    ("an-unknown-signature-algorithm", "signer was not issued by the pinned Intel SGX root CA"),
    ("not-certificates", "holds a certificate that does not parse"),
    ("empty", "issuer chain is not exactly two PEM certificates"),
])
def test_a_chain_that_is_not_intels_tcb_signing_certificate_and_the_root_is_refused(monkeypatch, chain, needle):
    """Each chain as dcap-qvl reads it (the first PEM block is the signer, whatever its label), and
    whichever of the two documents it signs."""
    pki = pin(monkeypatch)
    genuine, other = pki.signer_chain, other_chains(pki)[chain]
    both = {"tcb_info_issuer_chain": genuine, "qe_identity_issuer_chain": genuine}
    assert collateral.collateral_signers(both) is None
    for member, what in MEMBERS:
        refused = collateral.collateral_signers({**both, member: other})
        assert refused is not None and refused.startswith(f"the {what} ") and needle in refused


@pytest.mark.parametrize("member,what", MEMBERS)
def test_a_document_without_a_chain_as_text_is_refused(monkeypatch, member, what):
    pki = pin(monkeypatch)
    both = {"tcb_info_issuer_chain": pki.signer_chain, "qe_identity_issuer_chain": pki.signer_chain}
    for value in (None, 1, [pki.signer_chain]):
        assert collateral.collateral_signers({**both, member: value}) == (
            f"the {what} issuer chain is not exactly two PEM certificates")
    del both[member]
    assert collateral.collateral_signers(both) == f"the {what} issuer chain is not exactly two PEM certificates"


def test_the_genuine_chain_passes_under_the_pinned_root_only(monkeypatch):
    pki = intel_pki()
    # As a PCCS may send it: CRLF line ends, blank lines around and between the certificates.
    spaced = "\n" + pki.signer_chain.replace("\n", "\r\n").replace(
        "-----END CERTIFICATE-----\r\n", "-----END CERTIFICATE-----\r\n\r\n")
    both = {"tcb_info_issuer_chain": pki.signer_chain, "qe_identity_issuer_chain": spaced}
    # Under the package's own pin, Intel's, the synthetic chain is another root's.
    assert "does not end at the pinned Intel SGX root CA" in collateral.collateral_signers(both)
    pin(monkeypatch)
    assert collateral.collateral_signers(both) is None
    # And a chain that ends at Intel's real root is not the pinned one's.
    real_root = intel_root.INTEL_SGX_ROOT_CA_PEM
    under_intel = pki.signer_chain.split("-----END CERTIFICATE-----\n")[0] + "-----END CERTIFICATE-----\n" + real_root
    assert "does not end at the pinned Intel SGX root CA" in collateral.collateral_signers(
        {**both, "tcb_info_issuer_chain": under_intel})


# ---- the path every quote takes here: fetch once, judge, hand the verifier what was judged

def test_the_verifier_is_handed_the_text_whose_signers_were_judged(monkeypatch):
    pki = pin(monkeypatch)
    document = collateral_document(pki.signer_chain, pki.signer_chain)
    asked, handed = serve(monkeypatch, document)
    verdict = verify()
    assert isinstance(verdict, Verdict)
    # One fetch, from Intel's own service by default; the verifier fetches nothing.
    assert asked == [(QUOTE, "intel-pcs")]
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    assert handed == [(QUOTE, text, NOW)]
    assert collateral.collateral_signers(json.loads(handed[0][1])) is None


@pytest.mark.parametrize("member,what", MEMBERS)
@pytest.mark.parametrize("chain,needle", [
    ("platform-ca", "is signed by 'Intel SGX PCK Platform CA', not by 'Intel SGX TCB Signing'"),
    ("a-pck-certificate", "is signed by 'Intel SGX PCK Certificate', not by 'Intel SGX TCB Signing'"),
])
def test_collateral_under_another_certificate_of_the_root_never_reaches_the_verifier(monkeypatch, member, what,
                                                                                      chain, needle):
    """The holder of any key under the root (a platform CA, a PCK certificate) signs collateral that
    dcap-qvl 0.5.3 accepts: refused here, before dcap-qvl sees it."""
    pki = pin(monkeypatch)
    chains = {"tcb_info_issuer_chain": pki.signer_chain, "qe_identity_issuer_chain": pki.signer_chain,
              member: other_chains(pki)[chain]}
    asked, handed = serve(monkeypatch, collateral_document(chains["tcb_info_issuer_chain"],
                                                           chains["qe_identity_issuer_chain"]))
    with pytest.raises(tdx_verify.TdxQuoteRejected) as refused:
        verify()
    assert str(refused.value) == f"the TDX collateral from intel-pcs is not Intel's: the {what} {needle}"
    assert len(asked) == 1 and handed == []


@pytest.mark.parametrize("named,source", [(None, "intel-pcs"), ("intel-pcs", "intel-pcs"), ("phala-pccs", "phala-pccs"),
                                          ("https://pccs.example/", "https://pccs.example/")])
def test_the_rule_holds_whichever_service_answers(monkeypatch, named, source):
    pki = pin(monkeypatch)
    forged = collateral_document(pki.signer_chain, other_chains(pki)["platform-ca"])
    asked, handed = serve(monkeypatch, forged)
    with pytest.raises(tdx_verify.TdxQuoteRejected, match=f"the TDX collateral from {source} is not Intel's"):
        verify(collateral_source=named)
    assert asked == [(QUOTE, source)] and handed == []
    # The same service with Intel's own collateral is verified.
    asked, handed = serve(monkeypatch, collateral_document(pki.signer_chain, pki.signer_chain))
    assert isinstance(verify(collateral_source=named), Verdict)
    assert asked == [(QUOTE, source)] and len(handed) == 1


def test_the_environments_source_is_judged_by_the_same_rule(monkeypatch):
    pki = pin(monkeypatch)
    monkeypatch.setenv("TDX_COLLATERAL_SOURCE", "https://pccs.example/")
    asked, handed = serve(monkeypatch, collateral_document(other_chains(pki)["platform-ca"], pki.signer_chain))
    with pytest.raises(tdx_verify.TdxQuoteRejected, match="from https://pccs.example/ is not Intel's: the TCB Info"):
        verify()
    assert asked == [(QUOTE, "https://pccs.example/")] and handed == []
    # A source that is not one is a usage error, as in the vendored verifier: nothing is fetched.
    with pytest.raises(ValueError, match="TDX collateral source must be"):
        verify(collateral_source="http://pccs.example/")
    assert len(asked) == 1


def test_stale_collateral_is_no_verdict(monkeypatch):
    """As in the vendored verifier: stale collateral is the verifier's input failing, never a verdict
    on the TD, whoever signed it."""
    pki = pin(monkeypatch)
    for qe_chain in (pki.signer_chain, other_chains(pki)["platform-ca"]):
        stale = collateral_document(pki.signer_chain, qe_chain, issued="2026-10-01T00:00:00Z")
        asked, handed = serve(monkeypatch, stale)
        with pytest.raises(tdx_verify.VerifierUnavailable, match="stale TDX collateral from intel-pcs: collateral_age"):
            verify()
        assert len(asked) == 1 and handed == []


@pytest.mark.parametrize("document", [None, [], "collateral", {}, {"tcb_info": 1, "qe_identity": None}])
def test_a_document_that_is_not_collateral_is_no_verdict(monkeypatch, document):
    pin(monkeypatch)
    asked, handed = serve(monkeypatch, document)
    with pytest.raises(tdx_verify.VerifierUnavailable, match="TDX collateral from intel-pcs"):
        verify()
    assert handed == []


def test_collateral_without_a_json_form_is_no_verdict(monkeypatch):
    pin(monkeypatch)
    asked, handed = serve(monkeypatch, None, fetched=lambda document: object())
    with pytest.raises(tdx_verify.VerifierUnavailable, match="TDX collateral from intel-pcs is malformed"):
        verify()
    assert handed == []


def test_the_fetchs_failures_are_the_vendored_verifiers(monkeypatch):
    pin(monkeypatch)
    serve(monkeypatch, None, error=OSError("connection refused"))
    with pytest.raises(tdx_verify.VerifierUnavailable, match="from intel-pcs is unavailable: OSError: connection refused"):
        verify()
    serve(monkeypatch, None, error=ValueError("not a quote"))
    with pytest.raises(tdx_verify.TdxQuoteRejected, match="TDX quote/collateral request is invalid: not a quote"):
        verify()
    serve(monkeypatch, None, error=tdx_verify.VerifierUnavailable("dcap-qvl 0.5.3 is required"))
    with pytest.raises(tdx_verify.VerifierUnavailable, match="dcap-qvl 0.5.3 is required"):
        verify()
    asked, handed = serve(monkeypatch, None)
    with pytest.raises(tdx_verify.TdxQuoteRejected, match="TDX quote bytes are required"):
        asyncio.run(collateral.verify_quote(b"", now=NOW))
    with pytest.raises(ValueError, match="now must be integer Unix seconds"):
        asyncio.run(collateral.verify_quote(QUOTE, now=1.5))
    assert asked == [] and handed == []


def test_the_real_library_reads_the_judged_text(monkeypatch):
    """The seam with dcap-qvl itself: its collateral object's JSON is judged, and the vendored
    ``verify_tdx_quote_with_collateral`` parses that text. Another signer's collateral is refused by
    the signer rule; with the genuine chain Intel's verifier is reached and refuses these bytes,
    which are no quote."""
    dcap_qvl = pytest.importorskip("dcap_qvl")
    pki = pin(monkeypatch)
    served = []

    async def fetch(raw, source):
        return dcap_qvl.QuoteCollateralV3.from_json(json.dumps(served[-1]))

    monkeypatch.setattr(tdx_verify, "_fetch_collateral", fetch)
    served.append(collateral_document(pki.signer_chain, other_chains(pki)["platform-ca"]))
    with pytest.raises(tdx_verify.TdxQuoteRejected, match="is not Intel's: the QE Identity is signed by"):
        verify()
    served.append(collateral_document(pki.signer_chain, pki.signer_chain))
    with pytest.raises(tdx_verify.TdxQuoteRejected, match="Intel DCAP verification failed"):
        verify()
