import base64
import datetime as dt
import hashlib
from datetime import timezone
from pathlib import Path

import pytest

pytest.importorskip("xmlsec")

from lxml import etree
from lxml.etree import QName
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

from latvian_einvoice.soap.client import DIV_NS, SenderDocumentSigner
from latvian_einvoice.api import confirm


DS_NS = "http://www.w3.org/2000/09/xmldsig#"
UUI_NS = "http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"


def _self_signed(tmpdir: Path) -> tuple[Path, Path, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "LV"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(timezone.utc) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(timezone.utc) + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_file = tmpdir / "key.pem"
    cert_file = tmpdir / "cert.pem"
    key_file.write_bytes(key_pem)
    cert_file.write_bytes(cert_pem)
    return key_file, cert_file, cert_pem


def _b64_sha512(data: bytes) -> str:
    return base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def _find_by_id(root: etree._Element, id_value: str) -> etree._Element:
    matches = root.xpath(".//*[@Id=$id]", id=id_value)
    assert matches, f"Missing element with Id={id_value}"
    return matches[0]


def test_sender_document_signer_produces_verifiable_signature(tmp_path):
    key_file, cert_file, cert_pem = _self_signed(tmp_path)

    # Minimal SOAP envelope containing a DIV EnvelopeStructure (SendMessageInput).
    soap = etree.Element(QName(SOAP_ENV, "Envelope"), nsmap={"soap": SOAP_ENV})
    body = etree.SubElement(soap, QName(SOAP_ENV, "Body"))

    # Intentionally prefix UUI to exercise namespace normalization logic.
    send_input = etree.SubElement(body, QName(UUI_NS, "SendMessageInput"), nsmap={"uui": UUI_NS})
    div_env = etree.SubElement(send_input, QName(DIV_NS, "Envelope"), nsmap={"cm": DIV_NS})
    sender_doc = etree.SubElement(div_env, QName(DIV_NS, "SenderDocument"))
    sender_doc.set("Id", "SenderSection")
    etree.SubElement(sender_doc, QName(DIV_NS, "SenderTransportMetadata"))
    signatures = etree.SubElement(div_env, QName(DIV_NS, "Signatures"))
    etree.SubElement(signatures, QName(DS_NS, "Signature"))  # placeholder

    signer = SenderDocumentSigner(str(key_file), str(cert_file), sig_hash="sha512")
    signed, _headers = signer.egress(soap, {}, None, None)

    signed_div_env = signed.find(f".//{{{DIV_NS}}}Envelope")
    assert signed_div_env is not None
    # Verify as a standalone DIV envelope (server-side typically validates the DIV subtree,
    # not the full SOAP envelope namespace context).
    standalone = etree.fromstring(etree.tostring(signed_div_env))
    # Match signing context: the signer canonicalizes SignedInfo on a cleaned standalone DIV envelope,
    # while libxml2 C14N includes in-scope (even unused) namespaces if present.
    etree.cleanup_namespaces(standalone)
    signature = standalone.find(f".//{{{DS_NS}}}Signature")
    assert signature is not None

    # SenderDocument reference must use exclusive C14N transform.
    refs = signature.findall(f".//{{{DS_NS}}}Reference")
    sender_ref = next(r for r in refs if r.get("URI") == "#SenderSection")
    sender_ref_transform = sender_ref.find(f".//{{{DS_NS}}}Transform")
    assert sender_ref_transform is not None
    assert sender_ref_transform.get("Algorithm") == "http://www.w3.org/2001/10/xml-exc-c14n#"

    # Digest verification: SenderDocument (exclusive C14N).
    sender_target = _find_by_id(standalone, "SenderSection")
    sender_c14n = etree.tostring(sender_target, method="c14n", exclusive=True, with_comments=False)
    sender_dv = sender_ref.findtext(f".//{{{DS_NS}}}DigestValue")
    assert sender_dv == _b64_sha512(sender_c14n)

    # Digest verification: SignedProperties (exclusive C14N with ds inclusive prefixes).
    props_ref = next(r for r in refs if r.get("Type") == "http://uri.etsi.org/01903#SignedProperties")
    props_id = (props_ref.get("URI") or "")[1:]
    props_target = _find_by_id(signature, props_id)
    props_c14n = etree.tostring(
        props_target,
        method="c14n",
        exclusive=True,
        with_comments=False,
        inclusive_ns_prefixes=["ds"],
    )
    props_dv = props_ref.findtext(f".//{{{DS_NS}}}DigestValue")
    assert props_dv == _b64_sha512(props_c14n)

    # Signature verification over SignedInfo (inclusive C14N).
    signed_info = signature.find(f".//{{{DS_NS}}}SignedInfo")
    assert signed_info is not None
    si_c14n = etree.tostring(signed_info, method="c14n", exclusive=False, with_comments=False)
    sig_value_b64 = signature.findtext(f".//{{{DS_NS}}}SignatureValue")
    assert sig_value_b64
    sig_value = base64.b64decode(sig_value_b64)
    cert_obj = x509.load_pem_x509_certificate(cert_pem)
    cert_obj.public_key().verify(sig_value, si_c14n, asym_padding.PKCS1v15(), hashes.SHA512())


def test_confirm_combined_signature_produces_verifiable_signature(tmp_path):
    key_file, cert_file, cert_pem = _self_signed(tmp_path)
    signer = SenderDocumentSigner(str(key_file), str(cert_file), sig_hash="sha512")

    combined = etree.Element(QName(DIV_NS, "RecipientConfirmationPart"), nsmap={None: DIV_NS})
    sender_doc = etree.SubElement(combined, QName(DIV_NS, "SenderDocument"))
    sender_doc.set("Id", "SenderSection")
    etree.SubElement(combined, QName(DIV_NS, "ServerTransportMetadata")).set("Id", "ServerSection")
    confirmations = etree.SubElement(combined, QName(DIV_NS, "RecipientConfirmations"))
    entry = etree.SubElement(confirmations, QName(DIV_NS, "ConfirmationEntry"))
    entry.set("Id", "ConfirmEntry1")
    etree.SubElement(entry, QName(DIV_NS, "Status")).text = "RecipientAccepted"
    etree.SubElement(combined, QName(DIV_NS, "Signatures"))

    confirm._sign_combined_envelope(
        combined,
        signer,
        signature_id="ConfirmSignature",
        signed_section_ids=["SenderSection", "ServerSection", "ConfirmEntry1"],
    )

    signature = combined.find(f".//{{{DS_NS}}}Signature")
    assert signature is not None

    refs = signature.findall(f".//{{{DS_NS}}}Reference")
    # Verify section digests (inclusive C14N).
    for section_id in ("SenderSection", "ServerSection", "ConfirmEntry1"):
        ref = next(r for r in refs if r.get("URI") == f"#{section_id}")
        target = _find_by_id(combined, section_id)
        c14n = etree.tostring(target, method="c14n", exclusive=False, with_comments=False)
        dv = ref.findtext(f".//{{{DS_NS}}}DigestValue")
        assert dv == _b64_sha512(c14n)

    # Verify SignedProperties digest.
    props_ref = next(r for r in refs if r.get("Type") == "http://uri.etsi.org/01903#SignedProperties")
    props_id = (props_ref.get("URI") or "")[1:]
    props_target = _find_by_id(signature, props_id)
    props_c14n = etree.tostring(
        props_target,
        method="c14n",
        exclusive=True,
        with_comments=False,
        inclusive_ns_prefixes=["ds"],
    )
    props_dv = props_ref.findtext(f".//{{{DS_NS}}}DigestValue")
    assert props_dv == _b64_sha512(props_c14n)

    # Verify RSA signature over SignedInfo.
    signed_info = signature.find(f".//{{{DS_NS}}}SignedInfo")
    assert signed_info is not None
    si_c14n = etree.tostring(signed_info, method="c14n", exclusive=False, with_comments=False)
    sig_value_b64 = signature.findtext(f".//{{{DS_NS}}}SignatureValue")
    assert sig_value_b64
    sig_value = base64.b64decode(sig_value_b64)
    cert_obj = x509.load_pem_x509_certificate(cert_pem)
    cert_obj.public_key().verify(sig_value, si_c14n, asym_padding.PKCS1v15(), hashes.SHA512())

