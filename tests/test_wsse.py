import tempfile
from pathlib import Path
from lxml import etree
from lxml.etree import QName
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime as dt
from datetime import timezone

import pytest
import xmlsec

from latvian_einvoice.soap.client import SignOnlySignature
from zeep import ns


def _self_signed_cert(tmpdir: Path):
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
    return key_file, cert_file


def test_signonlysignature_adds_signature_and_headers(tmp_path):
    key_file, cert_file = _self_signed_cert(tmp_path)
    signer = SignOnlySignature(
        str(key_file),
        str(cert_file),
        add_timestamp=True,
        verify_response=False,
    )

    soap_env = "http://schemas.xmlsoap.org/soap/envelope/"
    envelope = etree.Element(QName(soap_env, "Envelope"), nsmap={"soap": soap_env})
    header = etree.SubElement(envelope, QName(soap_env, "Header"))
    body = etree.SubElement(envelope, QName(soap_env, "Body"))
    etree.SubElement(body, "TestPayload").text = "ok"

    envelope, _ = signer.apply(envelope, headers={})

    security = envelope.find(f".//{{{ns.WSSE}}}Security")
    assert security is not None
    signature = security.find(f".//{{{ns.DS}}}Signature")
    assert signature is not None
    bst = security.find(f".//{{{ns.WSSE}}}BinarySecurityToken")
    assert bst is not None
    ts = security.find(f".//{{{ns.WSU}}}Timestamp")
    assert ts is not None
