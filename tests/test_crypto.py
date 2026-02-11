import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime as dt
from datetime import timezone

from latvian_einvoice.utils_crypto import (
    encrypt_payload_aes_gcm,
    decrypt_payload_aes_gcm,
    derive_encryption_fields,
    decrypt_key_with_private,
    decrypt_key_with_private_oaep_sha1,
)
from latvian_einvoice.api import receive
from latvian_einvoice.soap.envelope import build_envelope
from latvian_einvoice.attachments import Attachment


def _self_signed_cert():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(timezone.utc) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(timezone.utc) + dt.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def test_encrypt_payload_roundtrip():
    key = b"\x01" * 32
    plaintext = b"hello world"
    iv, cipher_with_tag = encrypt_payload_aes_gcm(key, plaintext, aad=b"meta")
    decrypted = decrypt_payload_aes_gcm(key, iv, cipher_with_tag, aad=b"meta")
    assert decrypted == plaintext


def test_derive_encryption_fields_and_decrypt():
    cert_pem, key_pem = _self_signed_cert()
    enc_key_b64, thumb_b64, sym_key, _iv = derive_encryption_fields(
        recipient_cert_pem=cert_pem, key_bytes=b"1" * 32
    )
    # Encrypted key can be decrypted with private key
    decrypted = decrypt_key_with_private(key_pem, enc_key_b64)
    assert decrypted == b"1" * 32
    # Thumbprint should be SHA1 of DER
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    sha1 = hashlib.sha1(der).digest()
    assert thumb_b64 == base64.b64encode(sha1).decode("ascii")


def test_derive_encryption_fields_oaep_cbc_key_blob_roundtrip():
    cert_pem, key_pem = _self_signed_cert()
    enc_key_b64, thumb_b64, sym_key, iv = derive_encryption_fields(
        recipient_cert_pem=cert_pem,
        key_bytes=b"\x01" * 32,
        iv_bytes=b"\x02" * 16,
        mode="oaep_cbc",
    )
    assert sym_key == b"\x01" * 32
    assert iv == b"\x02" * 16
    # Encrypted key blob can be OAEP-decrypted and parsed to the original key+IV.
    key_blob = decrypt_key_with_private_oaep_sha1(key_pem, enc_key_b64)
    parsed = receive._parse_div_encrypted_key(key_blob)
    assert parsed == (b"\x01" * 32, b"\x02" * 16)


def test_build_envelope_with_encryption_populates_ciphertext():
    cert_pem, key_pem = _self_signed_cert()
    enc_key_b64, thumb_b64, sym_key, _iv = derive_encryption_fields(recipient_cert_pem=cert_pem)
    attachments = [Attachment(filename="a.txt", content=b"ABC", content_type="text/plain")]
    envelope, attachments_input, _ = build_envelope(
        sender_e_address="_DEFAULT@90000000000",
        recipients_list=["0101"],
        document_kind_code="EINVOICE",
        subject="Test",
        body_text="Body",
        attachments=attachments,
        encryption_key_b64=enc_key_b64,
        recipient_thumbprint_b64=thumb_b64,
        symmetric_key_bytes=sym_key,
    )

    rec_entry = envelope["SenderDocument"]["SenderTransportMetadata"]["Recipients"]["RecipientEntry"][0]
    assert rec_entry["EncryptionInfo"]["Key"] == enc_key_b64
    assert rec_entry["EncryptionInfo"]["CertificateThumbprint"] == thumb_b64

    assert attachments_input is not None
    ai = attachments_input["AttachmentInput"][0]
    assert "IV" in ai and "CipherText" in ai
    # DigestValue in File should match sha512 of ciphertext
    file_entry = envelope["SenderDocument"]["DocumentMetadata"]["PayloadReference"]["File"][0]
    assert file_entry["MimeType"] == "application/octet-stream"
    digest_b64 = file_entry["Content"]["DigestValue"]
    ct = base64.b64decode(ai["CipherText"])
    assert digest_b64 == base64.b64encode(hashlib.sha512(ct).digest()).decode("ascii")


def test_build_envelope_keeps_text_plain_when_not_encrypted():
    attachments = [Attachment(filename="a.txt", content=b"ABC", content_type="text/plain")]
    envelope, attachments_input, _ = build_envelope(
        sender_e_address="_DEFAULT@90000000000",
        recipients_list=["0101"],
        document_kind_code="DOC_EMPTY",
        subject="Test",
        body_text="Body",
        attachments=attachments,
    )

    assert attachments_input is not None
    file_entry = envelope["SenderDocument"]["DocumentMetadata"]["PayloadReference"]["File"][0]
    assert file_entry["MimeType"] == "text/plain"
