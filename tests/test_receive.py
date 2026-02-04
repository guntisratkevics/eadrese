import base64
import os
import datetime as dt
from datetime import timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

from latvian_einvoice.api import receive
from latvian_einvoice.utils_crypto import encrypt_payload_aes_gcm, derive_encryption_fields


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


class DummyTokenProvider:
    def get_token(self):
        return "token123"


class DummyService:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def GetNextMessage(self, Token, IncludeAttachments=True):
        self.calls.append({"token": Token, "include": IncludeAttachments})
        return self.response


class DummySoapClient:
    def __init__(self, service):
        self.service = service


def test_get_next_message_decrypts_attachments_and_confirms(tmp_path, monkeypatch):
    cert_pem, key_pem = _self_signed_cert()
    enc_key_b64, thumb_b64, sym_key = derive_encryption_fields(recipient_cert_pem=cert_pem)
    iv, ct = encrypt_payload_aes_gcm(sym_key, b"secret-bytes")

    response_payload = {
        "MessageId": "msg-123",
        "Envelope": {
            "SenderDocument": {
                "SenderTransportMetadata": {
                    "Recipients": {
                        "RecipientEntry": [
                            {"EncryptionInfo": {"Key": enc_key_b64, "CertificateThumbprint": thumb_b64}}
                        ]
                    }
                }
            }
        },
        "AttachmentsOutput": {
            "AttachmentOutput": [
                {
                    "IV": base64.b64encode(iv).decode("ascii"),
                    "CipherText": base64.b64encode(ct).decode("ascii"),
                }
            ]
        },
    }

    key_file = tmp_path / "priv.pem"
    key_file.write_bytes(key_pem)

    confirm_calls = []

    def _confirm(tp, sc, msg_id):
        confirm_calls.append(msg_id)

    monkeypatch.setattr(receive, "confirm_message", _confirm)

    svc = DummyService(response_payload)
    client = DummySoapClient(svc)
    token_provider = DummyTokenProvider()

    result = receive.get_next_message(
        token_provider,
        client,
        include_attachments=True,
        private_key_path=key_file,
        auto_confirm=True,
    )

    assert svc.calls[0]["token"] == "token123"
    decrypted = result["AttachmentsOutput"]["AttachmentOutput"][0]["DecryptedContent"]
    assert decrypted == b"secret-bytes"
    assert confirm_calls == ["msg-123"]
    assert result["Confirmed"] is True

