import base64
import os
import datetime as dt
from datetime import timezone
import gzip
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID

from latvian_einvoice.api import receive
from latvian_einvoice.utils_crypto import (
    encrypt_payload_aes_cbc_pkcs5,
    encrypt_payload_aes_gcm,
    derive_encryption_fields,
    thumbprint_sha1_b64,
)


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
    enc_key_b64, thumb_b64, sym_key, _iv = derive_encryption_fields(recipient_cert_pem=cert_pem)
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


def test_get_next_message_decrypts_div_aes_cbc(tmp_path, monkeypatch):
    cert_pem, key_pem = _self_signed_cert()
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)
    key_file = tmp_path / "priv.pem"
    key_file.write_bytes(key_pem)

    aes_key = b"\x01" * 32
    iv = b"\x02" * 16
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(b"cbc-secret") + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    key_blob = bytes([len(aes_key)]) + aes_key + iv
    cert = x509.load_pem_x509_certificate(cert_pem)
    encrypted_key = cert.public_key().encrypt(
        key_blob,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    enc_key_b64 = base64.b64encode(encrypted_key).decode("ascii")
    thumb_b64 = thumbprint_sha1_b64(cert_pem)

    response_payload = {
        "MessageId": "msg-456",
        "Envelope": {
            "SenderDocument": {
                "DocumentMetadata": {
                    "PayloadReference": {
                        "File": [
                            {
                                "Name": "payload.txt",
                                "Content": {"ContentReference": "0"},
                                "Compressed": False,
                            }
                        ]
                    }
                },
                "SenderTransportMetadata": {
                    "Recipients": {
                        "RecipientEntry": [
                            {"EncryptionInfo": {"Key": enc_key_b64, "CertificateThumbprint": thumb_b64}}
                        ]
                    }
                },
            }
        },
        "AttachmentsOutput": {
            "AttachmentOutput": [
                {
                    "ContentId": "0",
                    "Contents": base64.b64encode(ciphertext).decode("ascii"),
                }
            ]
        },
    }

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
        certificate_path=cert_file,
        auto_confirm=True,
    )

    decrypted = result["AttachmentsOutput"]["AttachmentOutput"][0]["DecryptedContent"]
    assert decrypted == b"cbc-secret"
    assert confirm_calls == ["msg-456"]


def test_get_message_list_parses_headers():
    class Svc:
        def __init__(self):
            self.calls = []

        def GetMessageList(self, MaxResultCount=None):
            self.calls.append({"MaxResultCount": MaxResultCount})
            return {
                "MessageHeaders": {
                    "MessageHeader": [
                        {"MessageId": "m1", "SenderEAddress": "S1"},
                        {"MessageId": "m2", "SenderEAddress": "S2"},
                    ]
                },
                "HasMoreData": False,
            }

    svc = Svc()
    client = DummySoapClient(svc)
    headers = receive.get_message_list(None, client, max_result_count=2)
    assert [h["MessageId"] for h in headers] == ["m1", "m2"]
    assert svc.calls == [{"MaxResultCount": 2}]


def test_get_next_message_falls_back_to_get_message_list_and_get_message():
    class Svc:
        def __init__(self):
            self.calls = []

        def GetMessageList(self, MaxResultCount=None):
            self.calls.append(("GetMessageList", MaxResultCount))
            return {"MessageHeaders": {"MessageHeader": {"MessageId": "msg-1"}}}

        # Intentionally no IncludeAttachments argument to exercise TypeError fallback.
        def GetMessage(self, MessageId=None):
            self.calls.append(("GetMessage", MessageId))
            return {"Envelope": {"SenderDocument": {"SenderTransportMetadata": {"Recipients": {"RecipientEntry": []}}}}}

    svc = Svc()
    client = DummySoapClient(svc)
    result = receive.get_next_message(
        None,
        client,
        include_attachments=False,
        auto_confirm=False,
    )
    assert result["MessageId"] == "msg-1"
    assert svc.calls == [("GetMessageList", 1), ("GetMessage", "msg-1")]


def test_get_message_attaches_separate_attachment_sections():
    chunk0 = b"AAA"
    chunk1 = b"BBB"

    class Svc:
        def __init__(self):
            self.section_calls = []

        # Intentionally no IncludeAttachments argument to exercise TypeError fallback.
        def GetMessage(self, MessageId=None):
            return {
                "Envelope": {"SenderDocument": {"SenderTransportMetadata": {"Recipients": {"RecipientEntry": []}}}},
                "AttachmentsOutput": {
                    "AttachmentOutput": [
                        {
                            "ContentId": "0",
                            "IsSeparateCall": True,
                            "SectionCount": 2,
                        }
                    ]
                },
            }

        def GetAttachmentSection(self, MessageId=None, ContentId=None, SectionIndex=None):
            self.section_calls.append((MessageId, ContentId, SectionIndex))
            part = chunk0 if int(SectionIndex) == 0 else chunk1
            return {"Contents": base64.b64encode(part).decode("ascii")}

    svc = Svc()
    client = DummySoapClient(svc)
    result = receive.get_message(
        None,
        client,
        message_id="msg-999",
        include_attachments=True,
        auto_confirm=False,
    )

    contents_b64 = result["AttachmentsOutput"]["AttachmentOutput"][0]["Contents"]
    assert base64.b64decode(contents_b64) == chunk0 + chunk1
    assert svc.section_calls == [("msg-999", "0", 0), ("msg-999", "0", 1)]


def test_get_message_decrypts_compressed_div_aes_cbc(tmp_path):
    cert_pem, key_pem = _self_signed_cert()
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)
    key_file = tmp_path / "priv.pem"
    key_file.write_bytes(key_pem)

    aes_key = b"\x11" * 32
    iv = b"\x22" * 16
    plaintext = b"hello-compressed"
    gz = gzip.compress(plaintext)
    ciphertext = encrypt_payload_aes_cbc_pkcs5(aes_key, iv, gz)

    key_blob = bytes([len(aes_key)]) + aes_key + iv
    cert = x509.load_pem_x509_certificate(cert_pem)
    encrypted_key = cert.public_key().encrypt(
        key_blob,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    enc_key_b64 = base64.b64encode(encrypted_key).decode("ascii")
    thumb_b64 = thumbprint_sha1_b64(cert_pem)

    class Svc:
        # Intentionally no IncludeAttachments argument to exercise TypeError fallback.
        def GetMessage(self, MessageId=None):
            return {
                "Envelope": {
                    "SenderDocument": {
                        "DocumentMetadata": {
                            "PayloadReference": {
                                "File": [
                                    {
                                        "Name": "payload.txt",
                                        "Content": {"ContentReference": "0"},
                                        "Compressed": True,
                                    }
                                ]
                            }
                        },
                        "SenderTransportMetadata": {
                            "Recipients": {
                                "RecipientEntry": [
                                    {
                                        "EncryptionInfo": {
                                            "Key": enc_key_b64,
                                            "CertificateThumbprint": thumb_b64,
                                        }
                                    }
                                ]
                            }
                        },
                    }
                },
                "AttachmentsOutput": {
                    "AttachmentOutput": [
                        {
                            "ContentId": "0",
                            "Contents": base64.b64encode(ciphertext).decode("ascii"),
                        }
                    ]
                },
            }

    svc = Svc()
    client = DummySoapClient(svc)
    result = receive.get_message(
        None,
        client,
        message_id="msg-777",
        include_attachments=True,
        private_key_path=key_file,
        certificate_path=cert_file,
        auto_confirm=False,
    )
    att = result["AttachmentsOutput"]["AttachmentOutput"][0]
    assert att["Name"] == "payload.txt"
    assert att["DecryptedContent"] == plaintext

