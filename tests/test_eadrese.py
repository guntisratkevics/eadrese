import pytest

pytest.importorskip("xmlsec")

import base64
import datetime as dt
from datetime import timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

from latvian_einvoice import (
    Attachment,
    EAddressClient,
    EAddressConfig,
    EDSClient,
    EAddressAuthError,
    EAddressSoapError,
)
from latvian_einvoice.api import send as send_api


class DummyResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
        self.content = b"{}"

    def json(self):
        return self._json


class DummySession:
    def __init__(self, post_responses, get_responses=None):
        self.verify = True
        self.headers = {}
        self.post_calls = []
        self.get_calls = []
        self._post_responses = list(post_responses)
        self._get_responses = list(get_responses or [])

    def post(self, url, data=None, auth=None, headers=None, timeout=None):
        self.post_calls.append({"url": url, "data": data, "auth": auth, "headers": headers})
        payload, status = self._post_responses[0]
        self._post_responses = self._post_responses[1:]
        return DummyResponse(payload, status_code=status)

    def get(self, url, headers=None, timeout=None):
        self.get_calls.append({"url": url, "headers": headers})
        if self._get_responses:
            payload, status = self._get_responses[0]
            self._get_responses = self._get_responses[1:]
        else:
            payload, status = ({}, 200)
        return DummyResponse(payload, status_code=status)


class StubService:
    def __init__(self):
        self.calls = []
        stub_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_numbers = stub_private_key.public_key().public_numbers()
        self._stub_modulus_b64 = base64.b64encode(
            public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
        ).decode()
        self._stub_exponent_b64 = base64.b64encode(
            public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
        ).decode()
        self._stub_thumbprint_b64 = base64.b64encode(b"\xAB" * 20).decode()

    def GetPublicKeyList(self, Token=None, **kwargs):
        recipients = kwargs.get("Recipients") or {}
        addresses = recipients.get("string") if isinstance(recipients, dict) else []
        if isinstance(addresses, str):
            addresses = [addresses]
        self.calls.append({"method": "GetPublicKeyList", "token": Token, "recipients": addresses})
        return {
            "RecipientPublicKey": [
                {
                    "EAddress": address,
                    "Modulus": self._stub_modulus_b64,
                    "Exponent": self._stub_exponent_b64,
                    "CertificateThumbprint": self._stub_thumbprint_b64,
                }
                for address in addresses
            ]
        }

    def SendMessage(self, Token, Envelope):
        self.calls.append({"method": "SendMessage", "token": Token, "envelope": Envelope})
        return {"MessageId": "stubbed-id"}

    def GetNextMessage(self, Token, IncludeAttachments):
        self.calls.append({"method": "GetNextMessage", "token": Token, "include_attachments": IncludeAttachments})
        return {"MessageId": "msg-1", "Subject": "Test"}

    def ConfirmMessage(self, Token=None, MessageId=None, RecipientConfirmationPart=None, **_kwargs):
        self.calls.append({"method": "ConfirmMessage", "token": Token, "message_id": MessageId})
        return None

    def SearchAddresseeUnit(self, Token=None, AddresseeUnitOwner=None, RegistrationNumber=None, **_kwargs):
        code = None
        addressee_owner_code = _kwargs.get("AddresseeOwnerCode")
        if addressee_owner_code:
            code = addressee_owner_code
        if isinstance(AddresseeUnitOwner, dict):
            code = AddresseeUnitOwner.get("Code")
        if not code:
            code = RegistrationNumber
        self.calls.append(
            {
                "method": "SearchAddresseeUnit",
                "token": Token,
                "code": code,
            }
        )
        return {"AddresseeUnits": {"AddresseeUnit": [{"Owner": {"Code": code}, "EAddress": "TEST_EADDR"}]}}


class SearchTypeErrorFallbackService:
    def __init__(self):
        self.calls = []

    def SearchAddresseeUnit(self, Token=None, AddresseeOwnerCode=None, AddresseeUnitOwner=None, **_kwargs):
        payload = {}
        if AddresseeOwnerCode is not None:
            payload["AddresseeOwnerCode"] = AddresseeOwnerCode
        if AddresseeUnitOwner is not None:
            payload["AddresseeUnitOwner"] = AddresseeUnitOwner
        self.calls.append({"token": Token, "payload": payload})

        if AddresseeOwnerCode:
            raise TypeError("unexpected payload shape")

        if isinstance(AddresseeUnitOwner, dict):
            code = AddresseeUnitOwner.get("Code")
            return {"AddresseeUnits": {"AddresseeUnit": [{"Owner": {"Code": code}, "EAddress": "TEST_EADDR"}]}}

        raise TypeError("missing supported payload")


class SearchBusinessFaultService:
    def __init__(self):
        self.calls = []

    def SearchAddresseeUnit(self, Token=None, AddresseeOwnerCode=None, AddresseeUnitOwner=None, **_kwargs):
        payload = {}
        if AddresseeOwnerCode is not None:
            payload["AddresseeOwnerCode"] = AddresseeOwnerCode
        if AddresseeUnitOwner is not None:
            payload["AddresseeUnitOwner"] = AddresseeUnitOwner
        self.calls.append({"token": Token, "payload": payload})

        if AddresseeOwnerCode:
            raise RuntimeError("Nav atļauts pārvaldīt norādīto adresātu.")

        return {"AddresseeUnits": {"AddresseeUnit": [{"Owner": {"Code": "fallback"}, "EAddress": "TEST_EADDR"}]}}


class ChunkedSendStubService:
    def __init__(self):
        self.calls = []

    def SendMessage(self, *args, **kwargs):
        raise AssertionError("SendMessage should not be used for large attachment flow")

    def InitSendMessage(
        self,
        Token=None,
        MessageClientId=None,
        SenderEAddress=None,
        AttachmentsInput=None,
        **_kwargs,
    ):
        self.calls.append(
            {
                "method": "InitSendMessage",
                "Token": Token,
                "MessageClientId": MessageClientId,
                "SenderEAddress": SenderEAddress,
                "AttachmentsInput": AttachmentsInput,
            }
        )
        return {"MessageId": "chunked-server-id"}

    def SendAttachmentSection(
        self,
        Token=None,
        MessageId=None,
        ContentId=None,
        SectionIndex=None,
        Contents=None,
        **_kwargs,
    ):
        self.calls.append(
            {
                "method": "SendAttachmentSection",
                "Token": Token,
                "MessageId": MessageId,
                "ContentId": ContentId,
                "SectionIndex": SectionIndex,
                "Contents": Contents,
            }
        )
        return {}

    def CompleteSendMessage(self, Token=None, MessageId=None, Envelope=None, **_kwargs):
        self.calls.append(
            {
                "method": "CompleteSendMessage",
                "Token": Token,
                "MessageId": MessageId,
                "Envelope": Envelope,
            }
        )
        return {}

def _self_signed(tmpdir):
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
    kf = tmpdir / "key.pem"
    cf = tmpdir / "cert.pem"
    kf.write_bytes(key_pem)
    cf.write_bytes(cert_pem)
    return kf, cf

def test_eadrese_send_message_uses_stub_service():
    session = DummySession([({"access_token": "token123", "expires_in": 120}, 200)])
    svc = StubService()
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False)
    client = EAddressClient(cfg, session=session, service=svc)

    attachment = Attachment(filename="sample.xml", content=b"<x/>", content_type="application/xml")
    msg_id = client.send_message("0101", document_kind_code="DOC_EMPTY", attachments=[attachment])

    assert msg_id == "stubbed-id"
    send_call = next(call for call in svc.calls if call["method"] == "SendMessage")
    assert send_call["token"] == "token123"
    envelope = send_call["envelope"]
    assert envelope["SenderDocument"]["SenderTransportMetadata"]["Recipients"]["RecipientEntry"][0]["RecipientE-Address"] == "0101"
    payload_files = envelope["SenderDocument"]["DocumentMetadata"]["PayloadReference"]["File"]
    assert payload_files[0]["Name"] == "sample.xml"


def test_eadrese_large_attachment_uses_chunked_send_flow():
    session = DummySession([({"access_token": "token123", "expires_in": 120}, 200)])
    svc = ChunkedSendStubService()
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False)
    client = EAddressClient(cfg, session=session, service=svc)

    large_content = b"A" * (4 * 1024 * 1024 + 1024)
    attachment = Attachment(
        filename="large.bin",
        content=large_content,
        content_type="application/octet-stream",
    )

    msg_id = client.send_message(
        "0101",
        document_kind_code="DOC_EMPTY",
        subject="Large attachment test",
        body_text="Chunked send test",
        attachments=[attachment],
    )

    assert msg_id == "chunked-server-id"
    methods = [call["method"] for call in svc.calls]
    assert methods[0] == "InitSendMessage"
    assert methods[-1] == "CompleteSendMessage"

    init_items = svc.calls[0]["AttachmentsInput"]["AttachmentInput"]
    assert init_items[0]["ContentId"] == "0"
    assert "Contents" not in init_items[0]

    section_calls = [call for call in svc.calls if call["method"] == "SendAttachmentSection"]
    assert len(section_calls) == 2
    assert section_calls[0]["SectionIndex"] == 0
    assert section_calls[1]["SectionIndex"] == 1
    assert isinstance(section_calls[0]["Contents"], bytes)
    assert isinstance(section_calls[1]["Contents"], bytes)


def test_eadrese_large_attachment_exact_multiple_sends_terminal_section():
    session = DummySession([({"access_token": "token123", "expires_in": 120}, 200)])
    svc = ChunkedSendStubService()
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False)
    client = EAddressClient(cfg, session=session, service=svc)

    exact_multiple = b"B" * (8 * 1024 * 1024)
    attachment = Attachment(
        filename="exact.bin",
        content=exact_multiple,
        content_type="application/octet-stream",
    )

    msg_id = client.send_message(
        "0101",
        document_kind_code="DOC_EMPTY",
        subject="Large attachment exact test",
        body_text="Chunked send terminal section test",
        attachments=[attachment],
    )

    assert msg_id == "chunked-server-id"
    section_calls = [call for call in svc.calls if call["method"] == "SendAttachmentSection"]
    assert len(section_calls) == 3
    assert section_calls[0]["SectionIndex"] == 0
    assert section_calls[1]["SectionIndex"] == 1
    assert section_calls[2]["SectionIndex"] == 2
    assert isinstance(section_calls[0]["Contents"], bytes)
    assert isinstance(section_calls[1]["Contents"], bytes)
    assert section_calls[2]["Contents"] is None


def test_eadrese_chunked_send_inline_contents_are_bytes():
    session = DummySession([({"access_token": "token123", "expires_in": 120}, 200)])
    svc = ChunkedSendStubService()
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False)
    client = EAddressClient(cfg, session=session, service=svc)

    larger = Attachment(
        filename="large.bin",
        content=b"L" * (3 * 1024 * 1024),
        content_type="application/octet-stream",
    )
    smaller = Attachment(
        filename="small.bin",
        content=b"S" * (2 * 1024 * 1024),
        content_type="application/octet-stream",
    )

    msg_id = client.send_message(
        "0101",
        document_kind_code="DOC_EMPTY",
        subject="Chunked mixed send",
        body_text="Chunked mixed send test",
        attachments=[larger, smaller],
    )

    assert msg_id == "chunked-server-id"
    init_items = svc.calls[0]["AttachmentsInput"]["AttachmentInput"]
    assert "Contents" not in init_items[0]
    assert isinstance(init_items[1]["Contents"], bytes)


def test_base64_payload_fields_are_normalized_to_bytes():
    payload = {
        "DigestValue": "AQID",
        "Description": "keep-as-string",
        "Recipients": {
            "RecipientEntry": [
                {
                    "EncryptionInfo": {
                        "Key": "AQIDBA==",
                        "CertificateThumbprint": "AQI=",
                    }
                }
            ]
        },
        "AttachmentInput": [{"ContentId": "0", "Contents": "QQ=="}],
    }

    normalized = send_api._normalize_base64_payload(payload)

    assert normalized["DigestValue"] == b"\x01\x02\x03"
    assert normalized["Description"] == "keep-as-string"
    assert normalized["Recipients"]["RecipientEntry"][0]["EncryptionInfo"]["Key"] == b"\x01\x02\x03\x04"
    assert normalized["Recipients"]["RecipientEntry"][0]["EncryptionInfo"]["CertificateThumbprint"] == b"\x01\x02"
    assert normalized["AttachmentInput"][0]["Contents"] == b"A"


def test_eadrese_receive_confirm_search(tmp_path):
    # 3 token calls: get_next_message, confirm_message, search_addressee
    session = DummySession([
        ({"access_token": "token123", "expires_in": 120}, 200),
        ({"access_token": "token123", "expires_in": 120}, 200),
        ({"access_token": "token123", "expires_in": 120}, 200),
    ])
    svc = StubService()
    key_file, cert_file = _self_signed(tmp_path)
    cfg = EAddressConfig(
        client_id="cid",
        client_secret="secret",
        verify_ssl=False,
        certificate=cert_file,
        private_key=key_file,
    )
    client = EAddressClient(cfg, session=session, service=svc)

    # 1. Get next message
    msg = client.get_next_message()
    assert msg["MessageId"] == "msg-1"
    assert svc.calls[0]["method"] == "GetNextMessage"

    # 2. Confirm message
    client.confirm_message("msg-1")
    assert svc.calls[1]["method"] == "ConfirmMessage"
    assert svc.calls[1]["message_id"] == "msg-1"

    # 3. Search addressee
    results = client.search_addressee("4000123123")
    assert len(results) == 1
    assert results[0]["Owner"]["Code"] == "4000123123"
    assert svc.calls[2]["method"] == "SearchAddresseeUnit"
    assert svc.calls[2]["code"] == "4000123123"


def test_search_addressee_falls_back_on_type_error():
    session = DummySession([({"access_token": "token123", "expires_in": 120}, 200)])
    svc = SearchTypeErrorFallbackService()
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False)
    client = EAddressClient(cfg, session=session, service=svc)

    results = client.search_addressee("4000123123")

    assert len(results) == 1
    assert results[0]["Owner"]["Code"] == "4000123123"
    assert any(call["payload"].get("AddresseeOwnerCode") == "4000123123" for call in svc.calls)
    assert any(
        isinstance(call["payload"].get("AddresseeUnitOwner"), dict)
        and call["payload"]["AddresseeUnitOwner"].get("Code") == "4000123123"
        for call in svc.calls
    )


def test_search_addressee_does_not_mask_business_fault():
    session = DummySession([({"access_token": "token123", "expires_in": 120}, 200)])
    svc = SearchBusinessFaultService()
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False)
    client = EAddressClient(cfg, session=session, service=svc)

    with pytest.raises(EAddressSoapError) as exc_info:
        client.search_addressee("4000123123")

    assert "Nav atļauts pārvaldīt norādīto adresātu." in str(exc_info.value)

    assert len(svc.calls) == 1
    assert svc.calls[0]["payload"].get("AddresseeOwnerCode") == "4000123123"
    assert "AddresseeUnitOwner" not in svc.calls[0]["payload"]


def test_eadrese_vid_auto_logic():
    session = DummySession([({"access_token": "token123", "expires_in": 120}, 200)])
    svc = StubService()
    # Enable VID auto logic
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False, vid_subaddress_auto=True)
    client = EAddressClient(cfg, session=session, service=svc)

    attachment = Attachment(filename="inv.xml", content=b"<inv/>", content_type="application/xml")

    # Send invoice to Client
    # Should automatically append VID address as secondary recipient
    client.send_message("010101-11111", document_kind_code="EINVOICE", attachments=[attachment])

    send_call = next(call for call in svc.calls if call["method"] == "SendMessage")
    envelope = send_call["envelope"]
    # Check recipients structure
    recipient_structs = envelope["SenderDocument"]["SenderTransportMetadata"]["Recipients"]["RecipientEntry"]

    # We expect 2 recipients: Client + VID
    assert len(recipient_structs) == 2
    addrs = {r["RecipientE-Address"] for r in recipient_structs}
    assert "010101-11111" in addrs
    assert "VID_EREKINI_PROD@90000069281" in addrs  # Default PROD address since token url is standard


def test_eadrese_auth_error():
    # 401 response for token
    session = DummySession([({"error": "invalid_client"}, 401)])
    svc = StubService()
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False)
    client = EAddressClient(cfg, session=session, service=svc)

    try:
        client.get_next_message()
    except EAddressAuthError:
        pass  # Expected
    except Exception as e:
        assert False, f"Raised wrong exception type: {type(e)}"
    else:
        assert False, "Should have raised EAddressAuthError"
