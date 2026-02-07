import pytest

pytest.importorskip("xmlsec")

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

    def SendMessage(self, Token, Envelope):
        self.calls.append({"method": "SendMessage", "token": Token, "envelope": Envelope})
        return {"MessageId": "stubbed-id"}

    def GetNextMessage(self, Token, IncludeAttachments):
        self.calls.append({"method": "GetNextMessage", "token": Token, "include_attachments": IncludeAttachments})
        return {"MessageId": "msg-1", "Subject": "Test"}

    def ConfirmMessage(self, Token=None, MessageId=None, RecipientConfirmationPart=None, **_kwargs):
        self.calls.append({"method": "ConfirmMessage", "token": Token, "message_id": MessageId})
        return None

    def SearchAddresseeUnit(self, Token, RegistrationNumber):
        self.calls.append({"method": "SearchAddresseeUnit", "token": Token, "registration_number": RegistrationNumber})
        return {"Addressee": [{"Name": "Tester", "RegNr": RegistrationNumber}]}

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
    msg_id = client.send_message("0101", attachments=[attachment])

    assert msg_id == "stubbed-id"
    assert svc.calls[0]["token"] == "token123"
    envelope = svc.calls[0]["envelope"]
    assert envelope["SenderDocument"]["SenderTransportMetadata"]["Recipients"]["RecipientEntry"][0]["RecipientE-Address"] == "0101"
    payload_files = envelope["SenderDocument"]["DocumentMetadata"]["PayloadReference"]["File"]
    assert payload_files[0]["Name"] == "sample.xml"


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
    assert results[0]["Name"] == "Tester"
    assert svc.calls[2]["method"] == "SearchAddresseeUnit"
    assert svc.calls[2]["registration_number"] == "4000123123"


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
    
    envelope = svc.calls[0]["envelope"]
    # Check recipients structure
    recipient_structs = envelope["SenderDocument"]["SenderTransportMetadata"]["Recipients"]["RecipientEntry"]
    
    # We expect 2 recipients: Client + VID
    assert len(recipient_structs) == 2
    addrs = {r["RecipientE-Address"] for r in recipient_structs}
    assert "010101-11111" in addrs
    assert "VID_EREKINI_PROD@90000069281" in addrs # Default PROD address since token url is standard

    
def test_eadrese_auth_error():
    # 401 response for token
    session = DummySession([({"error": "invalid_client"}, 401)])
    svc = StubService()
    cfg = EAddressConfig(client_id="cid", client_secret="secret", verify_ssl=False)
    client = EAddressClient(cfg, session=session, service=svc)

    try:
        client.get_next_message()
    except EAddressAuthError:
        pass # Expected
    except Exception as e:
        assert False, f"Raised wrong exception type: {type(e)}"
    else:
        assert False, "Should have raised EAddressAuthError"
