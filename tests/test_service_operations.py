from types import SimpleNamespace

import pytest

from latvian_einvoice.api import cert_validate, directory, notifications, receive
from latvian_einvoice.api.server_confirmation import get_message_server_confirmation
from latvian_einvoice.errors import EAddressSoapError


class StaticTokenProvider:
    def get_token(self):
        return "test-token"


def _soap(service):
    return SimpleNamespace(service=service)


def test_notification_poll_collects_and_confirms_generic_items():
    class Service:
        def __init__(self):
            self.confirmed = []

        def GetNotificationList(self, **_kwargs):
            return {
                "Notifications": {
                    "Notification": [
                        {"Id": 10, "MessageId": "MESSAGE-001"},
                        {"Id": 11, "MessageId": "MESSAGE-002"},
                    ]
                },
                "HasMoreData": False,
            }

        def ConfirmNotificationList(self, NotificationIds, **_kwargs):
            self.confirmed.extend(NotificationIds)

    service = Service()
    result = notifications.poll_notifications(
        StaticTokenProvider(), _soap(service), max_items=10, auto_confirm=True
    )

    assert [item["Id"] for item in result["items"]] == [10, 11]
    assert result["confirmed_ids"] == [10, 11]
    assert service.confirmed == [10, 11]


def test_initial_directory_sync_paginates_without_oauth_token_collision():
    class Service:
        def __init__(self):
            self.tokens = []

        def GetInitialAddresseeRecordList(self, **kwargs):
            token = kwargs.get("Token")
            self.tokens.append(token)
            if token is None:
                return {
                    "AddresseeRecords": {"AddresseeRecord": [{"Version": 1}]},
                    "ContinuationToken": "next-page",
                }
            return {
                "AddresseeRecords": {"AddresseeRecord": [{"Version": 2}]},
                "ContinuationToken": "",
            }

    service = Service()
    result = directory.get_initial_addressee_record_list(
        StaticTokenProvider(), _soap(service), all_pages=True
    )

    assert result["record_count"] == 2
    assert result["latest_version"] == 2
    assert service.tokens == [None, "next-page"]


def test_initial_directory_sync_rejects_repeated_continuation_token():
    class Service:
        def GetInitialAddresseeRecordList(self, **_kwargs):
            return {
                "AddresseeRecords": {"AddresseeRecord": [{"Version": 1}]},
                "ContinuationToken": "same-page",
            }

    with pytest.raises(EAddressSoapError, match="pagination stalled"):
        directory.get_initial_addressee_record_list(
            StaticTokenProvider(), _soap(Service()), all_pages=True
        )


def test_changed_directory_sync_rejects_stalled_pagination():
    class Service:
        def GetChangedAddresseeRecordList(self, **_kwargs):
            return {
                "AddresseeRecords": {"AddresseeRecord": [{"Version": 5}]},
                "HasMoreData": True,
            }

    with pytest.raises(EAddressSoapError, match="pagination stalled"):
        directory.get_changed_addressee_record_list(
            StaticTokenProvider(), _soap(Service()), last_version=5, all_pages=True
        )


def test_server_confirmation_requires_message_id():
    with pytest.raises(EAddressSoapError, match="must not be empty"):
        get_message_server_confirmation(
            StaticTokenProvider(), _soap(SimpleNamespace()), " "
        )


def test_certificate_validation_uses_generic_lookup_values(monkeypatch):
    attempts = []

    def fake_search(_token_provider, _soap_client, value):
        attempts.append(value)
        return [{"EAddress": "_DEFAULT@40000000000"}] if value == "40000000000" else []

    monkeypatch.setattr(cert_validate, "search_addressee", fake_search)
    result = cert_validate.cert_validate(
        StaticTokenProvider(),
        _soap(SimpleNamespace()),
        ["", "40000000000", "40000000000"],
    )

    assert result["status"] == "ok"
    assert result["lookup_value"] == "40000000000"
    assert attempts == ["40000000000"]


def test_raw_get_message_response_uses_one_service_call():
    soap_xml = b"""\
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:uui="http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
               xmlns:div="http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0">
  <soap:Body>
    <uui:GetMessageOutput>
      <div:Envelope>
        <div:SenderDocument Id="SenderSection">
          <div:DocumentMetadata>
            <div:PayloadReference>
              <div:File>
                <div:Name>synthetic.xml</div:Name>
                <div:Compressed>false</div:Compressed>
                <div:Content><div:ContentReference>attachment-1</div:ContentReference></div:Content>
              </div:File>
            </div:PayloadReference>
          </div:DocumentMetadata>
          <div:SenderTransportMetadata>
            <div:Recipients>
              <div:RecipientEntry>
                <div:RecipientE-Address>_PRIVATE@40000000000</div:RecipientE-Address>
                <div:EncryptionInfo><div:Key>SYNTHETIC-KEY</div:Key></div:EncryptionInfo>
              </div:RecipientEntry>
            </div:Recipients>
          </div:SenderTransportMetadata>
          <div:Signatures>
            <div:Signature>
              <div:SignedInfo>
                <div:DigestMethod Algorithm="urn:synthetic:digest" />
              </div:SignedInfo>
            </div:Signature>
          </div:Signatures>
        </div:SenderDocument>
      </div:Envelope>
      <uui:Recipients><uui:string>_PRIVATE@40000000000</uui:string></uui:Recipients>
    </uui:GetMessageOutput>
  </soap:Body>
</soap:Envelope>
"""

    class RawSettings:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class RawClient:
        def settings(self, **_kwargs):
            return RawSettings()

    class Service:
        def __init__(self):
            self.calls = 0

        def GetMessage(self, **_kwargs):
            self.calls += 1
            return SimpleNamespace(content=soap_xml)

    service = Service()
    soap_client = SimpleNamespace(service=service, _client=RawClient())

    result = receive._fetch_message(
        StaticTokenProvider(), soap_client, "MESSAGE-001", include_attachments=True
    )

    assert service.calls == 1
    assert result["MessageId"] == "MESSAGE-001"
    assert result["Recipients"] == ["_PRIVATE@40000000000"]
    sender_document = result["Envelope"]["SenderDocument"]
    file_entry = sender_document["DocumentMetadata"]["PayloadReference"]["File"]
    assert file_entry["Name"] == "synthetic.xml"
    assert file_entry["Compressed"] is False
    recipient = sender_document["SenderTransportMetadata"]["Recipients"]["RecipientEntry"]
    assert recipient["EncryptionInfo"]["Key"] == "SYNTHETIC-KEY"
    digest_method = sender_document["Signatures"]["Signature"]["SignedInfo"]["DigestMethod"]
    assert digest_method["Algorithm"] == "urn:synthetic:digest"
