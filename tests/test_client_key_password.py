from types import SimpleNamespace

from latvian_einvoice import EAddressClient, EAddressConfig
from latvian_einvoice.api import receive


def _client_with_password() -> EAddressClient:
    client = object.__new__(EAddressClient)
    client.cfg = EAddressConfig(
        client_id="client",
        client_secret="secret",
        key_password="encrypted-key-password",
    )
    client.token_provider = SimpleNamespace()
    client.soap_client = SimpleNamespace()
    return client


def test_get_next_message_forwards_encoded_key_password(monkeypatch):
    captured = {}

    def fake_get_next_message(*_args, **kwargs):
        captured.update(kwargs)
        return None

    monkeypatch.setattr(receive, "get_next_message", fake_get_next_message)

    _client_with_password().get_next_message()

    assert captured["key_password"] == b"encrypted-key-password"


def test_get_message_forwards_encoded_key_password(monkeypatch):
    captured = {}

    def fake_get_message(*_args, **kwargs):
        captured.update(kwargs)
        return None

    monkeypatch.setattr(receive, "get_message", fake_get_message)

    _client_with_password().get_message("MESSAGE-001")

    assert captured["key_password"] == b"encrypted-key-password"
