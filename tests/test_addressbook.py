from latvian_einvoice.api import addressbook


class DummySoapClient:
    def __init__(self, service):
        self.service = service


def test_get_public_key_list_parses_nested_recipient_public_key_list():
    class Svc:
        def __init__(self):
            self.calls = []

        def GetPublicKeyList(self, Recipients=None, **_kwargs):
            self.calls.append({"Recipients": Recipients})
            return {
                "PublicKeys": {
                    "RecipientPublicKey": [
                        {"EAddress": "A", "Modulus": "M1", "Exponent": "E1", "CertificateThumbprint": "T1"},
                        {"EAddress": "B", "Modulus": "M2", "Exponent": "E2", "CertificateThumbprint": "T2"},
                    ]
                }
            }

    svc = Svc()
    client = DummySoapClient(svc)
    keys = addressbook.get_public_key_list(None, client, ["A", "B"])
    assert [k["EAddress"] for k in keys] == ["A", "B"]
    assert svc.calls == [{"Recipients": {"string": ["A", "B"]}}]


def test_get_public_key_list_parses_flat_list():
    class Svc:
        def GetPublicKeyList(self, Recipients=None, **_kwargs):
            return {
                "PublicKeys": [
                    {"EAddress": "A", "Modulus": "M1", "Exponent": "E1", "CertificateThumbprint": "T1"},
                ]
            }

    client = DummySoapClient(Svc())
    keys = addressbook.get_public_key_list(None, client, ["A"])
    assert keys[0]["EAddress"] == "A"

