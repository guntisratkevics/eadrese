"""Pushes an e-invoice XML to the VID-EDS sandbox and prints its GUID."""
from pathlib import Path
from latvian_einvoice import EDSClient, EDSConfig

cfg = EDSConfig(
    api_key="your-sandbox-api-key",
    client_id="your-sandbox-client",
    client_secret="your-sandbox-secret",
    base_url="https://eds-test.vid.gov.lv/api",
    token_url="https://eds-test.vid.gov.lv/api/auth/token",
    verify_ssl=False,
)

cli = EDSClient(cfg)
xml_bytes = Path("sample.xml").read_bytes()

doc_guid = cli.send_invoice(xml_bytes)
print("Document GUID:", doc_guid)

status = cli.get_status(doc_guid)
print("Status:", status)
