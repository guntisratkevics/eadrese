## ☛ `examples/send_eds_invoice.py`
```python
"""Pushes an e‑invoice XML to VID EDS sandbox and prints document GUID."""
from pathlib import Path
from latvian_einvoice import EDSClient, EDSConfig

cfg = EDSConfig(
    api_key="demo‑api‑key",
    client_id="demo‑client‑id",
    client_secret="demo‑secret",
    base_url="https://eds-test.vid.gov.lv/api",  # sandbox
    token_url="https://eds-test.vid.gov.lv/api/auth/token",
    verify_ssl=False,
)
cli = EDSClient(cfg)
xml_data = Path("sample.xml").read_bytes()

doc_guid = cli.send_invoice(xml_data)
print("Document GUID:", doc_guid)
status = cli.get_status(doc_guid)
print("Status:", status)
```

---
