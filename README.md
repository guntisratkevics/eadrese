# Latvian E-Invoice & E-Address SDK (experimental)

A **work-in-progress** Python client for Latvia's E-Address (VRAA VUS) and VID EDS e-invoice integration.
Designed to work without official Java/.NET libraries, but **parts of the protocol are still being reverse‑engineered** and not fully tested end-to-end.

## Features
*   **OAuth2 Authentication**: Automatic token fetching and caching.
*   **SOAP Client**: Integration with VUS `UnifiedService` (experimental; may change).
*   **E-Invoices**: Support for `EINVOICE` document type (envelope shape follows DIV XSD; validation ongoing).
*   **VID Integration**: Automatic routing to VID sub-addresses in PROD/TEST.
*   **Zero Java/.NET**: Pure Python implementation using `zeep` and `requests`.

## Installation
```bash
pip install .
```
(Or `pip install -e .` for development)

**Status / Caveats**
*   Experimental: not production-ready; cryptographic parts (WS-Security, XAdES, OCSP, encryption) are under active development.
*   Partially reverse-engineered (“wiresharked”) from official Java/.NET flows and XSD/WSDL; behavior may differ from the official clients.
*   Response signature/OCSP validation is best-effort only; verify with your own trust store and additional checks.

## Documentation
*   [Client Specification](docs/python-client-spec.md)
*   [Security & mTLS](docs/security.md)

## Quick Start

### Sending a Message
```python
from latvian_einvoice import EAddressClient, EAddressConfig

cfg = EAddressConfig(
    client_id="YOUR_ID",
    client_secret="YOUR_SECRET",
    verify_ssl=False # Use True in PROD
)
client = EAddressClient(cfg)
client.send_message(
    recipient_personal_code="123456-12345",
    subject="Hello",
    body_text="World"
)
```

See [examples/](examples/) for more scripts:
*   `send_test_message.py`
*   `send_einvoice_test.py`
*   `receive_and_confirm.py`

## Testing
Run unit tests:
```bash
pytest
```
