# Latvian E-Invoice & E-Address SDK

A pure Python client for Latvia's E-Address (VRAA VUS) and VID EDS e-invoice integration.
Designed to work without official Java/.NET libraries.

## Features
*   **OAuth2 Authentication**: Automatic token fetching and caching.
*   **SOAP Client**: Full integration with VUS `UnifiedService`.
*   **E-Invoices**: Specialized support for `EINVOICE` document type.
*   **VID Integration**: Automatic routing to VID sub-addresses in PROD/TEST.
*   **Zero Java/.NET**: Pure Python implementation using `zeep` and `requests`.

## Installation
```bash
pip install .
```
(Or `pip install -e .` for development)

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
