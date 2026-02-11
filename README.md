# Latvian E-Invoice & E-Address SDK (experimental)

A work-in-progress Python client for Latvia's E-Address (VRAA VUS / DIV) and VID EDS e-invoice integration.
This is NOT an official implementation. It is partially reverse-engineered (wiresharked) from official Java/.NET flows
and XSD/WSDL documents. Use at your own risk.

Status / caveats
- Experimental and not fully tested end-to-end.
- Cryptographic and protocol details are still being validated against the official clients.
- Response signature and OCSP validation are best-effort.

## Support / Donate (Overall)
If this SDK helps your work and you want to support further development:
- https://revolut.me/guntisha2j

VRAA operational notes (from support replies)
- For EINVOICE, the VID subaddress is mandatory; add it manually or enable automatic VID recipient insertion.
- Test environment message retrieval window is 2 days; replies are sent to the sender e-address.

## What it does
- Implements VUS UnifiedService SOAP calls (SendMessage, GetNextMessage, ConfirmMessage, SearchAddressee).
- Builds DIV Envelope (SenderDocument, Signatures, AttachmentsInput) according to DIV XSD.
- Signs SenderDocument with XMLDSig + XAdES-BES (RSA-SHA512, SHA-512 digests; XAdES v1.3.2 SignedProperties).
- Adds WS-Security signature to the SOAP header (RSA-SHA1/SHA1) with Timestamp + To, matching the Java profile.
- Supports mTLS client auth; OAuth2 client-credentials token is optional when required by the environment.
- Optional outbound attachment encryption (AES-GCM placeholder) with per-recipient EncryptionInfo.
- Inbound attachment decryption for DIV AES-CBC + RSA-OAEP (SHA1) key wrapping with optional GZIP decompression.
- Optional VID subaddress auto-add for EINVOICE.

## How it works (high level)
1) build_envelope creates the DIV Envelope and attachment metadata (optionally encrypted).
2) SenderDocumentSigner signs the SenderDocument and injects ds:Signature + XAdES QualifyingProperties.
3) SignOnlySignature creates WSSE BinarySecurityToken + Signature for SOAP headers.
4) SoapClient sends the request via Zeep; TokenProvider adds OAuth token when configured.

## Specifications and protocols
- SOAP: VUS UnifiedService (DIV).
- XMLDSig: W3C XML Signature (RSA-SHA512 for SenderDocument, RSA-SHA1 for WSSE header).
- XAdES: ETSI XAdES v1.3.2 (SignedProperties).
- WS-Security: OASIS 2004 profile (BinarySecurityToken + SecurityTokenReference).
- TLS: mutual TLS (client cert + key).

## Installation
```bash
pip install .
```
(Or `pip install -e .` for development)

## Quick start (mTLS only)
```python
from latvian_einvoice import EAddressClient, EAddressConfig

cfg = EAddressConfig(
    client_id="",  # empty when OAuth not required
    client_secret="",
    wsse_signing=True,
    wsse_verify=False,
    wsdl_url="https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl",
    default_from="_PRIVATE@<REG_NO>",
    client_cert_path="/path/to/client.crt.pem",
    client_key_path="/path/to/client.key.pem",
    certificate="/path/to/client.crt.pem",
    private_key="/path/to/client.key.pem",
    verify_ssl=False,  # True in PROD
)

client = EAddressClient(cfg)
client.send_message(
    recipient_personal_code="_PRIVATE@<TEST_RECIPIENT>",
    document_kind_code="DOC_EMPTY",
    subject="Hello",
    body_text="Smoke test",
)
```

## Quick start (OAuth + mTLS)
```python
cfg = EAddressConfig(
    client_id="YOUR_ID",
    client_secret="YOUR_SECRET",
    wsse_signing=True,
    wsdl_url="https://div.vraa.gov.lv/UnifiedService.svc?wsdl",
    token_url="https://div.vraa.gov.lv/Auth/token",
    client_cert_path="/path/to/client.crt.pem",
    client_key_path="/path/to/client.key.pem",
    certificate="/path/to/client.crt.pem",
    private_key="/path/to/client.key.pem",
    verify_ssl=True,
)
```

## Documentation
- docs/python-client-spec.md
- docs/security.md

## PHP (early stage)
An experimental PHP client lives under `php/`. It currently contains scaffolding for configuration,
envelope building, crypto utilities, and a sidecar HTTP client (send/list/confirm via the Java sidecar API).
Direct SOAP/WSSE signing is not yet complete.

## Testing
```bash
pytest
```

### Support Python Development
- https://revolut.me/guntisha2j

### Support PHP Development
- https://revolut.me/guntisha2j
