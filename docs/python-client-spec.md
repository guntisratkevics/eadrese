# Python E-Address Client Specification

## 1. Overview
`latvian_einvoice` is a pure Python implementation of Latvia's E-Address (VRAA VUS / DIV) and VID EDS e-invoice flow.
It mirrors the behavior of the official Java/.NET clients where possible, but
it is experimental and based on published schemas, WSDL documents, and
interoperability testing.

## 2. Endpoints
Typical endpoints (adjust for TEST/PROD):
- WSDL (PROD): https://div.vraa.gov.lv/UnifiedService.svc?wsdl
- Token URL (PROD): https://div.vraa.gov.lv/Auth/token
- WSDL (TEST): https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl

## 3. Authentication and transport
- mTLS is required by VUS/DIV. Configure `client_cert_path` and `client_key_path` (PEM).
- OAuth2 client-credentials is supported via `client_id`/`client_secret` and `token_url`.
- Some test environments accept mTLS-only without OAuth; keep OAuth optional in code.

## 4. Message model
- DIV Envelope with SenderDocument + Signatures (XMLDSig + XAdES-BES).
- SendMessage supports:
  - document_kind_code (DOC_EMPTY or EINVOICE)
  - subject/body_text
  - recipients (personal code or e-address)
  - optional attachments (with optional AES-GCM encryption)
  - optional EncryptionInfo for recipients
  - optional `reference_id` for replies, emitted as
    `CommonMetadata.DocumentReferences.ReferenceEntry.RefRegistrationNumber`
- VID auto add: when `vid_subaddress_auto=True` and DocumentKindCode is EINVOICE, the library adds
  VID subaddress automatically (TEST or PROD).
- VRAA note: EINVOICE messages must include VID subaddress (mandatory).
- VRAA note: test environment message retrieval window is 2 days.

## 5. Signatures
- SenderDocument signature:
  - XMLDSig RSA-SHA512
  - SHA-512 digests
  - XAdES v1.3.2 SignedProperties (SHA-1 cert digest)
  - SenderDocument reference uses exclusive C14N
- SOAP WS-Security signature:
  - RSA-SHA1 / SHA1 digests (matches Java profile)
  - Timestamp + To are signed
  - BinarySecurityToken + SecurityTokenReference

## 6. Receiving, confirmation, and directory operations
- `GetNextMessage`, `GetMessageList`, and `GetMessage` retrieve messages.
- MTOM/XOP response parts and separate attachment sections are normalized.
- `ConfirmMessage` supports accepted/rejected status metadata.
- Optional decryption for attachments when EncryptionInfo and private key are provided.
- DIV inbound encryption (per Java/.NET clients):
  - RSA-OAEP (SHA1) decrypt of `EncryptionInfo.Key` yields `[key_len][aes_key][iv]`.
  - AES-CBC/PKCS5 for content bytes; guarded GZIP decompression preserves
    explicitly supplied `.gz`/`application-gzip` payloads.
- Notification list/confirm/poll and message server-confirmation operations are
  exposed by `EAddressClient`.
- Initial and changed addressee-directory synchronization supports paging and
  checkpoint versions.

## 7. Configuration
Key parameters in `EAddressConfig`:
- client_id, client_secret, token_url (OAuth)
- certificate, private_key (WSSE signing)
- client_cert_path, client_key_path (mTLS)
- wsse_signing, wsse_verify, wsse_timestamp
- vid_subaddress_auto, vid_subaddress
- default_from, default_to

## 8. Public examples and diagnostics

- Use placeholder e-addresses, registration numbers, message IDs, and payloads
  in documentation and tests.
- Never commit credentials, certificates, private keys, production messages, or
  organization-specific debug output.
- Treat `EADRESE_DEBUG_DIR` output as sensitive and keep it outside the
  repository.
