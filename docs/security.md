# Security Configuration

## mTLS (Mutual TLS)
VUS/DIV requires mutual TLS authentication. Provide a valid client certificate and private key (PEM).

Example:
```python
config = EAddressConfig(
    client_cert_path=Path("/path/to/client.crt.pem"),
    client_key_path=Path("/path/to/client.key.pem"),
)
```

## WS-Security
SOAP requests are signed with WS-Security when `wsse_signing=True`:
- SignatureMethod: RSA-SHA1
- DigestMethod: SHA1
- Signed parts: Timestamp + To
- BinarySecurityToken + SecurityTokenReference

The SenderDocument inside the DIV Envelope is signed separately with XMLDSig + XAdES-BES.

## OAuth2
OAuth2 client-credentials is supported. Some test environments accept mTLS-only. Configure as needed:
```python
config = EAddressConfig(client_id="ID", client_secret="SECRET", token_url="...")
```

## Response verification
`wsse_verify=True` enables basic signature verification against a trust store or explicit server cert.
OCSP validation is best-effort and disabled by default.

## PFX to PEM Conversion
If you have a PFX (PKCS#12) file, convert it to PEM format using OpenSSL:

1. Extract Private Key:
```bash
openssl pkcs12 -in file.pfx -nocerts -out key.pem
```
2. Extract Certificate:
```bash
openssl pkcs12 -in file.pfx -clcerts -nokeys -out cert.pem
```
