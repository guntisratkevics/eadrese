# Security Configuration

## mTLS (Mutual TLS)
The E-Address services (VUS) require mutual TLS authentication. You must provide a valid client certificate and private key.

### Configuration
In `EAddressConfig`, provide paths to your PEM-encoded files:
```python
config = EAddressConfig(
    ...
    certificate=Path("/path/to/client.crt"),
    private_key=Path("/path/to/client.key")
)
```

### PFX to PEM Conversion
If you have a PFX (PKCS#12) file, convert it to PEM format using OpenSSL:

1.  **Extract Private Key:**
    ```bash
    openssl pkcs12 -in files.pfx -nocerts -out key.pem
    ```
    *Note: You may need to remove the passphrase or handle it in your application securely.*

2.  **Extract Certificate:**
    ```bash
    openssl pkcs12 -in file.pfx -clcerts -nokeys -out cert.pem
    ```

## Token Security
*   **Caching**: This library automatically caches OAuth2 access tokens in memory.
*   **Sensitivity**: Never log the `access_token` or `client_secret`. The library's internal logging redacts these values (ensure your application logging does too).

## WS-Security
The library uses `zeep.wsse.signature.Signature` to sign SOAP requests if certificates are provided. This ensures message integrity and authenticity at the SOAP envelope level, in addition to the transport-level mTLS.
