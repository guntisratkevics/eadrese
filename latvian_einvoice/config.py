from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class EAddressConfig:
    """Credentials and endpoints for e-adrese VUS/DIV."""

    client_id: str
    client_secret: str
    certificate: Optional[Path] = None
    private_key: Optional[Path] = None
    wsse_signing: bool = False
    wsse_verify: bool = True
    wsse_timestamp: bool = True
    wsdl_url: str = "https://div.vraa.gov.lv/UnifiedService.svc?wsdl"
    token_url: str = "https://div.vraa.gov.lv/Auth/token"
    verify_ssl: bool = True
    timeout: int = 30
    # Optional local WSDL override (e.g., file:///.../refs/vraadivclient-20190430/localhost/.../UnifiedService.svc.wsdl)
    local_wsdl_url: Optional[str] = None
    
    # VID e-invoice sub-address settings
    vid_subaddress_auto: bool = False
    # Defaults from spec (will be used if vid_subaddress_auto is True)
    # TEST: VID_EREKINI_TEST@90000069281
    # PROD: VID_EREKINI_PROD@90000069281
    vid_subaddress: Optional[str] = None 
    
    # Test environment aliases
    default_from: str = "_DEFAULT@90000000000"
    default_to: str = "_PRIVATE@10000000000"

    # Encryption defaults (per-recipient overrides can be passed into send_message)
    # Key: base64-encoded encrypted symmetric key; Thumbprint: base64 of recipient cert SHA-1 per DIV spec.
    default_encryption_key_b64: Optional[str] = None
    default_recipient_thumbprint_b64: Optional[str] = None

    # Recipient certificate (PEM) for encrypting symmetric key in EncryptionInfo
    recipient_cert_path: Optional[Path] = None

    # mTLS client cert/key for transport (PEM paths)
    client_cert_path: Optional[Path] = None
    client_key_path: Optional[Path] = None

    # WS-Security response signature verification
    verify_response_signature: bool = True
    trust_store_path: Optional[Path] = None  # PEM bundle of trusted issuers (server cert chain)
