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
    wsdl_url: str = "https://div.vraa.gov.lv/UnifiedService.svc?wsdl"
    token_url: str = "https://div.vraa.gov.lv/Auth/token"
    verify_ssl: bool = True
    timeout: int = 30
    
    # VID e-invoice sub-address settings
    vid_subaddress_auto: bool = False
    # Defaults from spec (will be used if vid_subaddress_auto is True)
    # TEST: VID_EREKINI_TEST@90000069281
    # PROD: VID_EREKINI_PROD@90000069281
    vid_subaddress: Optional[str] = None 
    
    # Test environment aliases
    default_from: str = "_DEFAULT@90000000000"
    default_to: str = "_PRIVATE@10000000000"
