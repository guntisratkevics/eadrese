from typing import Any, Mapping, Optional
from zeep.helpers import serialize_object
from ..errors import EAddressSoapError
from ..auth import TokenProvider
from ..soap.client import SoapClient

def get_next_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    include_attachments: bool = True
) -> Optional[Mapping[str, Any]]:
    """Check for the next available message."""
    token = token_provider.get_token()
    svc = soap_client.service
    
    try:
        if hasattr(svc, "GetNextMessage"):
            response = svc.GetNextMessage(Token=token, IncludeAttachments=include_attachments)
        else:
            # Stub support logic if needed, or raise
            raise EAddressSoapError("Service has no GetNextMessage method")
    except Exception as exc:
         raise EAddressSoapError("VUS GetNextMessage call failed") from exc
    
    if not response:
        return None
    return serialize_object(response)
