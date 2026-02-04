from ..errors import EAddressSoapError
from ..auth import TokenProvider
from ..soap.client import SoapClient

def confirm_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    message_id: str
) -> bool:
    """Confirm receipt of a message. Returns True on success."""
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service
    
    try:
        if hasattr(svc, "ConfirmMessage"):
            if token:
                svc.ConfirmMessage(Token=token, MessageId=message_id)
            else:
                svc.ConfirmMessage(MessageId=message_id)
        else:
            raise EAddressSoapError("Service has no ConfirmMessage method")
    except Exception as exc:
         raise EAddressSoapError(f"VUS ConfirmMessage call failed for {message_id}") from exc
    return True
