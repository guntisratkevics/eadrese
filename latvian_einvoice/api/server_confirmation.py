"""GetMessageServerConfirmation."""
from typing import Any, Mapping, Optional

from zeep.helpers import serialize_object

from ..auth import TokenProvider
from ..errors import EAddressSoapError
from ..soap.client import SoapClient
from ._soap_utils import soap_call


def get_message_server_confirmation(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    message_id: str,
) -> Mapping[str, Any]:
    """
    Fetch server confirmation for a sent message.

    Returns the full ``ServerConfirmationPart`` response dict, including
    ``ServerTransportMetadata.ServerReceivedTime`` and the VRAA server signature.

    Raises :class:`~latvian_einvoice.errors.EAddressSoapError` on failure.
    """
    message_id = (message_id or "").strip()
    if not message_id:
        raise EAddressSoapError("message_id must not be empty")

    token = token_provider.get_token() if token_provider else None
    try:
        response = soap_call(
            soap_client.service,
            "GetMessageServerConfirmation",
            token,
            MessageId=message_id,
        )
    except EAddressSoapError:
        raise
    except Exception as exc:
        raise EAddressSoapError(
            f"VUS GetMessageServerConfirmation call failed for {message_id}"
        ) from exc

    return serialize_object(response) or {}
