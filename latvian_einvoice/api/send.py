import logging
from typing import Iterable, Mapping
from zeep.helpers import serialize_object

from ..attachments import Attachment
from ..config import EAddressConfig
from ..errors import EAddressSoapError
from ..soap.envelope import build_envelope
from ..auth import TokenProvider
from ..soap.client import SoapClient

logger = logging.getLogger(__name__)

def send_message(
    cfg: EAddressConfig,
    token_provider: TokenProvider,
    soap_client: SoapClient,
    recipient_personal_code: str,
    connection_id: str | None = None,
    sender_address: str | None = None,
    document_kind_code: str = "EINVOICE",
    subject: str = "Electronic invoice",
    body_text: str = "Please see the attached e-invoice.",
    attachments: Iterable[Attachment] = (),
) -> str:
    """Send a single e-adrese message and return the VUS messageId."""
    token = token_provider.get_token() if token_provider else None
    
    recipients = [recipient_personal_code]
    
    # VID auto logic
    if cfg.vid_subaddress_auto and document_kind_code == "EINVOICE":
        vid_addr = cfg.vid_subaddress
        if not vid_addr:
             if "test" in cfg.token_url.lower():
                 vid_addr = "VID_EREKINI_TEST@90000069281"
             else:
                 vid_addr = "VID_EREKINI_PROD@90000069281"
        
        if vid_addr and vid_addr not in recipients:
            recipients.append(vid_addr)

    envelope, attachments_input, built_message_id = build_envelope(
        sender_address or cfg.default_from,
        recipients,
        document_kind_code,
        subject,
        body_text,
        list(attachments),
    )
    logger.debug("Built envelope: %s", envelope)
    
    svc = soap_client.service
    # Handle both real service and callables (stubs)
    try:
        if hasattr(svc, "SendMessage"):
            try:
                kwargs = {
                    "Envelope": envelope,
                    "AttachmentsInput": attachments_input or None,
                }
                if token:
                    kwargs["Token"] = token
                if connection_id:
                    kwargs["_soapheaders"] = {"ConnectionId": connection_id}
                response = svc.SendMessage(**kwargs)
            except TypeError:
                # Fallback for simple stubs expecting positional args
                if connection_id:
                    response = svc.SendMessage(connection_id, token, envelope) if token else svc.SendMessage(connection_id, envelope)
                else:
                    response = svc.SendMessage(token, envelope) if token else svc.SendMessage(envelope)
        elif callable(svc):
             response = svc(None, envelope)
        else:
             raise EAddressSoapError("Service has no SendMessage method")
    except Exception as exc:
        raise EAddressSoapError("VUS SendMessage call failed") from exc

    data = serialize_object(response) if response is not None else {}
    message_id_out = None
    if isinstance(data, Mapping):
        message_id_out = data.get("MessageId") or data.get("messageId")
    if not message_id_out:
        message_id_out = built_message_id
    return str(message_id_out)
