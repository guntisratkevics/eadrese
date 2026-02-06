import logging
import requests
from typing import Any, Iterable, List, Mapping, Optional

from .config import EAddressConfig
from .attachments import Attachment
from .auth import TokenProvider
from .soap.client import SoapClient
from .api import send, receive, confirm, addressbook

logger = logging.getLogger(__name__)

class EAddressClient:
    """Thin wrapper around e-adrese VUS (SOAP) + OAuth2 auth."""

    def __init__(self, cfg: EAddressConfig, *, session: Optional[requests.Session] = None, service=None):
        self.cfg = cfg
        self._session = session or requests.Session()
        if not cfg.verify_ssl:
            self._session.verify = False  # noqa: S501 (only for sandbox)
        
        self.token_provider = TokenProvider(cfg, self._session)
        self.soap_client = SoapClient(cfg, self._session, service=service)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_message(
        self,
        recipient_personal_code: str,
        *,
        connection_id: str | None = None,
        recipient_cert_path: str | None = None,
        recipient_cert_pem: bytes | None = None,
        encryption_key_b64: str | None = None,
        recipient_thumbprint_b64: str | None = None,
        symmetric_key_bytes: bytes | None = None,
        trace_text: str = "Created",
        notify_sender_on_delivery: bool = False,
        document_kind_code: str = "EINVOICE",
        subject: str = "Electronic invoice",
        body_text: str = "Please see the attached e-invoice.",
        attachments: Iterable[Attachment] = (),
    ) -> str:
        """Send a single e-adrese message and return the VUS messageId."""
        return send.send_message(
            self.cfg,
            self.token_provider,
            self.soap_client,
            recipient_personal_code,
            connection_id=connection_id,
            recipient_cert_path=recipient_cert_path,
            recipient_cert_pem=recipient_cert_pem,
            encryption_key_b64=encryption_key_b64,
            recipient_thumbprint_b64=recipient_thumbprint_b64,
            symmetric_key_bytes=symmetric_key_bytes,
            trace_text=trace_text,
            notify_sender_on_delivery=notify_sender_on_delivery,
            sender_address=None,
            document_kind_code=document_kind_code,
            subject=subject,
            body_text=body_text,
            attachments=attachments,
        )

    def get_next_message(self, include_attachments: bool = True) -> Optional[Mapping[str, Any]]:
        """
        Check for the next available message.
        Returns None if no message is available.
        """
        return receive.get_next_message(
            self.token_provider,
            self.soap_client,
            include_attachments,
            auto_confirm=False,
        )

    def confirm_message(self, message_id: str) -> None:
        """Confirm receipt of a message."""
        confirm.confirm_message(
            self.token_provider,
            self.soap_client,
            message_id
        )

    def search_addressee(self, registration_number: str) -> List[Mapping[str, Any]]:
        """
        Search for an addressee by registration number / personal code.
        """
        return addressbook.search_addressee(
            self.token_provider,
            self.soap_client,
            registration_number
        )
