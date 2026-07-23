import requests
from typing import Any, Iterable, List, Mapping, Optional

from .config import EAddressConfig
from .attachments import Attachment
from .auth import TokenProvider
from .soap.client import SoapClient
from .api import send, receive, confirm, addressbook
from .api import notifications, directory, cert_validate, server_confirmation


class EAddressClient:
    """Thin wrapper around e-adrese VUS (SOAP) + OAuth2 auth."""

    def __init__(
        self,
        cfg: EAddressConfig,
        *,
        session: Optional[requests.Session] = None,
        service=None,
    ):
        self.cfg = cfg
        self._session = session or requests.Session()
        if not cfg.verify_ssl:
            self._session.verify = False  # noqa: S501 (only for sandbox)

        self.token_provider = TokenProvider(cfg, self._session)
        self.soap_client = SoapClient(cfg, self._session, service=service)

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    def send_message(
        self,
        recipient_personal_code: str,
        *,
        connection_id: Optional[str] = None,
        recipient_cert_path: Optional[str] = None,
        recipient_cert_pem: Optional[bytes] = None,
        recipient_public_key_modulus_b64: Optional[str] = None,
        recipient_public_key_exponent_b64: Optional[str] = None,
        encryption_key_b64: Optional[str] = None,
        recipient_thumbprint_b64: Optional[str] = None,
        symmetric_key_bytes: Optional[bytes] = None,
        symmetric_iv_bytes: Optional[bytes] = None,
        encryption_mode: Optional[str] = None,
        trace_text: str = "Created",
        notify_sender_on_delivery: bool = False,
        reference_id: Optional[str] = None,
        document_kind_code: str = "EINVOICE",
        subject: str = "Electronic invoice",
        body_text: str = "Please see the attached e-invoice.",
        attachments: Iterable[Attachment] = (),
    ) -> str:
        """Send a single e-adrese message and return the VUS MessageId."""
        return send.send_message(
            self.cfg,
            self.token_provider,
            self.soap_client,
            recipient_personal_code,
            connection_id=connection_id,
            recipient_cert_path=recipient_cert_path,
            recipient_cert_pem=recipient_cert_pem,
            recipient_public_key_modulus_b64=recipient_public_key_modulus_b64,
            recipient_public_key_exponent_b64=recipient_public_key_exponent_b64,
            encryption_key_b64=encryption_key_b64,
            recipient_thumbprint_b64=recipient_thumbprint_b64,
            symmetric_key_bytes=symmetric_key_bytes,
            symmetric_iv_bytes=symmetric_iv_bytes,
            encryption_mode=encryption_mode,
            trace_text=trace_text,
            notify_sender_on_delivery=notify_sender_on_delivery,
            reference_id=reference_id,
            sender_address=None,
            document_kind_code=document_kind_code,
            subject=subject,
            body_text=body_text,
            attachments=attachments,
        )

    def get_next_message(
        self, include_attachments: bool = True
    ) -> Optional[Mapping[str, Any]]:
        """Check for the next available message. Returns ``None`` if queue is empty."""
        key_password = (
            self.cfg.key_password.encode()
            if isinstance(self.cfg.key_password, str)
            else self.cfg.key_password
        )
        return receive.get_next_message(
            self.token_provider,
            self.soap_client,
            include_attachments,
            private_key_path=self.cfg.private_key,
            certificate_path=self.cfg.certificate,
            auto_confirm=False,
            key_password=key_password,
        )

    def get_message(
        self,
        message_id: str,
        *,
        include_attachments: bool = True,
        auto_confirm: bool = False,
    ) -> Optional[Mapping[str, Any]]:
        """Fetch a specific message by ID."""
        key_password = (
            self.cfg.key_password.encode()
            if isinstance(self.cfg.key_password, str)
            else self.cfg.key_password
        )
        return receive.get_message(
            self.token_provider,
            self.soap_client,
            message_id=message_id,
            include_attachments=include_attachments,
            private_key_path=self.cfg.private_key,
            certificate_path=self.cfg.certificate,
            auto_confirm=auto_confirm,
            key_password=key_password,
        )

    def get_message_list(
        self, max_result_count: Optional[int] = None
    ) -> List[Mapping[str, Any]]:
        """Return a list of message headers from the inbox."""
        return receive.get_message_list(
            self.token_provider,
            self.soap_client,
            max_result_count=max_result_count,
        )

    def confirm_message(
        self,
        message_id: str,
        *,
        status: str = "RecipientAccepted",
        status_code: Optional[str] = None,
        status_reason: Optional[str] = None,
    ) -> None:
        """Send a recipient confirmation/rejection for a message (XAdES signature)."""
        confirm.confirm_message(
            self.token_provider,
            self.soap_client,
            message_id,
            status=status,
            status_code=status_code,
            status_reason=status_reason,
        )

    def get_message_server_confirmation(
        self, message_id: str
    ) -> Mapping[str, Any]:
        """
        Fetch the VRAA server confirmation for a sent message.

        Returns the full ``ServerConfirmationPart`` dict including
        ``ServerTransportMetadata.ServerReceivedTime`` and the VRAA server signature.
        """
        return server_confirmation.get_message_server_confirmation(
            self.token_provider, self.soap_client, message_id
        )

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def get_notification_list(self, max_items: int = 50) -> Mapping[str, Any]:
        """Return raw ``GetNotificationList`` response dict."""
        return notifications.get_notification_list(
            self.token_provider, self.soap_client, max_items=max_items
        )

    def confirm_notification_list(self, notification_ids: List[int]) -> List[int]:
        """Confirm a list of notification IDs. Returns the confirmed IDs."""
        return notifications.confirm_notification_list(
            self.token_provider, self.soap_client, notification_ids
        )

    def poll_notifications(
        self, max_items: int = 50, auto_confirm: bool = True
    ) -> Mapping[str, Any]:
        """
        Poll notifications with optional auto-confirm.

        Returns ``{"items": [...], "has_more_data": bool, "confirmed_ids": [...]}``.
        """
        return notifications.poll_notifications(
            self.token_provider, self.soap_client, max_items=max_items, auto_confirm=auto_confirm
        )

    # ------------------------------------------------------------------
    # Addressee directory
    # ------------------------------------------------------------------

    def search_addressee(self, registration_number: str) -> List[Mapping[str, Any]]:
        """Search for an addressee by registration number / personal code / e-address."""
        return addressbook.search_addressee(
            self.token_provider, self.soap_client, registration_number
        )

    def get_initial_addressee_record_list(
        self,
        continuation_token: Optional[str] = None,
        all_pages: bool = True,
    ) -> Mapping[str, Any]:
        """
        Full initial sync of the VRAA addressee directory.

        Auto-paginates through all pages when ``all_pages=True``.
        Returns ``{"records": [...], "continuation_token": str | None, "latest_version": int | None, "record_count": int}``.
        """
        return directory.get_initial_addressee_record_list(
            self.token_provider,
            self.soap_client,
            continuation_token=continuation_token,
            all_pages=all_pages,
        )

    def get_changed_addressee_record_list(
        self, last_version: int = 0, all_pages: bool = False
    ) -> Mapping[str, Any]:
        """
        Incremental sync of the VRAA addressee directory since *last_version*.

        When ``all_pages=True``, automatically continues until VRAA reports
        ``HasMoreData=False`` using the latest returned ``Version`` as the next checkpoint.

        Returns ``{"records": [...], "has_more_data": bool, "latest_version": int | None, "record_count": int}``.
        """
        return directory.get_changed_addressee_record_list(
            self.token_provider, self.soap_client, last_version=last_version, all_pages=all_pages
        )

    def get_addressee_unit(self, query: str) -> Optional[Mapping[str, Any]]:
        """
        Fetch full addressee unit metadata.

        .. warning::
            Restricted to government institutions managing their own DIV units.
            Commercial clients receive a permission error — use :meth:`search_addressee` instead.
        """
        return addressbook.get_addressee_unit(
            self.token_provider, self.soap_client, query
        )

    def validate_eaddress(
        self,
        eaddresses: List[str],
        eaddress_type: Optional[str] = None,
    ) -> List[Mapping[str, Any]]:
        """
        Validate e-addresses in the VRAA directory.

        *eaddress_type*: ``'NaturalPerson'``, ``'RegisteredEntity'``, or ``None``.

        .. warning::
            Restricted to government accounts.
            Commercial clients receive a permission error — use :meth:`search_addressee` instead.
        """
        return addressbook.validate_eaddress(
            self.token_provider, self.soap_client, eaddresses, eaddress_type
        )

    # ------------------------------------------------------------------
    # Connectivity / certificate
    # ------------------------------------------------------------------

    def cert_validate(self, lookup_values: List[str]) -> Mapping[str, Any]:
        """
        Validate SOAP connectivity and certificate via ``SearchAddresseeUnit``.

        Returns ``{"status": "ok" | "error", "message": str, ...}``.
        """
        return cert_validate.cert_validate(
            self.token_provider, self.soap_client, lookup_values
        )
