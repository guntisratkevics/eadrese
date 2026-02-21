import base64
import logging
import os
from pathlib import Path
from typing import Any, Iterable, Mapping
from zeep.helpers import serialize_object

from ..attachments import Attachment
from ..config import EAddressConfig
from ..errors import EAddressSoapError
from ..soap.envelope import build_envelope
from ..auth import TokenProvider
from ..soap.client import SoapClient
from ..utils_crypto import (
    derive_encryption_fields,
    rsa_public_key_from_modexp,
    build_div_key_blob,
    encrypt_key_blob_oaep_sha1,
)

logger = logging.getLogger(__name__)

_MAX_MESSAGE_FILES_SIZE = 0x400000  # 4 MiB
_ATTACHMENT_SECTION_SIZE = 0x400000  # 4 MiB


def _call_service_method(
    svc: Any,
    method_name: str,
    *,
    token: str | None,
    kwargs: Mapping[str, Any],
):
    method = getattr(svc, method_name, None)
    if method is None:
        raise EAddressSoapError(f"Service has no {method_name} method")

    if token:
        try:
            return method(Token=token, **kwargs)
        except TypeError:
            pass

    try:
        return method(**kwargs)
    except TypeError as exc:
        # Keep simple stubs/test doubles working for SendMessage fallback signatures.
        if method_name == "SendMessage":
            envelope = kwargs.get("Envelope")
            attachments_input = kwargs.get("AttachmentsInput")
            if token:
                try:
                    return method(token, envelope, attachments_input)
                except TypeError:
                    pass
                try:
                    return method(token, envelope)
                except TypeError:
                    pass
            try:
                return method(envelope, attachments_input)
            except TypeError:
                pass
            return method(envelope)
        raise exc


def _extract_message_id(response: Any, fallback: str) -> str:
    data = serialize_object(response) if response is not None else {}
    if isinstance(data, str):
        text = data.strip()
        if text:
            return text
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="ignore").strip()
        if text:
            return text
    message_id_out = None
    if isinstance(data, Mapping):
        message_id_out = data.get("MessageId") or data.get("messageId")
    if not message_id_out:
        message_id_out = fallback
    return str(message_id_out)


def _decode_contents_field(raw_value: Any) -> bytes:
    if raw_value is None:
        return b""
    if isinstance(raw_value, bytes):
        return raw_value
    if isinstance(raw_value, str):
        value = raw_value.strip()
        if not value:
            return b""
        return base64.b64decode(value)
    raise EAddressSoapError(f"Unsupported AttachmentInput contents type: {type(raw_value)!r}")


def _split_inline_and_separate_attachments(
    attachment_inputs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_size = sorted(attachment_inputs, key=lambda x: x["size"])
    inline_ids: set[int] = set()
    running = 0
    for item in by_size:
        if running + item["size"] <= _MAX_MESSAGE_FILES_SIZE:
            inline_ids.add(item["index"])
            running += item["size"]

    inline = [item for item in attachment_inputs if item["index"] in inline_ids]
    separate = [item for item in attachment_inputs if item["index"] not in inline_ids]
    return inline, separate


def _send_message_chunked(
    svc: Any,
    *,
    token: str | None,
    envelope: Mapping[str, Any],
    built_message_id: str,
    attachment_inputs: list[dict[str, Any]],
) -> str:
    inline, separate = _split_inline_and_separate_attachments(attachment_inputs)

    init_items: list[dict[str, Any]] = []
    inline_map = {item["index"]: item for item in inline}
    for item in attachment_inputs:
        if item["index"] in inline_map:
            init_items.append(
                {
                    "ContentId": item["content_id"],
                    "Contents": item["contents_b64"],
                }
            )
        else:
            init_items.append({"ContentId": item["content_id"]})

    sender_address = (
        envelope.get("SenderDocument", {})
        .get("SenderTransportMetadata", {})
        .get("SenderE-Address", "")
    )
    init_kwargs: dict[str, Any] = {
        "MessageClientId": built_message_id,
        "SenderEAddress": sender_address,
    }
    if init_items:
        init_kwargs["AttachmentsInput"] = {"AttachmentInput": init_items}

    init_response = _call_service_method(
        svc,
        "InitSendMessage",
        token=token,
        kwargs=init_kwargs,
    )
    server_message_id = _extract_message_id(init_response, built_message_id)

    for item in separate:
        content = item["contents_bytes"]
        content_id = item["content_id"]
        section_index = 0
        for offset in range(0, len(content), _ATTACHMENT_SECTION_SIZE):
            chunk = content[offset : offset + _ATTACHMENT_SECTION_SIZE]
            _call_service_method(
                svc,
                "SendAttachmentSection",
                token=token,
                kwargs={
                    "MessageId": server_message_id,
                    "ContentId": content_id,
                    "SectionIndex": section_index,
                    "Contents": chunk,
                },
            )
            section_index += 1

        # Java client sends an explicit terminal section when payload is
        # an exact multiple of section size.
        if content and len(content) % _ATTACHMENT_SECTION_SIZE == 0:
            _call_service_method(
                svc,
                "SendAttachmentSection",
                token=token,
                kwargs={
                    "MessageId": server_message_id,
                    "ContentId": content_id,
                    "SectionIndex": section_index,
                },
            )

    _call_service_method(
        svc,
        "CompleteSendMessage",
        token=token,
        kwargs={
            "MessageId": server_message_id,
            "Envelope": envelope,
        },
    )
    return server_message_id


def send_message(
    cfg: EAddressConfig,
    token_provider: TokenProvider,
    soap_client: SoapClient,
    recipient_personal_code: str,
    connection_id: str | None = None,
    recipient_cert_path: str | Path | None = None,
    recipient_cert_pem: bytes | None = None,
    recipient_public_key_modulus_b64: str | None = None,
    recipient_public_key_exponent_b64: str | None = None,
    encryption_key_b64: str | None = None,
    recipient_thumbprint_b64: str | None = None,
    symmetric_key_bytes: bytes | None = None,
    symmetric_iv_bytes: bytes | None = None,
    encryption_mode: str | None = None,
    trace_text: str = "Created",
    notify_sender_on_delivery: bool = False,
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

    mode = (encryption_mode or cfg.outbound_encryption or "gcm").lower()
    enc_key_b64 = encryption_key_b64
    thumb_b64 = recipient_thumbprint_b64
    sym_key = symmetric_key_bytes
    sym_iv = symmetric_iv_bytes
    if recipient_public_key_modulus_b64 and recipient_public_key_exponent_b64 and thumb_b64:
        public_key = rsa_public_key_from_modexp(
            recipient_public_key_modulus_b64, recipient_public_key_exponent_b64
        )
        sym_key = sym_key or os.urandom(32)
        if mode not in ("oaep_cbc", "cbc"):
            raise EAddressSoapError("Recipient public key requires oaep_cbc mode")
        sym_iv = sym_iv or os.urandom(16)
        key_blob = build_div_key_blob(sym_key, sym_iv)
        enc_key_b64 = encrypt_key_blob_oaep_sha1(public_key, key_blob)
    elif recipient_cert_path or recipient_cert_pem:
        enc_key_b64, thumb_b64, sym_key, sym_iv = derive_encryption_fields(
            recipient_cert_path=Path(recipient_cert_path) if recipient_cert_path else None,
            recipient_cert_pem=recipient_cert_pem,
            key_bytes=symmetric_key_bytes,
            iv_bytes=symmetric_iv_bytes,
            mode=mode,
        )

    envelope, attachments_input, built_message_id = build_envelope(
        sender_address or cfg.default_from,
        recipients,
        document_kind_code,
        subject,
        body_text,
        list(attachments),
        encryption_key_b64=enc_key_b64,
        recipient_thumbprint_b64=thumb_b64,
        trace_text=trace_text,
        notify_sender_on_delivery=notify_sender_on_delivery,
        symmetric_key_bytes=sym_key,
        symmetric_iv_bytes=sym_iv,
        encryption_mode=mode,
    )
    logger.debug("Built envelope: %s", envelope)
    
    svc = soap_client.service
    if callable(svc) and not hasattr(svc, "SendMessage"):
        try:
            response = svc(None, envelope)
        except Exception as exc:
            raise EAddressSoapError("VUS SendMessage call failed") from exc
        return _extract_message_id(response, built_message_id)

    attachment_items_raw = []
    if isinstance(attachments_input, Mapping):
        attachment_items_raw = list(attachments_input.get("AttachmentInput") or [])

    parsed_attachment_items: list[dict[str, Any]] = []
    total_content_size = 0
    if attachment_items_raw:
        for index, item in enumerate(attachment_items_raw):
            if not isinstance(item, Mapping):
                continue
            content_id = str(item.get("ContentId", index))
            if "Contents" in item and item.get("Contents") not in (None, ""):
                contents_bytes = _decode_contents_field(item.get("Contents"))
                parsed_attachment_items.append(
                    {
                        "index": index,
                        "content_id": content_id,
                        "contents_b64": base64.b64encode(contents_bytes).decode("ascii"),
                        "contents_bytes": contents_bytes,
                        "size": len(contents_bytes),
                    }
                )
                total_content_size += len(contents_bytes)
            else:
                raise EAddressSoapError(
                    "AttachmentInput without Contents is not supported for large-file send flow; "
                    "use oaep_cbc mode for encrypted attachment sends."
                )

    use_chunked_send = total_content_size > _MAX_MESSAGE_FILES_SIZE

    try:
        if use_chunked_send:
            return _send_message_chunked(
                svc,
                token=token,
                envelope=envelope,
                built_message_id=built_message_id,
                attachment_inputs=parsed_attachment_items,
            )

        response = _call_service_method(
            svc,
            "SendMessage",
            token=token,
            kwargs={
                "Envelope": envelope,
                "AttachmentsInput": attachments_input or None,
            },
        )
    except Exception as exc:
        raise EAddressSoapError(f"VUS SendMessage call failed: {exc}") from exc

    return _extract_message_id(response, built_message_id)
