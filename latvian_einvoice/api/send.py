import base64
import json
import logging
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from zeep.helpers import serialize_object

from ..attachments import Attachment
from ..config import EAddressConfig
from ..errors import EAddressSoapError
from ..soap.envelope import build_envelope
from ..auth import TokenProvider
from ..soap.client import SoapClient
from .addressbook import get_public_key_list
from ..utils_crypto import (
    derive_encryption_fields,
    rsa_public_key_from_modexp,
    build_div_key_blob,
    encrypt_key_blob_oaep_sha1,
)

logger = logging.getLogger(__name__)

_MAX_MESSAGE_FILES_SIZE = 0x400000  # 4 MiB
_ATTACHMENT_SECTION_SIZE = 0x400000  # 4 MiB
_BASE64_BINARY_FIELDS = {
    "CertificateThumbprint",
    "CipherText",
    "Contents",
    "DigestValue",
    "Exponent",
    "IV",
    "Key",
    "Modulus",
    "SignatureValue",
    "X509Certificate",
    "X509SKI",
}


def _safe_debug_token(value: str | None, fallback: str = "message") -> str:
    text = (value or "").strip()
    safe = "".join(ch if ch.isalnum() else "_" for ch in text)
    return safe or fallback


def _write_send_debug_manifest(
    *,
    message_id: str,
    sender_address: str | None,
    recipients: list[str],
    document_kind_code: str,
    notify_sender_on_delivery: bool,
    encryption_mode: str,
    encryption_key_b64: str | None,
    recipient_thumbprint_b64: str | None,
    symmetric_key_bytes: bytes | None,
    symmetric_iv_bytes: bytes | None,
    attachments: list[Attachment],
    cfg: EAddressConfig,
    recipient_transport_entries: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    debug_dir = (os.environ.get("EADRESE_DEBUG_DIR") or "").strip()
    if not debug_dir:
        return
    try:
        out_dir = Path(debug_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_id = _safe_debug_token(message_id)
        manifest = {
            "message_id": message_id,
            "sender_address": sender_address,
            "recipients": recipients,
            "document_kind_code": document_kind_code,
            "notify_sender_on_delivery": notify_sender_on_delivery,
            "encryption_mode": encryption_mode,
            "has_encryption_key": bool(encryption_key_b64),
            "has_recipient_thumbprint": bool(recipient_thumbprint_b64),
            "has_symmetric_key": bool(symmetric_key_bytes),
            "has_symmetric_iv": bool(symmetric_iv_bytes),
            "attachment_count": len(attachments),
            "attachment_names": [getattr(item, "file_name", None) for item in attachments],
            "vid_subaddress_auto": bool(getattr(cfg, "vid_subaddress_auto", False)),
            "vid_subaddress": getattr(cfg, "vid_subaddress", None),
            "default_from": getattr(cfg, "default_from", None),
            "token_url": getattr(cfg, "token_url", None),
            "recipient_transport_entries": [],
        }
        for entry in recipient_transport_entries or []:
            if not isinstance(entry, Mapping):
                continue
            encryption_info = entry.get("EncryptionInfo")
            manifest["recipient_transport_entries"].append(
                {
                    "recipient": entry.get("RecipientE-Address"),
                    "has_encryption_info": isinstance(encryption_info, Mapping),
                    "has_key": bool(isinstance(encryption_info, Mapping) and encryption_info.get("Key")),
                    "thumbprint_len": len(str((encryption_info or {}).get("CertificateThumbprint") or "")),
                }
            )
        (out_dir / f"send_{safe_id}_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        logger.exception("Failed to persist e-adrese send debug manifest")


def _decode_base64_text(value: str) -> bytes:
    text = value.strip()
    if not text:
        return b""
    padding = (-len(text)) % 4
    if padding:
        text = f"{text}{'=' * padding}"
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        return base64.b64decode(text, validate=False)


def _normalize_recipient_code(value: str | None) -> str:
    return (value or "").strip()


def _normalize_public_key_entry(value: Mapping[str, Any]) -> dict[str, str] | None:
    recipient = _normalize_recipient_code(
        value.get("EAddress")
        or value.get("Recipient")
        or value.get("RecipientEAddress")
    )
    modulus = str(value.get("Modulus") or "").strip()
    exponent = str(value.get("Exponent") or "").strip()
    thumbprint = str(value.get("CertificateThumbprint") or value.get("Thumbprint") or "").strip()
    if not recipient or not modulus or not exponent or not thumbprint:
        return None
    return {
        "recipient": recipient,
        "modulus": modulus,
        "exponent": exponent,
        "thumbprint": thumbprint,
    }


def _resolve_public_key_map(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    recipients: Sequence[str],
) -> dict[str, dict[str, str]]:
    public_keys = get_public_key_list(token_provider, soap_client, list(recipients))
    result: dict[str, dict[str, str]] = {}
    for item in public_keys:
        if not isinstance(item, Mapping):
            continue
        normalized = _normalize_public_key_entry(item)
        if not normalized:
            continue
        result[normalized["recipient"]] = normalized
    return result


def _build_recipient_transport_entries_from_public_keys(
    recipients: Sequence[str],
    public_key_map: Mapping[str, Mapping[str, str]],
    *,
    symmetric_key_bytes: bytes,
    symmetric_iv_bytes: bytes,
) -> tuple[list[dict[str, Any]], list[str]]:
    key_blob = build_div_key_blob(symmetric_key_bytes, symmetric_iv_bytes)
    entries: list[dict[str, Any]] = []
    missing: list[str] = []
    for recipient in recipients:
        recipient_code = _normalize_recipient_code(recipient)
        public_key_info = public_key_map.get(recipient_code)
        if not public_key_info:
            missing.append(recipient_code)
            continue
        public_key = rsa_public_key_from_modexp(
            public_key_info["modulus"],
            public_key_info["exponent"],
        )
        encrypted_key_b64 = encrypt_key_blob_oaep_sha1(public_key, key_blob)
        entries.append(
            {
                "RecipientE-Address": recipient_code,
                "EncryptionInfo": {
                    "Key": encrypted_key_b64,
                    "CertificateThumbprint": public_key_info["thumbprint"],
                },
            }
        )
    return entries, missing


def _normalize_base64_payload(value: Any, field_name: str | None = None) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _normalize_base64_payload(
                item_value,
                str(key) if isinstance(key, str) else None,
            )
            for key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_normalize_base64_payload(item, field_name) for item in value]
    if isinstance(value, tuple):
        return tuple(_normalize_base64_payload(item, field_name) for item in value)

    if field_name in _BASE64_BINARY_FIELDS:
        if value is None or isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return _decode_base64_text(value)

    return value


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
                    "Contents": item["contents_bytes"],
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
    reference_id: str | None = None,
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
    enc_key_b64 = encryption_key_b64  # gitleaks:allow -- runtime encrypted key, not a literal secret
    thumb_b64 = recipient_thumbprint_b64
    sym_key = symmetric_key_bytes
    sym_iv = symmetric_iv_bytes
    recipient_transport_entries: list[dict[str, Any]] | None = None
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
    elif document_kind_code == "EINVOICE" and recipients:
        public_key_map = _resolve_public_key_map(token_provider, soap_client, recipients)
        if not public_key_map:
            raise EAddressSoapError(
                "No recipient public keys returned for EINVOICE recipients: %s"
                % ", ".join(recipients)
            )
        if mode not in ("oaep_cbc", "cbc"):
            logger.info(
                "Switching EINVOICE outbound encryption mode from %s to oaep_cbc for recipient public-key flow",
                mode,
            )
            mode = "oaep_cbc"
        sym_key = sym_key or os.urandom(32)
        sym_iv = sym_iv or os.urandom(16)
        recipient_transport_entries, missing_recipients = _build_recipient_transport_entries_from_public_keys(
            recipients,
            public_key_map,
            symmetric_key_bytes=sym_key,
            symmetric_iv_bytes=sym_iv,
        )
        if missing_recipients:
            raise EAddressSoapError(
                "Missing recipient public keys for EINVOICE recipients: %s"
                % ", ".join(missing_recipients)
            )

    attachments_list = list(attachments)
    envelope, attachments_input, built_message_id = build_envelope(
        sender_address or cfg.default_from,
        recipients,
        document_kind_code,
        subject,
        body_text,
        attachments_list,
        encryption_key_b64=enc_key_b64,
        recipient_thumbprint_b64=thumb_b64,
        recipient_entries=recipient_transport_entries,
        trace_text=trace_text,
        notify_sender_on_delivery=notify_sender_on_delivery,
        reference_id=reference_id,
        symmetric_key_bytes=sym_key,
        symmetric_iv_bytes=sym_iv,
        encryption_mode=mode,
    )
    _write_send_debug_manifest(
        message_id=built_message_id,
        sender_address=sender_address or cfg.default_from,
        recipients=recipients,
        document_kind_code=document_kind_code,
        notify_sender_on_delivery=notify_sender_on_delivery,
        encryption_mode=mode,
        encryption_key_b64=enc_key_b64,
        recipient_thumbprint_b64=thumb_b64,
        symmetric_key_bytes=sym_key,
        symmetric_iv_bytes=sym_iv,
        attachments=attachments_list,
        cfg=cfg,
        recipient_transport_entries=recipient_transport_entries or [
            {"RecipientE-Address": recipient}
            for recipient in recipients
        ],
    )
    envelope = _normalize_base64_payload(envelope)
    attachments_input = _normalize_base64_payload(attachments_input)
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
