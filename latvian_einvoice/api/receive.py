from typing import Any, Mapping, Optional, List
from zeep.helpers import serialize_object
from ..errors import EAddressSoapError
from ..auth import TokenProvider
from ..soap.client import SoapClient
from ..utils_crypto import (
    decrypt_key_with_private,
    decrypt_key_with_private_oaep_sha1,
    decrypt_payload_aes_gcm,
    decrypt_payload_aes_cbc_pkcs5,
    thumbprint_sha1_b64,
)
from pathlib import Path
import base64
import gzip
from .confirm import confirm_message


def _message_headers_from_list(list_data: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    headers = (list_data or {}).get("MessageHeaders") or {}
    header_items = headers.get("MessageHeader") if isinstance(headers, dict) else headers
    if not header_items:
        return []
    if isinstance(header_items, list):
        return [item for item in header_items if isinstance(item, dict)]
    if isinstance(header_items, dict):
        return [header_items]
    return []


def get_message_list(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    max_result_count: Optional[int] = None,
) -> List[Mapping[str, Any]]:
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service
    if not hasattr(svc, "GetMessageList"):
        raise EAddressSoapError("Service has no GetMessageList method")

    kwargs = {}
    if max_result_count:
        kwargs["MaxResultCount"] = max_result_count

    try:
        if token:
            try:
                response_list = svc.GetMessageList(Token=token, **kwargs)
            except TypeError:
                response_list = svc.GetMessageList(**kwargs)
        else:
            response_list = svc.GetMessageList(**kwargs)
    except TypeError:
        response_list = svc.GetMessageList()
    except Exception as exc:
        raise EAddressSoapError("VUS GetMessageList call failed") from exc

    list_data = serialize_object(response_list) if response_list is not None else {}
    return _message_headers_from_list(list_data)


def _fetch_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    message_id: str,
    include_attachments: bool = True,
) -> Optional[Mapping[str, Any]]:
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service
    if not hasattr(svc, "GetMessage"):
        raise EAddressSoapError("Service has no GetMessage method")

    try:
        if token:
            try:
                response = svc.GetMessage(Token=token, MessageId=message_id, IncludeAttachments=include_attachments)
            except TypeError:
                try:
                    response = svc.GetMessage(MessageId=message_id, IncludeAttachments=include_attachments)
                except TypeError:
                    response = svc.GetMessage(MessageId=message_id)
        else:
            try:
                response = svc.GetMessage(MessageId=message_id, IncludeAttachments=include_attachments)
            except TypeError:
                response = svc.GetMessage(MessageId=message_id)
    except TypeError:
        response = svc.GetMessage(message_id)
    except Exception as exc:
        raise EAddressSoapError("VUS GetMessage call failed") from exc

    if not response:
        return None
    data = serialize_object(response)
    if isinstance(data, dict) and not data.get("MessageId"):
        data["MessageId"] = message_id
    return data


def _attach_sections(
    data: Mapping[str, Any],
    soap_client: SoapClient,
    message_id: Optional[str],
    include_attachments: bool,
) -> None:
    if not (data and include_attachments):
        return
    try:
        attachments = data.get("AttachmentsOutput", {}).get("AttachmentOutput", [])
        if isinstance(attachments, dict):
            attachments = [attachments]
        if not message_id or not attachments:
            return
        svc = soap_client.service
        for att in attachments:
            if not isinstance(att, dict):
                continue
            if not att.get("IsSeparateCall"):
                continue
            content_id = att.get("ContentId")
            section_count = att.get("SectionCount") or 0
            if not content_id or not section_count:
                continue
            combined = bytearray()
            for idx in range(int(section_count)):
                try:
                    section = svc.GetAttachmentSection(MessageId=message_id, ContentId=content_id, SectionIndex=idx)
                except TypeError:
                    section = svc.GetAttachmentSection(message_id, content_id, idx)
                section_data = serialize_object(section) if section is not None else {}
                part_b64 = section_data.get("Contents")
                if part_b64:
                    combined.extend(base64.b64decode(part_b64))
            if combined:
                att["Contents"] = base64.b64encode(bytes(combined)).decode("ascii")
    except Exception:
        return


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _payload_file_map(data: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    file_map: dict[str, Mapping[str, Any]] = {}
    try:
        files = (
            data.get("Envelope", {})
            .get("SenderDocument", {})
            .get("DocumentMetadata", {})
            .get("PayloadReference", {})
            .get("File", [])
        )
    except AttributeError:
        return file_map
    for entry in _as_list(files):
        if not isinstance(entry, dict):
            continue
        content = entry.get("Content", {})
        content_ref = content.get("ContentReference") if isinstance(content, dict) else None
        if not content_ref:
            continue
        file_map[str(content_ref).lower()] = entry
    return file_map


def _recipient_entries(data: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    try:
        recipients = (
            data.get("Envelope", {})
            .get("SenderDocument", {})
            .get("SenderTransportMetadata", {})
            .get("Recipients", {})
        )
    except AttributeError:
        return []
    entries = recipients.get("RecipientEntry", [])
    return [entry for entry in _as_list(entries) if isinstance(entry, dict)]


def _parse_div_encrypted_key(raw: bytes) -> Optional[tuple[bytes, bytes]]:
    if not raw or len(raw) < 2:
        return None
    key_len = raw[0]
    if key_len not in (16, 24, 32):
        return None
    if len(raw) < 1 + key_len + 16:
        return None
    aes_key = raw[1 : 1 + key_len]
    iv = raw[1 + key_len :]
    if len(iv) != 16:
        return None
    return aes_key, iv


def _decrypt_attachments(
    data: Mapping[str, Any],
    private_key_path: Optional[Path],
    certificate_path: Optional[Path] = None,
) -> None:
    if not (data and private_key_path and data.get("AttachmentsOutput")):
        return
    try:
        priv_pem = Path(private_key_path).read_bytes()
    except Exception:
        return

    cert_thumb = None
    if certificate_path:
        try:
            cert_thumb = thumbprint_sha1_b64(Path(certificate_path).read_bytes()).strip()
        except Exception:
            cert_thumb = None

    recipient_entries = _recipient_entries(data)
    candidates = []
    for entry in recipient_entries:
        enc_info = entry.get("EncryptionInfo") if isinstance(entry, dict) else None
        if not isinstance(enc_info, dict):
            continue
        key_b64 = enc_info.get("Key")
        if not key_b64:
            continue
        candidates.append(
            {
                "key": key_b64,
                "thumb": (enc_info.get("CertificateThumbprint") or "").strip(),
            }
        )
    if not candidates:
        return

    if cert_thumb:
        candidates.sort(key=lambda c: 0 if c["thumb"] == cert_thumb else 1)

    aes_key = None
    aes_iv = None
    gcm_key = None

    for cand in candidates:
        try:
            decrypted_key = decrypt_key_with_private_oaep_sha1(priv_pem, cand["key"])
        except Exception:
            continue
        parsed = _parse_div_encrypted_key(decrypted_key)
        if parsed:
            aes_key, aes_iv = parsed
            break

    if aes_key is None:
        for cand in candidates:
            try:
                gcm_key = decrypt_key_with_private(priv_pem, cand["key"])
                if gcm_key:
                    break
            except Exception:
                continue

    file_map = _payload_file_map(data)
    attachments = data["AttachmentsOutput"].get("AttachmentOutput", [])
    if isinstance(attachments, dict):
        attachments = [attachments]

    for att in attachments:
        if not isinstance(att, dict):
            continue
        if att.get("DecryptedContent") is not None:
            continue

        content_id = att.get("ContentId") or att.get("contentId")
        file_entry = file_map.get(str(content_id).lower()) if content_id is not None else None
        if file_entry:
            if not att.get("Name") and not att.get("FileName"):
                name = file_entry.get("Name")
                if name:
                    att["Name"] = name
        compressed = bool(file_entry.get("Compressed") or False) if file_entry else False

        decrypted_ok = False
        if aes_key and aes_iv and att.get("Contents"):
            try:
                ciphertext = base64.b64decode(att["Contents"])
                decrypted = decrypt_payload_aes_cbc_pkcs5(aes_key, aes_iv, ciphertext)
                if compressed:
                    decrypted = gzip.decompress(decrypted)
                att["DecryptedContent"] = decrypted
                decrypted_ok = True
            except Exception:
                decrypted_ok = False

        if not decrypted_ok and gcm_key:
            try:
                if att.get("CipherText") and att.get("IV"):
                    iv = base64.b64decode(att["IV"])
                    ct = base64.b64decode(att["CipherText"])
                elif att.get("Contents"):
                    raw = base64.b64decode(att["Contents"])
                    iv, ct = raw[:12], raw[12:]
                else:
                    continue
                decrypted = decrypt_payload_aes_gcm(gcm_key, iv, ct)
                if compressed:
                    decrypted = gzip.decompress(decrypted)
                att["DecryptedContent"] = decrypted
                decrypted_ok = True
            except Exception:
                decrypted_ok = False

        if not decrypted_ok:
            att["DecryptError"] = True


def _auto_confirm(
    data: Mapping[str, Any],
    token_provider: TokenProvider,
    soap_client: SoapClient,
    auto_confirm: bool,
) -> None:
    if not auto_confirm:
        return
    msg_id = data.get("MessageId") or data.get("messageId")
    if not msg_id:
        return
    try:
        confirm_message(token_provider, soap_client, msg_id)
        data["Confirmed"] = True
    except Exception as exc:
        data["Confirmed"] = False
        data["ConfirmError"] = str(exc)


def get_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    message_id: str,
    include_attachments: bool = True,
    private_key_path: Optional[Path] = None,
    certificate_path: Optional[Path] = None,
    auto_confirm: bool = True,
) -> Optional[Mapping[str, Any]]:
    data = _fetch_message(token_provider, soap_client, message_id, include_attachments)
    if not data:
        return None
    msg_id = data.get("MessageId") or message_id
    _attach_sections(data, soap_client, msg_id, include_attachments)
    _decrypt_attachments(data, private_key_path, certificate_path)
    _auto_confirm(data, token_provider, soap_client, auto_confirm)
    return data

def get_next_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    include_attachments: bool = True,
    private_key_path: Optional[Path] = None,
    certificate_path: Optional[Path] = None,
    auto_confirm: bool = True,
) -> Optional[Mapping[str, Any]]:
    """Check for the next available message."""
    token = token_provider.get_token() if token_provider else None
    svc = soap_client.service
    
    message_id = None
    try:
        if hasattr(svc, "GetNextMessage"):
            if token:
                response = svc.GetNextMessage(Token=token, IncludeAttachments=include_attachments)
            else:
                response = svc.GetNextMessage(IncludeAttachments=include_attachments)
        elif hasattr(svc, "GetMessageList") and hasattr(svc, "GetMessage"):
            # UnifiedServiceInterface uses GetMessageList/GetMessage instead of GetNextMessage.
            headers = get_message_list(token_provider, soap_client, max_result_count=1)
            if not headers:
                return None
            message_id = headers[0].get("MessageId") if isinstance(headers[0], dict) else None
            if not message_id:
                return None
            response = _fetch_message(token_provider, soap_client, message_id, include_attachments)
        else:
            raise EAddressSoapError("Service has no GetNextMessage/GetMessageList methods")
    except Exception as exc:
        raise EAddressSoapError("VUS GetNextMessage call failed") from exc
    
    if not response:
        return None
    if isinstance(response, dict):
        data = response
    else:
        data = serialize_object(response)
    if message_id and isinstance(data, dict) and not data.get("MessageId"):
        data["MessageId"] = message_id

    msg_id = data.get("MessageId") or data.get("messageId") or message_id
    _attach_sections(data, soap_client, msg_id, include_attachments)
    _decrypt_attachments(data, private_key_path, certificate_path)
    _auto_confirm(data, token_provider, soap_client, auto_confirm)
    return data
