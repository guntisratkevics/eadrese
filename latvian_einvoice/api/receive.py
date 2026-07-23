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
import re
from lxml import etree
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


def _normalize_content_id(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower().startswith("cid:"):
        text = text[4:]
    return text.strip("<>")


def _extract_soap_xml_and_parts(raw: bytes) -> tuple[Optional[bytes], dict[str, bytes]]:
    payload = bytes(raw or b"").lstrip()
    if not payload:
        return None, {}
    if payload.startswith(b"<"):
        return payload, {}
    if not payload.startswith(b"--"):
        return None, {}

    newline_pos = payload.find(b"\n")
    first_line = payload if newline_pos < 0 else payload[:newline_pos]
    first_line = first_line.strip()
    if not first_line.startswith(b"--") or len(first_line) < 4:
        return None, {}

    boundary = first_line[2:]
    if not boundary or b" " in boundary:
        return None, {}

    marker = b"--" + boundary
    soap_xml = None
    parts: dict[str, bytes] = {}
    pos = 0

    while True:
        boundary_pos = payload.find(marker, pos)
        if boundary_pos < 0:
            break
        line_end = payload.find(b"\n", boundary_pos)
        if line_end < 0:
            break
        line = payload[boundary_pos:line_end].strip()
        if line == marker + b"--":
            break
        pos = line_end + 1

        sep_pos = payload.find(b"\r\n\r\n", pos)
        sep_len = 4
        if sep_pos < 0:
            sep_pos = payload.find(b"\n\n", pos)
            sep_len = 2
        if sep_pos < 0:
            break

        headers_raw = payload[pos:sep_pos]
        body_start = sep_pos + sep_len
        next_candidates = [
            idx
            for idx in (
                payload.find(b"\r\n" + marker, body_start),
                payload.find(b"\n" + marker, body_start),
            )
            if idx >= 0
        ]
        if not next_candidates:
            break
        next_boundary = min(next_candidates)
        body = payload[body_start:next_boundary]
        pos = next_boundary

        headers: dict[str, str] = {}
        for line in re.split(br"\r\n|\n|\r", headers_raw):
            line = line.strip()
            if not line or b":" not in line:
                continue
            key, value = line.split(b":", 1)
            headers[key.decode("utf-8", errors="ignore").strip().lower()] = (
                value.decode("utf-8", errors="ignore").strip()
            )

        content_type = headers.get("content-type", "").lower()
        transfer_encoding = headers.get("content-transfer-encoding", "").lower()
        content_id = _normalize_content_id(headers.get("content-id", ""))

        if transfer_encoding == "base64":
            normalized = re.sub(br"\s+", b"", body)
            try:
                body = base64.b64decode(normalized)
            except Exception:
                pass

        if soap_xml is None and (
            "application/xop+xml" in content_type
            or "application/soap+xml" in content_type
            or "text/xml" in content_type
        ):
            soap_xml = body.strip()
            continue

        if content_id:
            parts[content_id] = body

    return soap_xml, parts


def _xml_element_value(element: etree._Element) -> Any:
    attributes = {
        etree.QName(name).localname: value
        for name, value in element.attrib.items()
    }
    children = [child for child in element if isinstance(child.tag, str)]
    if not children:
        text = (element.text or "").strip()
        value: Any = text
        if text.lower() == "true":
            value = True
        elif text.lower() == "false":
            value = False
        if attributes:
            if text:
                attributes["_value_1"] = value
            return attributes
        return value

    result: dict[str, Any] = attributes
    for child in children:
        name = etree.QName(child).localname
        value = _xml_element_value(child)
        if name not in result:
            result[name] = value
        elif isinstance(result[name], list):
            result[name].append(value)
        else:
            result[name] = [result[name], value]
    return result


def _parse_get_message_raw_response(raw: bytes) -> Optional[Mapping[str, Any]]:
    soap_xml, parts = _extract_soap_xml_and_parts(raw)
    if soap_xml is None:
        return None

    try:
        root = etree.fromstring(soap_xml)
    except Exception:
        return None

    output_nodes = root.xpath("//*[local-name()='GetMessageOutput']")
    if not output_nodes:
        return None
    output = output_nodes[0]

    envelope_node = output.xpath("./*[local-name()='Envelope'][1]")
    envelope_xml = None
    envelope = None
    if envelope_node:
        try:
            envelope_xml = etree.tostring(envelope_node[0], encoding="unicode")
            envelope = _xml_element_value(envelope_node[0])
        except Exception:
            envelope_xml = None
            envelope = None

    recipients = []
    for node in output.xpath(".//*[local-name()='Recipients']/*[local-name()='string']"):
        value = (node.text or "").strip()
        if value:
            recipients.append(value)

    confirmation_name = output.xpath("string(.//*[local-name()='ConfirmationName'][1])").strip() or None

    attachments = []
    for att_node in output.xpath(".//*[local-name()='AttachmentsOutput']/*[local-name()='AttachmentOutput']"):
        content_id = att_node.xpath("string(./*[local-name()='ContentId'][1])").strip() or None
        is_separate_raw = att_node.xpath("string(./*[local-name()='IsSeparateCall'][1])").strip().lower()
        if is_separate_raw == "true":
            is_separate = True
        elif is_separate_raw == "false":
            is_separate = False
        else:
            is_separate = None
        section_count_raw = att_node.xpath("string(./*[local-name()='SectionCount'][1])").strip()
        section_size_raw = att_node.xpath("string(./*[local-name()='SectionSize'][1])").strip()

        contents_b64 = None
        contents_nodes = att_node.xpath("./*[local-name()='Contents'][1]")
        if contents_nodes:
            contents_node = contents_nodes[0]
            text = "".join(contents_node.itertext())
            normalized_text = re.sub(r"\s+", "", text or "").strip()
            if normalized_text:
                contents_b64 = normalized_text
            else:
                include_nodes = contents_node.xpath(".//*[local-name()='Include'][1]")
                if include_nodes:
                    href = include_nodes[0].get("href")
                    cid = _normalize_content_id(href)
                    if cid and cid in parts:
                        contents_b64 = base64.b64encode(parts[cid]).decode("ascii")

        attachments.append(
            {
                "ContentId": content_id,
                "IsSeparateCall": is_separate,
                "SectionCount": int(section_count_raw) if section_count_raw else None,
                "SectionSize": int(section_size_raw) if section_size_raw else None,
                "Contents": contents_b64,
            }
        )

    return {
        "Envelope": envelope,
        "EnvelopeXml": envelope_xml,
        "Recipients": recipients,
        "ConfirmationName": confirmation_name,
        "AttachmentsOutput": {"AttachmentOutput": attachments} if attachments else None,
    }


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

    raw_parsed = None
    raw_client = getattr(soap_client, "_client", None)
    if raw_client is not None:
        try:
            with raw_client.settings(raw_response=True):
                if token:
                    try:
                        raw_response = svc.GetMessage(Token=token, MessageId=message_id, IncludeAttachments=include_attachments)
                    except TypeError:
                        try:
                            raw_response = svc.GetMessage(MessageId=message_id, IncludeAttachments=include_attachments)
                        except TypeError:
                            raw_response = svc.GetMessage(MessageId=message_id)
                else:
                    try:
                        raw_response = svc.GetMessage(MessageId=message_id, IncludeAttachments=include_attachments)
                    except TypeError:
                        raw_response = svc.GetMessage(MessageId=message_id)
            if getattr(raw_response, "content", None):
                raw_parsed = _parse_get_message_raw_response(raw_response.content)
        except TypeError:
            pass
        except Exception:
            pass

    if isinstance(raw_parsed, Mapping):
        data = dict(raw_parsed)
        if not data.get("MessageId"):
            data["MessageId"] = message_id
        return data

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
    if isinstance(data, dict) and isinstance(raw_parsed, Mapping):
        for field_name in ("AttachmentsOutput", "EnvelopeXml", "Recipients", "ConfirmationName"):
            if raw_parsed.get(field_name) is not None:
                data[field_name] = raw_parsed.get(field_name)
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
                section_data = serialize_object(section) if section is not None else None
                part_value = section_data.get("Contents") if isinstance(section_data, dict) else section_data
                part = _decode_binary_field(part_value)
                if part:
                    combined.extend(part)
            if combined:
                att["Contents"] = bytes(combined)
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


def _decode_binary_field(value: Any) -> Optional[bytes]:
    # Zeep may already decode xsd:base64Binary into bytes.
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return base64.b64decode(text)
        except Exception:
            return None
    return None


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


def _is_explicit_gzip_attachment(filename: Any = None, mimetype: Any = None) -> bool:
    lower_name = str(filename or "").strip().lower()
    lower_type = str(mimetype or "").strip().lower()
    return (
        lower_name.endswith((".gz", ".gzip", ".tgz", ".tar.gz"))
        or lower_type in {"application/gzip", "application/x-gzip"}
    )


def _looks_like_unwrapped_payload(payload: bytes) -> bool:
    stripped = payload.lstrip()
    return stripped.startswith((b"PK\x03\x04", b"<?xml", b"<", b"%PDF-"))


def _maybe_decompress_gzip_payload(
    payload: bytes,
    compressed_hint: bool = False,
    filename: Any = None,
    mimetype: Any = None,
) -> bytes:
    if not payload:
        return payload
    if not (compressed_hint or payload.startswith(b"\x1f\x8b")):
        return payload
    if not compressed_hint and _is_explicit_gzip_attachment(filename, mimetype):
        return payload
    try:
        decompressed = gzip.decompress(payload)
    except Exception:
        return payload
    if compressed_hint or _looks_like_unwrapped_payload(decompressed):
        return decompressed
    return payload


def _normalize_plain_attachment_compression(data: Mapping[str, Any]) -> None:
    if not (data and data.get("AttachmentsOutput")):
        return

    file_map = _payload_file_map(data)
    attachments = data["AttachmentsOutput"].get("AttachmentOutput", [])
    if isinstance(attachments, dict):
        attachments = [attachments]

    for att in attachments:
        if not isinstance(att, dict):
            continue
        content_id = att.get("ContentId") or att.get("contentId")
        file_entry = file_map.get(str(content_id).lower()) if content_id is not None else None
        filename = (
            (file_entry or {}).get("Name")
            or att.get("FileName")
            or att.get("Name")
        )
        mimetype = att.get("ContentType")
        if att.get("DecryptedContent") is not None:
            raw_decrypted = _decode_binary_field(att.get("DecryptedContent"))
            if raw_decrypted:
                normalized_decrypted = _maybe_decompress_gzip_payload(
                    raw_decrypted,
                    compressed_hint=False,
                    filename=filename,
                    mimetype=mimetype,
                )
                if normalized_decrypted != raw_decrypted:
                    att["DecryptedContent"] = normalized_decrypted
            continue

        compressed = bool(file_entry.get("Compressed") or False) if file_entry else False
        raw_content = _decode_binary_field(att.get("Contents"))
        normalized = _maybe_decompress_gzip_payload(
            raw_content or b"",
            compressed_hint=compressed,
            filename=filename,
            mimetype=mimetype,
        )
        if raw_content and normalized != raw_content:
            att["Contents"] = normalized
            att["_GzipNormalized"] = True


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
    key_password: Optional[bytes] = None,
) -> None:
    _normalize_plain_attachment_compression(data)

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

    # Strategy:
    # 1. Try OAEP.
    #    a) Check for DIV Blob ([len][key][iv]). If found, use it (aes_key+aes_iv).
    #    b) Check for Raw Key (16/24/32 bytes). If valid, keep as candidate (gcm_key).
    # 2. If no DIV Blob found yet, Try PKCS1v15.
    #    a) Check for DIV Blob. If found, use it.
    #    b) Check for Raw Key. If valid, keep as candidate (if no gcm_key yet).

    for cand in candidates:
        # Try OAEP
        try:
            raw = decrypt_key_with_private_oaep_sha1(priv_pem, cand["key"], key_password)
            parsed = _parse_div_encrypted_key(raw)
            if parsed:
                aes_key, aes_iv = parsed
                break  # Found definitive blob

            if len(raw) in (16, 24, 32) and gcm_key is None:
                gcm_key = raw
        except Exception:
            pass

    if aes_key is None:
        # Try PKCS1v15
        for cand in candidates:
            try:
                raw = decrypt_key_with_private(priv_pem, cand["key"], key_password)
                parsed = _parse_div_encrypted_key(raw)
                if parsed:
                    aes_key, aes_iv = parsed
                    break  # Found definitive blob

                if len(raw) in (16, 24, 32) and gcm_key is None:
                    gcm_key = raw
            except Exception:
                pass

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
        if att.get("_GzipNormalized") and not (att.get("CipherText") and att.get("IV")):
            continue

        decrypted_ok = False
        if aes_key and aes_iv and att.get("Contents"):
            try:
                ciphertext = _decode_binary_field(att.get("Contents"))
                if not ciphertext:
                    raise ValueError("Missing/invalid attachment contents")
                decrypted = decrypt_payload_aes_cbc_pkcs5(aes_key, aes_iv, ciphertext)
                decrypted = _maybe_decompress_gzip_payload(
                    decrypted,
                    compressed_hint=compressed,
                    filename=(file_entry or {}).get("Name") or att.get("FileName") or att.get("Name"),
                    mimetype=att.get("ContentType"),
                )
                att["DecryptedContent"] = decrypted
                decrypted_ok = True
            except Exception:
                decrypted_ok = False

        if not decrypted_ok and gcm_key:
            try:
                if att.get("CipherText") and att.get("IV"):
                    iv = _decode_binary_field(att.get("IV"))
                    ct = _decode_binary_field(att.get("CipherText"))
                elif att.get("Contents"):
                    raw = _decode_binary_field(att.get("Contents"))
                    if not raw:
                        raise ValueError("Missing/invalid attachment contents")
                    iv, ct = raw[:12], raw[12:]
                else:
                    continue
                if not iv or not ct:
                    raise ValueError("Missing/invalid IV/ciphertext")
                decrypted = decrypt_payload_aes_gcm(gcm_key, iv, ct)
                decrypted = _maybe_decompress_gzip_payload(
                    decrypted,
                    compressed_hint=compressed,
                    filename=(file_entry or {}).get("Name") or att.get("FileName") or att.get("Name"),
                    mimetype=att.get("ContentType"),
                )
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
    recipients = data.get("Recipients") if isinstance(data, dict) else None
    recipient_eaddresses = None
    if isinstance(recipients, dict):
        values = recipients.get("string")
        if isinstance(values, list):
            recipient_eaddresses = values
        elif isinstance(values, str):
            recipient_eaddresses = [values]
    elif isinstance(recipients, list):
        recipient_eaddresses = recipients
    confirmation_name = data.get("ConfirmationName") if isinstance(data, dict) else None
    try:
        confirm_message(
            token_provider,
            soap_client,
            msg_id,
            recipient_eaddresses=recipient_eaddresses,
            confirmation_name=confirmation_name,
        )
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
    key_password: Optional[bytes] = None,
) -> Optional[Mapping[str, Any]]:
    data = _fetch_message(token_provider, soap_client, message_id, include_attachments)
    if not data:
        return None
    msg_id = data.get("MessageId") or message_id
    _attach_sections(data, soap_client, msg_id, include_attachments)
    _decrypt_attachments(data, private_key_path, certificate_path, key_password)
    _auto_confirm(data, token_provider, soap_client, auto_confirm)
    return data

def get_next_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    include_attachments: bool = True,
    private_key_path: Optional[Path] = None,
    certificate_path: Optional[Path] = None,
    auto_confirm: bool = True,
    key_password: Optional[bytes] = None,
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
    _decrypt_attachments(data, private_key_path, certificate_path, key_password)
    _auto_confirm(data, token_provider, soap_client, auto_confirm)
    return data
