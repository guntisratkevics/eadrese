import base64
import uuid
import datetime as _dt
from typing import List, Mapping, Sequence, Optional
from ..attachments import Attachment
from ..utils import tz_riga
from ..utils_crypto import encrypt_payload_aes_gcm

def build_envelope(
    sender_e_address: str,
    recipients_list: List[str],
    document_kind_code: str,
    subject: str,
    body_text: str,
    attachments: Sequence[Attachment],
    *,
    encryption_key_b64: str | None = None,
    recipient_thumbprint_b64: str | None = None,
    trace_text: str = "Created",
    symmetric_key_bytes: Optional[bytes] = None,
) -> tuple[Mapping[str, object], Sequence[Mapping[str, object]] | None, str]:
    """Builds a minimal DIV EnvelopeStructure equivalent to the Java sidecar."""
    now = _dt.datetime.now(tz=tz_riga())
    message_id = uuid.uuid4().hex
    sender_doc_id = "SenderSection"

    attachments_input_items = []
    files = []
    for idx, att in enumerate(attachments, start=1):
        payload_bytes = att.content
        iv = cipher_with_tag = None
        # Encrypt payload if we have a symmetric key
        if symmetric_key_bytes:
            iv, cipher_with_tag = encrypt_payload_aes_gcm(symmetric_key_bytes, att.content)
            payload_bytes = cipher_with_tag

        content_id = str(idx - 1)
        digest = att.sha512_digest() if hasattr(att, "sha512_digest") else b""
        digest_b64 = base64.b64encode(digest).decode("ascii")
        attachments_input_items.append(
            {
                "ContentId": content_id,
                # If encrypted, send IV and CipherText separately; else fall back to plain base64 content.
                **(
                    {
                        "IV": base64.b64encode(iv).decode("ascii"),
                        "CipherText": base64.b64encode(cipher_with_tag).decode("ascii"),
                    }
                    if symmetric_key_bytes
                    else {
                        "Contents": base64.b64encode(payload_bytes).decode("ascii"),
                    }
                ),
            }
        )
        digest_b64_payload = base64.b64encode(
            getattr(att, "sha512_digest")() if not symmetric_key_bytes else __import__("hashlib").sha512(payload_bytes).digest()
        ).decode("ascii")
        files.append(
            {
                "MimeType": att.content_type,
                "Size": len(payload_bytes),
                "Name": att.filename,
                "Content": {
                    "ContentReference": content_id,
                    "DigestMethod": {"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha512"},
                    "DigestValue": digest_b64_payload,
                },
                "Compressed": False,
                "AppendixNumber": "1",
            }
        )

    document_metadata = {
        "GeneralMetadata": {
            "Authors": {"AuthorEntry": [{"Institution": {"Title": "Sender"}}]},
            "Date": now.date(),
            "Title": subject,
            "Description": body_text,
            "DocumentKind": {
                "DocumentKindCode": document_kind_code,
                "DocumentKindVersion": "1.0",
                "DocumentKindName": document_kind_code,
            },
        },
        "PayloadReference": {"File": files},
    }
    
    recipient_entries = []
    for r_code in recipients_list:
        entry = {
            "RecipientE-Address": r_code,
        }
        if encryption_key_b64 and recipient_thumbprint_b64:
            entry["EncryptionInfo"] = {
                "Key": encryption_key_b64,
                "CertificateThumbprint": recipient_thumbprint_b64,
            }
        recipient_entries.append(entry)

    sender_transport = {
        "SenderE-Address": sender_e_address or (recipients_list[0] if recipients_list else "_DEFAULT@00000000000"),
        "SenderRefNumber": message_id,
        "Recipients": {"RecipientEntry": recipient_entries},
        "NotifySenderOnDelivery": False,
        "Priority": "normal",
        "TraceInfo": {"TraceInfoEntry": [{"TraceInfoID": "Trace1", "TraceText": trace_text[:50]}]},
    }

    # Minimal ds:Signature (structure valid for XSD; not cryptographically verified here).
    digest_source = attachments[0].content if attachments else (body_text or "").encode("utf-8")
    digest_b64 = base64.b64encode(
        getattr(attachments[0], "sha512_digest")() if attachments else digest_source
    ).decode("ascii")
    signature = {
        # Placeholder Signature; will be replaced by SenderDocumentSigner plugin with a real signature.
        "SignedInfo": {
            "CanonicalizationMethod": {"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"},
            "SignatureMethod": {"Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"},
            "Reference": {
                "URI": f"#{sender_doc_id}",
                "DigestMethod": {"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha512"},
                "DigestValue": digest_b64,
            },
        },
        "SignatureValue": "",
    }

    envelope = {
        "SenderDocument": {
            "Id": sender_doc_id,
            "DocumentMetadata": document_metadata,
            "SenderTransportMetadata": sender_transport,
        },
        # ServerTransportMetadata and RecipientConfirmations are populated by DIV (optional).
        "Signatures": {"Signature": signature},
    }
    attachments_input = {"AttachmentInput": attachments_input_items} if attachments_input_items else None
    return envelope, attachments_input, message_id
