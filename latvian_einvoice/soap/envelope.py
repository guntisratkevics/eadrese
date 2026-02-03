import base64
import uuid
import datetime as _dt
from typing import List, Mapping, Sequence
from ..attachments import Attachment
from ..utils import tz_riga

def build_envelope(
    sender_e_address: str,
    recipients_list: List[str],
    document_kind_code: str,
    subject: str,
    body_text: str,
    attachments: Sequence[Attachment],
) -> tuple[Mapping[str, object], Sequence[Mapping[str, object]], str]:
    """Builds a minimal DIV EnvelopeStructure equivalent to the Java sidecar."""
    now = _dt.datetime.now(tz=tz_riga())
    message_id = uuid.uuid4().hex
    sender_doc_id = "SenderSection"

    attachments_input_items = []
    files = []
    for idx, att in enumerate(attachments, start=1):
        content_id = str(idx - 1)
        digest = att.sha512_digest() if hasattr(att, "sha512_digest") else b""
        digest_b64 = base64.b64encode(digest).decode("ascii")
        attachments_input_items.append(
            {
                "ContentId": content_id,
                "Contents": att.content,
            }
        )
        files.append(
            {
                "MimeType": att.content_type,
                "Size": len(att.content),
                "Name": att.filename,
                "Content": {
                    "ContentReference": content_id,
                    "DigestMethod": {"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha512"},
                    "DigestValue": digest_b64,
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
        recipient_entries.append({
            "RecipientE-Address": r_code,
        })

    sender_transport = {
        "SenderE-Address": sender_e_address or (recipients_list[0] if recipients_list else "_DEFAULT@00000000000"),
        "SenderRefNumber": message_id,
        "Recipients": {"RecipientEntry": recipient_entries},
        "NotifySenderOnDelivery": False,
        "Priority": "normal",
        "TraceInfo": {"TraceInfoEntry": [{"TraceInfoID": "Trace1", "TraceText": "Created"}]},
    }

    # Minimal placeholder signature (zeep enforces Signature element minOccurs=1)
    # This is NOT a cryptographically valid signature; DIV may still reject it,
    # but it allows schema serialization so we can iterate on envelope shape.
    digest_source = attachments[0].content if attachments else body_text.encode("utf-8")
    digest_b64 = base64.b64encode(
        getattr(attachments[0], "sha256_digest")() if attachments else digest_source
    ).decode("ascii")
    signature = {
        "SignedInfo": {
            "CanonicalizationMethod": {"Algorithm": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
            "SignatureMethod": {"Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
            "Reference": {
                "URI": f"#{sender_doc_id}",
                "DigestMethod": {"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"},
                "DigestValue": digest_b64,
            },
        },
        "SignatureValue": base64.b64encode(b"placeholder-signature").decode("ascii"),
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
