import base64
import uuid
import datetime as _dt
from typing import List, Mapping, Sequence
from ..attachments import Attachment
from ..utils import tz_riga

def build_envelope(
    recipients_list: List[str],
    document_kind_code: str,
    subject: str,
    body_text: str,
    attachments: Sequence[Attachment],
) -> tuple[Mapping[str, object], Sequence[Mapping[str, object]], str]:
    """Builds a minimal DIV EnvelopeStructure equivalent to the Java sidecar."""
    now = _dt.datetime.now(tz=tz_riga())
    message_id = str(uuid.uuid4())
    sender_doc_id = "SenderSection"

    attachments_input_items = []
    files = []
    for idx, att in enumerate(attachments, start=1):
        content_id = f"cid:{idx}"
        digest = att.sha256_digest() if hasattr(att, "sha256_digest") else b""
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
                    "DigestMethod": {"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"},
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
        "SenderE-Address": recipients_list[0] if recipients_list else "_DEFAULT@00000000000",
        "SenderRefNumber": message_id,
        "Recipients": {"RecipientEntry": recipient_entries},
        "NotifySenderOnDelivery": False,
        "Priority": "normal",
        "TraceInfo": {"TraceInfoEntry": [{"TraceInfoID": "Trace1", "TraceText": "Created"}]},
    }

    envelope = {
        "SenderDocument": {
            "Id": sender_doc_id,
            "DocumentMetadata": document_metadata,
            "SenderTransportMetadata": sender_transport,
        },
        "ServerTransportMetadata": {"Id": "ServerSection"},
        "RecipientConfirmations": {},
        "Signatures": {},
    }
    attachments_input = {"AttachmentInput": attachments_input_items} if attachments_input_items else None
    return envelope, attachments_input, message_id
