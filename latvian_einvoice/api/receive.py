from typing import Any, Mapping, Optional
from zeep.helpers import serialize_object
from ..errors import EAddressSoapError
from ..auth import TokenProvider
from ..soap.client import SoapClient
from ..utils_crypto import decrypt_key_with_private, decrypt_payload_aes_gcm
from pathlib import Path
import base64
from .confirm import confirm_message

def get_next_message(
    token_provider: TokenProvider,
    soap_client: SoapClient,
    include_attachments: bool = True,
    private_key_path: Optional[Path] = None,
    auto_confirm: bool = True,
) -> Optional[Mapping[str, Any]]:
    """Check for the next available message."""
    token = token_provider.get_token()
    svc = soap_client.service
    
    try:
        if hasattr(svc, "GetNextMessage"):
            response = svc.GetNextMessage(Token=token, IncludeAttachments=include_attachments)
        else:
            # Stub support logic if needed, or raise
            raise EAddressSoapError("Service has no GetNextMessage method")
    except Exception as exc:
         raise EAddressSoapError("VUS GetNextMessage call failed") from exc
    
    if not response:
        return None
    data = serialize_object(response)

    # Attempt decryption of attachments if EncryptionInfo present and private key available
    if include_attachments and private_key_path and data.get("AttachmentsOutput"):
        try:
            priv_pem = Path(private_key_path).read_bytes()
            enc_info = data.get("Envelope", {}).get("SenderDocument", {}).get("SenderTransportMetadata", {}) \
                .get("Recipients", {}).get("RecipientEntry", [{}])[0].get("EncryptionInfo", {})
            enc_key_b64 = enc_info.get("Key")
            if enc_key_b64:
                sym_key = decrypt_key_with_private(priv_pem, enc_key_b64)
                for att in data["AttachmentsOutput"].get("AttachmentOutput", []):
                    cipher_b64 = att.get("CipherText")
                    iv_b64 = att.get("IV")
                    content_b64 = att.get("Contents")
                    if cipher_b64 and iv_b64:
                        iv = base64.b64decode(iv_b64)
                        ct = base64.b64decode(cipher_b64)
                    elif content_b64:
                        raw = base64.b64decode(content_b64)
                        iv, ct = raw[:12], raw[12:]
                    else:
                        continue
                    try:
                        decrypted = decrypt_payload_aes_gcm(sym_key, iv, ct)
                        att["DecryptedContent"] = decrypted
                    except Exception:
                        # leave undecrypted if fails
                        att["DecryptError"] = True
        except Exception:
            pass

    # Auto confirm receipt if message id present
    if auto_confirm:
        msg_id = data.get("MessageId") or data.get("messageId")
        if msg_id:
            try:
                confirm_message(token_provider, soap_client, msg_id)
                data["Confirmed"] = True
            except Exception as exc:
                data["Confirmed"] = False
                data["ConfirmError"] = str(exc)
    return data
