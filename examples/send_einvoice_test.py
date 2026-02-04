import os
import logging
import pytest
pytest.importorskip("xmlsec")

from latvian_einvoice import EAddressClient, EAddressConfig, Attachment

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("example_einvoice")

def main():
    client_id = os.getenv("EADRESE_CLIENT_ID", "your-client-id")
    client_secret = os.getenv("EADRESE_CLIENT_SECRET", "your-secret")
    
    cfg = EAddressConfig(
        client_id=client_id,
        client_secret=client_secret,
        verify_ssl=False,
        vid_subaddress_auto=True # Automatically add VID as recipient
    )
    
    client = EAddressClient(cfg)
    sender = cfg.default_from
    recipient = cfg.default_to
    
    # Mock UBL invoice content
    ubl_content = b"""<?xml version="1.0" encoding="UTF-8"?><Invoice>...</Invoice>"""
    
    att = Attachment(
        filename="invoice.xml",
        content=ubl_content,
        content_type="application/xml"
    )
    
    logger.info(f"Sending E-INVOICE from {sender} to {recipient} (plus VID)")
    
    try:
        msg_id = client.send_message(
            recipient_personal_code=recipient,
            document_kind_code="EINVOICE",
            subject="Invoice #12345",
            body_text="Please find attached invoice.",
            attachments=[att]
        )
        logger.info(f"E-Invoice sent! MessageID: {msg_id}")
    except Exception as e:
        logger.error(f"Failed to send invoice: {e}")

if __name__ == "__main__":
    main()
