"""Sends an e-invoice (XML+PDF) to the e-adrese DIV sandbox
and prints the returned message ID.
"""
from pathlib import Path
from latvian_einvoice import (
    Attachment,
    EAddressClient,
    EAddressConfig,
)

# --- credentials ---------------------------------------------------------
cfg = EAddressConfig(
    client_id="your-sandbox-client",
    client_secret="your-sandbox-secret",
    verify_ssl=False,              # DIV sandbox often uses self-signed certs
)

client = EAddressClient(cfg)

# --- attachments ---------------------------------------------------------
xml_attachment = Attachment.from_file(Path("sample.xml"), "application/xml")
pdf_attachment = Attachment.from_file(Path("sample.pdf"), "application/pdf")

# --- send ---------------------------------------------------------------
recipient_code = "010170-12345"      # personal code published by VDAA for tests
msg_id = client.send_message(
    recipient_personal_code=recipient_code,
    attachments=[xml_attachment, pdf_attachment],
)
print("Message sent. ID:", msg_id)
