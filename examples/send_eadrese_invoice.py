"""Sends an e-invoice (XML + PDF) to e-adrese DIV sandbox and prints message ID."""
from pathlib import Path

from latvian_einvoice import Attachment, EAddressClient, EAddressConfig

# Sandbox (DIV) credentials - replace with real ones in production
cfg = EAddressConfig(
    client_id="demo-client",
    client_secret="demo-secret",
    verify_ssl=False,  # DIV sandbox may use self-signed certs
)

client = EAddressClient(cfg)

# Prepare attachments
xml_attachment = Attachment.from_file(Path("sample.xml"), "application/xml")
pdf_attachment = Attachment.from_file(Path("sample.pdf"), "application/pdf")

# Send message
audience_code = "010170-12345"  # test recipient personal code in DIV
msg_id = client.send_message(
    recipient_personal_code=audience_code,
    attachments=[xml_attachment, pdf_attachment],
)

print("Message sent successfully, ID:", msg_id)
