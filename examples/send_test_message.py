import os
import logging
from pathlib import Path
from latvian_einvoice import EAddressClient, EAddressConfig, Attachment

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("example_send")

def main():
    # Load credentials from environment
    client_id = os.getenv("EADRESE_CLIENT_ID", "your-client-id")
    client_secret = os.getenv("EADRESE_CLIENT_SECRET", "your-secret")
    
    # Configure client (defaults to PROD URL, override for TEST if needed)
    cfg = EAddressConfig(
        client_id=client_id,
        client_secret=client_secret,
        verify_ssl=False, # Use True in production with proper CA
        # wsdl_url="...", # Override if using TEST environment
        # token_url="...",
    )
    
    client = EAddressClient(cfg)
    
    # Use defaults or overrides
    sender = cfg.default_from
    recipient = cfg.default_to
    
    logger.info(f"Sending message from {sender} to {recipient}")
    
    # Create simple attachment
    att = Attachment(
        filename="hello.txt",
        content=b"Hello from Python client!",
        content_type="text/plain"
    )
    
    try:
        msg_id = client.send_message(
            recipient_personal_code=recipient,
            subject="Test Message",
            body_text="This is a test message from the Python library.",
            attachments=[att]
        )
        logger.info(f"Message sent successfully! MessageID: {msg_id}")
    except Exception as e:
        logger.error(f"Failed to send message: {e}")

if __name__ == "__main__":
    main()
