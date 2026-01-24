import os
import logging
from latvian_einvoice import EAddressClient, EAddressConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("example_receive")

def main():
    client_id = os.getenv("EADRESE_CLIENT_ID", "your-client-id")
    client_secret = os.getenv("EADRESE_CLIENT_SECRET", "your-secret")
    
    cfg = EAddressConfig(
        client_id=client_id,
        client_secret=client_secret,
        verify_ssl=False,
    )
    
    client = EAddressClient(cfg)
    
    logger.info("Checking for new messages...")
    
    try:
        msg = client.get_next_message()
        if msg:
            mid = msg.get("MessageId")
            logger.info(f"Received message: {mid}")
            logger.info(f"Subject: {msg.get('Title')}")
            
            # Confirm receipt
            logger.info(f"Confirming message {mid}...")
            client.confirm_message(mid)
            logger.info("Confirmed!")
        else:
            logger.info("No new messages.")
            
    except Exception as e:
        logger.error(f"Error receiving message: {e}")

if __name__ == "__main__":
    main()
