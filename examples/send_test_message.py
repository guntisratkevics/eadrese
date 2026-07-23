"""Send a plain message to the DIV TEST environment."""

import logging
import os
from urllib.parse import urlparse

from latvian_einvoice import Attachment, EAddressClient, EAddressConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("example_send")


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Set {name} before running this TEST-only example")
    return value


def require_test_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != "divtest.vraa.gov.lv":
        raise RuntimeError("This example is restricted to the DIV TEST HTTPS endpoint")
    return value


def main() -> None:
    wsdl_url = os.environ.get(
        "EADRESE_TEST_WSDL_URL",
        "https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl",
    )
    token_url = os.environ.get(
        "EADRESE_TEST_TOKEN_URL",
        "https://divtest.vraa.gov.lv/Auth/token",
    )
    wsdl_url = require_test_url(wsdl_url)
    token_url = require_test_url(token_url)

    cfg = EAddressConfig(
        client_id=required_env("EADRESE_CLIENT_ID"),
        client_secret=required_env("EADRESE_CLIENT_SECRET"),
        wsdl_url=wsdl_url,
        token_url=token_url,
        verify_ssl=True,
    )
    client = EAddressClient(cfg)
    recipient = required_env("EADRESE_TEST_RECIPIENT")

    attachment = Attachment(
        filename="hello.txt",
        content=b"Hello from the Python client!",
        content_type="text/plain",
    )
    message_id = client.send_message(
        recipient_personal_code=recipient,
        subject="Test Message",
        body_text="This is a TEST-environment message from the Python library.",
        attachments=[attachment],
    )
    logger.info("Message sent successfully. MessageID: %s", message_id)


if __name__ == "__main__":
    main()
