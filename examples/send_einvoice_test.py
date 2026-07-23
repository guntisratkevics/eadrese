"""Send a synthetic UBL e-invoice to the DIV TEST environment."""

import logging
import os
from urllib.parse import urlparse

from latvian_einvoice import Attachment, EAddressClient, EAddressConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("example_einvoice")


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
        vid_subaddress_auto=True,
    )
    client = EAddressClient(cfg)
    recipient = required_env("EADRESE_TEST_RECIPIENT")
    attachment = Attachment(
        filename="invoice.xml",
        content=b'<?xml version="1.0" encoding="UTF-8"?><Invoice>synthetic-test-data</Invoice>',
        content_type="application/xml",
    )

    message_id = client.send_message(
        recipient_personal_code=recipient,
        document_kind_code="EINVOICE",
        subject="Synthetic TEST invoice",
        body_text="Synthetic invoice for TEST environment interoperability checks.",
        attachments=[attachment],
    )
    logger.info("E-invoice sent. MessageID: %s", message_id)


if __name__ == "__main__":
    main()
