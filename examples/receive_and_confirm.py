"""Receive and optionally confirm one message in the DIV TEST environment."""

import logging
import os
from urllib.parse import urlparse

from latvian_einvoice import EAddressClient, EAddressConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("example_receive")


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
    message = EAddressClient(cfg).get_next_message()
    if not message:
        logger.info("No new TEST messages.")
        return

    message_id = message.get("MessageId")
    logger.info("Received TEST message: %s", message_id)
    logger.info("Subject: %s", message.get("Title"))
    if os.environ.get("EADRESE_CONFIRM", "").strip() != "1":
        logger.warning("Not confirming. Set EADRESE_CONFIRM=1 to acknowledge this TEST message.")
        return

    EAddressClient(cfg).confirm_message(message_id)
    logger.info("Confirmed TEST message.")


if __name__ == "__main__":
    main()
