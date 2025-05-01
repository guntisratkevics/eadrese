## ☛ `latvian_einvoice/eadrese_client.py`
```python
"""eadrese_client.py
~~~~~~~~~~~~~~~~~~~
A **reference implementation** of Latvia's e-adrese (VRAA VUS) integration in pure Python.
-------------------------------------------------------------------------

This file is **framework-agnostic** – you can:
* import it directly in any Python project, **or**
* embed it in an Odoo addon, calling the public methods from cron jobs / button actions.

Dependencies (install with pip):
```
pip install zeep requests cryptography python-dateutil
```

> **NOTE**  
> The real service requires a qualified website authentication certificate (QWAC) *and* a qualified e-seal (QSeal).  
> For local tests leave ``certificate=None`` + ``private_key=None``; VUS will still accept the call inside the **DIV** sandbox.
"""
from __future__ import annotations

import base64
import datetime as _dt
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, Optional

import requests
from dateutil import tz
from zeep import Client  # SOAP
from zeep.helpers import serialize_object
from zeep.plugins import HistoryPlugin
from zeep.transports import Transport
from zeep.wsse.signature import Signature

__all__ = [
    "EAddressConfig",
    "Attachment",
    "EAddressClient",
    "EAddressError",
]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class EAddressConfig:
    """Credentials and endpoints for e-adrese VUS/DIV.

    Args:
        client_id: Supplied by VDAA when you register the system.
        client_secret: For OAuth2 *Client Credentials* flow.
        certificate: Path to QWAC certificate in *PEM* (or `None` in DIV test).
        private_key: Path to private key matching the certificate (PEM).
        wsdl_url: UnifiedService WSDL address (sandbox by default).
        token_url: OAuth2 token endpoint (sandbox by default).
        verify_ssl: Verify server SSL certs (turn *off* for first quick tests).
    """

    client_id: str
    client_secret: str
    certificate: Optional[Path] = None
    private_key: Optional[Path] = None
    wsdl_url: str = "https://div.vraa.gov.lv/UnifiedService.svc?wsdl"
    token_url: str = "https://div.vraa.gov.lv/Auth/token"
    verify_ssl: bool = True


@dataclass
class Attachment:
    """File to include in an e-adrese message."""

    filename: str
    content: bytes
    content_type: str = "application/octet-stream"

    @classmethod
    def from_file(cls, path: Path, content_type: Optional[str] = None) -> "Attachment":
        data = path.read_bytes()
        ctype = content_type or _guess_mime(path.suffix)
        return cls(filename=path.name, content=data, content_type=ctype)


class EAddressError(RuntimeError):
    """Raised for any VUS error or transport problem."""

    def __init__(self, msg: str, *, response: Optional[Mapping] = None):
        super().__init__(msg)
        self.response = response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_MIME_MAP = {
    ".xml": "application/xml",
    ".pdf": "application/pdf",
    ".txt": "text/plain",
}


def _guess_mime(ext: str) -> str:
    return _MIME_MAP.get(ext.lower(), "application/octet-stream")


def _tz_riga() -> _dt.tzinfo:
    return tz.gettz("Europe/Riga")


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------


class EAddressClient:
    """Thin wrapper around e-adrese VUS (SOAP) + OAuth2 auth."""

    def __init__(self, cfg: EAddressConfig):
        self.cfg = cfg
        self._session = requests.Session()
        if not cfg.verify_ssl:
            self._session.verify = False  # noqa: S501 (only for sandbox)
        self._token: Optional[str] = None
        self._token_expiry: _dt.datetime | None = None

        self._history = HistoryPlugin()
        transport = Transport(session=self._session, timeout=30)
        wsse = None
        if cfg.certificate and cfg.private_key:
            wsse = Signature(str(cfg.certificate), str(cfg.private_key))

        self._client = Client(cfg.wsdl_url, transport=transport, plugins=[self._history], wsse=wsse)
        self._svc = self._client.create_service(
            "{http://vraa.gov.lv}IUnifiedService",
            cfg.wsdl_url.replace("?wsdl", ""),
        )
        logger.info("Initialized e-adrese SOAP client @ %s", cfg.wsdl_url)

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def send_message(
        self,
        recipient_personal_code: str,
        *,
        document_kind_code: str = "EINVOICE",
        subject: str = "Elektroniskais rēķins",
        body_text: str = "Lūdzu, skatiet pielikumā e-rēķinu.",
        attachments: Iterable[Attachment],
    ) -> str:
        """Send a *single* e-adrese message.

        Returns the **messageId** assigned by VUS. Raises :class:`EAddressError`
        on failure.
        """
        token = self._get_token()
        envelope = self._build_envelope(
            recipient_personal_code,
            document_kind_code,
            subject,
            body_text,
            list(attachments),
        )
        logger.debug("Built envelope: %s", envelope)
        try:
            response
