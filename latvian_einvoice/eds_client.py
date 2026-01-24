"""Thin wrapper for VID EDS e-Invoice REST API (Swagger v2, 2025-02-14)."""
from __future__ import annotations

import datetime as _dt
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from dateutil import tz

__all__ = [
    "EDSConfig",
    "EDSClient",
    "EDSError",
]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _tz_riga():
    return tz.gettz("Europe/Riga")


class EDSError(RuntimeError):
    def __init__(self, msg: str, *, response: Optional[requests.Response] = None):
        super().__init__(msg)
        self.response = response


@dataclass
class EDSConfig:
    """Credentials & endpoints for VID EDS API."""

    api_key: str  # Generated in EDS → Servisu saskarne API
    client_id: str  # OAuth2 client Id
    client_secret: str
    base_url: str = "https://eds.vid.gov.lv/api"
    token_url: str = "https://eds.vid.gov.lv/api/auth/token"
    verify_ssl: bool = True


class EDSClient:
    """Minimal VID EDS REST client."""

    def __init__(self, cfg: EDSConfig):
        self.cfg = cfg
        self._s = requests.Session()
        self._s.headers.update({"X-Api-Key": cfg.api_key})
        if not cfg.verify_ssl:
            self._s.verify = False  # noqa: S501
        self._token: Optional[str] = None
        self._token_expiry: Optional[_dt.datetime] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_invoice(self, xml_bytes: bytes) -> str:
        """POST /einvoice - returns EDS document GUID."""
        token = self._ensure_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/xml"}
        url = f"{self.cfg.base_url}/einvoice"
        resp = self._s.post(url, data=xml_bytes, headers=headers, timeout=30)
        if resp.status_code != 202:
            raise EDSError("Failed to send invoice", response=resp)
        return resp.json()["documentGuid"]

    def get_status(self, document_guid: str) -> Dict[str, Any]:
        token = self._ensure_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.cfg.base_url}/einvoice/{document_guid}"
        resp = self._s.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            raise EDSError("Status lookup failed", response=resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_token(self) -> str:
        now = _dt.datetime.now(tz=_tz_riga())
        if self._token and self._token_expiry and now < self._token_expiry - _dt.timedelta(seconds=60):
            return self._token
        logger.debug("Fetching new EDS OAuth token")
        resp = self._s.post(
            self.cfg.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.cfg.client_id,
                "client_secret": self.cfg.client_secret,
            },
            timeout=15,
        )
        if resp.status_code != 200:
            raise EDSError("OAuth failed", response=resp)
        data = resp.json()
        self._token = data["access_token"]
        self._token_expiry = now + _dt.timedelta(seconds=data.get("expires_in", 3600))
        return self._token
