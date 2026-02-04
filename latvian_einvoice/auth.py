import datetime as _dt
import logging
import requests
from .config import EAddressConfig
from .errors import EAddressAuthError, EAddressTransportError
from .utils import tz_riga

logger = logging.getLogger(__name__)

class TokenProvider:
    def __init__(self, cfg: EAddressConfig, session: requests.Session):
        self.cfg = cfg
        self._session = session
        self._token = None
        self._token_expiry = None

    def get_token(self) -> str:
        now = _dt.datetime.now(tz=tz_riga())
        if self._token and self._token_expiry and now < self._token_expiry - _dt.timedelta(seconds=60):
            return self._token

        # Allow bypassing OAuth when VRAA has not issued client credentials (Java mTLS-only flow).
        if (
            not self.cfg.token_url
            or self.cfg.token_url.lower().startswith(("dummy", "skip"))
            or not self.cfg.client_id
            or not self.cfg.client_secret
        ):
            return None
        
        try:
            resp = self._session.post(
                self.cfg.token_url,
                data={"grant_type": "client_credentials"},
                auth=(self.cfg.client_id, self.cfg.client_secret),
                timeout=self.cfg.timeout,
            )
        except requests.RequestException as exc:
             raise EAddressTransportError("OAuth token connection failed") from exc

        if resp.status_code != 200:
            raise EAddressAuthError("OAuth token request failed", response=resp.json() if resp.content else None)
        
        try:
            payload = resp.json()
        except ValueError:
             raise EAddressAuthError("Invalid JSON in token response", response=resp.text)

        token = payload.get("access_token")
        if not token:
            raise EAddressAuthError("OAuth token missing in response", response=payload)
        self._token = token
        self._token_expiry = now + _dt.timedelta(seconds=payload.get("expires_in", 600))
        return self._token
