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
            # Store only the OAuth error code/description — never the full response body,
            # which may be emitted by logging frameworks and expose token-server internals.
            _safe: dict = {"http_status": resp.status_code}
            try:
                _body = resp.json()
                for _k in ("error", "error_description", "error_codes"):
                    if _k in _body:
                        _safe[_k] = _body[_k]
            except Exception:
                pass
            raise EAddressAuthError(
                f"OAuth token request failed (HTTP {resp.status_code})", response=_safe
            )

        try:
            payload = resp.json()
        except ValueError:
            raise EAddressAuthError(
                "Invalid JSON in token response", response={"http_status": resp.status_code}
            )

        token = payload.get("access_token")
        if not token:
            raise EAddressAuthError(
                "OAuth token missing in response — check client_id/client_secret and token_url",
                response={"http_status": resp.status_code},
            )
        self._token = token
        self._token_expiry = now + _dt.timedelta(seconds=payload.get("expires_in", 600))
        return self._token
