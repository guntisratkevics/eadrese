"""Latvian e-invoice unified SDK."""
from importlib.metadata import PackageNotFoundError, version as _v

from .client import EAddressClient
from .config import EAddressConfig
from .attachments import Attachment
from .errors import (
    EAddressError,
    EAddressAuthError,
    EAddressTransportError,
    EAddressSoapError,
)
from .eds_client import (
    EDSClient,
    EDSConfig,
    EDSError,
)

try:
    __version__ = _v(__name__)
except PackageNotFoundError:
    __version__ = "0.0.0+editable"

__all__ = [
    # e-adrese
    "EAddressConfig",
    "Attachment",
    "EAddressClient",
    "EAddressError",
    "EAddressAuthError",
    "EAddressTransportError",
    "EAddressSoapError",
    # VID EDS
    "EDSConfig",
    "EDSClient",
    "EDSError",
]
