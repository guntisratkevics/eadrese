## ☛ `latvian_einvoice/__init__.py`
```python
"""Latvian e‑invoice unified SDK."""
from .eadrese_client import (
    Attachment,
    EAddressClient,
    EAddressConfig,
    EAddressError,
)
from .eds_client import (
    EDSClient,
    EDSConfig,
    EDSError,
)
from importlib.metadata import version as _v, PackageNotFoundError
try:
    __version__ = _v(__name__)
except PackageNotFoundError:
    __version__ = "0.0.0+editable"

__all__ = [
    # e‑adrese
    "EAddressConfig",
    "Attachment",
    "EAddressClient",
    "EAddressError",
    # VID EDS
    "EDSConfig",
    "EDSClient",
    "EDSError",
]
```

---
