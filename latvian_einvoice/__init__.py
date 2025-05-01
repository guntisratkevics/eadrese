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
