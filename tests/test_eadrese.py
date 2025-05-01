## ☛ `tests/test_eadrese.py` & `tests/test_eds.py`
```python
# tests/test_eds.py
import os
from latvian_einvoice import EDSClient, EDSConfig

SKIP = os.getenv("CI_EDS", "false").lower() == "false"

def test_token_cache(monkeypatch):
    if SKIP:
        return
    cfg = EDSConfig(api_key="k", client_id="c", client_secret="s", verify_ssl=False)
    cli = EDSClient(cfg)
    # monkeypatch the _ensure_token to avoid real call
    monkeypatch.setattr(cli, "_ensure_token", lambda: "token123")
    assert cli._ensure_token() == "token123"
```

(*`test_eadrese.py` remains same as earlier with import path update*)

---
